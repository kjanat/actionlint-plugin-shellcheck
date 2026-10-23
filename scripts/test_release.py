import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import release

ID = "12345678-1234-1234-1234-123456789abc"


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.package = self.directory / "artifacts"
        self.package.mkdir()
        for name in release.FILES:
            (self.package / name).write_bytes(name.encode())
        self.checksums = "".join(
            f"{release.digest(self.package / name)}  {name}\n" for name in release.FILES
        )
        (self.package / "SHA256SUMS").write_text(self.checksums, encoding="utf-8")

    def test_tag_matches_crate_version(self):
        manifest = self.directory / "Cargo.toml"
        manifest.write_text('[package]\nversion = "0.1.0"\n', encoding="utf-8")
        release.check_tag("v0.1.0", manifest)
        for tag in ("master", "v0.2.0", "0.1.0"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.check_tag(tag, manifest)

    def test_verifies_all_packaged_files_and_tested_digest(self):
        checksum = hashlib.sha256(b"plugin.wasm").hexdigest()
        self.assertEqual(release.verify(self.package, checksum), checksum)
        with self.assertRaisesRegex(ValueError, "tested component"):
            release.verify(self.package, "0" * 64)
        (self.package / "schema.json").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "schema.json"):
            release.verify(self.package, checksum)

    def test_rejects_missing_extra_duplicate_and_traversal_checksums(self):
        for checksums in (
            self.checksums.splitlines()[0] + "\n",
            self.checksums + self.checksums.splitlines()[0] + "\n",
            self.checksums.replace("plugin.wasm", "../plugin.wasm"),
        ):
            with self.subTest(checksums=checksums):
                (self.package / "SHA256SUMS").write_text(checksums, encoding="utf-8")
                with self.assertRaises(ValueError):
                    release.verify(self.package)
        (self.package / "unexpected").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "exactly"):
            release.verify(self.package)

    def test_different_asset_is_never_replaced(self):
        existing = {"draft": True, "assets": [{"name": "plugin.wasm"}]}

        def download(arguments, check):
            Path(arguments[-1], "plugin.wasm").write_bytes(b"different")

        with (
            patch.object(release.subprocess, "run", side_effect=download),
            self.assertRaisesRegex(ValueError, "Refusing to replace"),
        ):
            release.compare_assets(existing, "owner/repo", "v0.1.0", self.package)

    def test_existing_identical_draft_can_resume_missing_assets(self):
        existing = {"draft": True, "assets": [{"name": "plugin.wasm"}]}

        def download(arguments, check):
            Path(arguments[-1], "plugin.wasm").write_bytes(b"plugin.wasm")

        with patch.object(release.subprocess, "run", side_effect=download):
            missing = release.compare_assets(
                existing, "owner/repo", "v0.1.0", self.package
            )
            self.assertEqual(
                set(missing), {"metadata.json", "schema.json", "LICENSE", "SHA256SUMS"}
            )
            existing["draft"] = False
            with self.assertRaisesRegex(ValueError, "Published release is incomplete"):
                release.compare_assets(existing, "owner/repo", "v0.1.0", self.package)

    def test_rejects_unexpected_release_assets(self):
        with self.assertRaisesRegex(ValueError, "unexpected"):
            release.compare_assets(
                {"assets": [{"name": "other.wasm"}]}, "o/r", "v0.1.0", self.package
            )

    def test_existing_published_release_is_not_mutated(self):
        existing = {"id": 5, "draft": False, "immutable": True, "assets": []}
        with (
            patch.dict(
                os.environ,
                RELEASE_TAG="v0.1.0",
                EXPECTED_SHA256=release.verify(self.package),
                GITHUB_REPOSITORY="owner/repo",
                GH_TOKEN="test",
            ),
            patch.object(release, "check_tag"),
            patch.object(release, "compare_assets", return_value=[]),
            patch.object(release, "request_json", return_value=existing) as request,
            patch.object(release.subprocess, "run") as run,
        ):
            release.publish(self.package)
            self.assertEqual(request.call_count, 2)
            self.assertTrue(all(len(call.args) == 2 for call in request.call_args_list))
            run.assert_not_called()

    def test_authentication_failure_does_not_create_release(self):
        with (
            patch.dict(
                os.environ,
                RELEASE_TAG="v0.1.0",
                EXPECTED_SHA256=release.verify(self.package),
                GITHUB_REPOSITORY="owner/repo",
                GH_TOKEN="test",
            ),
            patch.object(release, "check_tag"),
            patch.object(
                release,
                "request_json",
                side_effect=HTTPError("url", 403, "forbidden", {}, None),
            ) as request,
        ):
            with self.assertRaises(HTTPError):
                release.publish(self.package)
            self.assertEqual(request.call_count, 1)

    def test_new_release_uploads_and_compares_before_publication(self):
        draft = {"id": 5, "draft": True, "assets": []}
        published = {**draft, "draft": False, "immutable": True}
        responses = [
            HTTPError("url", 404, "missing", {}, None),
            draft,
            draft,
            published,
        ]
        events = []

        def request(*args, **kwargs):
            events.append(("request", args, kwargs))
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        def compare(*args):
            events.append(("compare",))
            return ["plugin.wasm"] if len(events) == 3 else []

        with (
            patch.dict(
                os.environ,
                RELEASE_TAG="v0.1.0",
                EXPECTED_SHA256=release.verify(self.package),
                GITHUB_REPOSITORY="owner/repo",
                GH_TOKEN="test",
            ),
            patch.object(release, "check_tag"),
            patch.object(release, "compare_assets", side_effect=compare),
            patch.object(release, "request_json", side_effect=request),
            patch.object(
                release.subprocess,
                "run",
                side_effect=lambda *a, **k: events.append(("upload", a)),
            ),
        ):
            release.publish(self.package)
        self.assertEqual(
            [event[0] for event in events],
            [
                "request",
                "request",
                "compare",
                "upload",
                "request",
                "compare",
                "request",
            ],
        )
        self.assertTrue(events[1][1][2]["draft"])
        self.assertIn(
            "https://github.com/owner/repo/blob/v0.1.0/CHANGELOG.md",
            events[1][1][2]["body"],
        )
        self.assertEqual(events[-1][1][2], {"draft": False})
        self.assertEqual(events[-1][2], {"method": "PATCH"})
        self.assertNotIn("--clobber", events[3][1][0])

    def test_mutable_release_cannot_be_submitted(self):
        existing = {"id": 5, "draft": False, "immutable": False, "assets": []}
        with (
            patch.dict(
                os.environ,
                RELEASE_TAG="v0.1.0",
                EXPECTED_SHA256=release.verify(self.package),
                GITHUB_REPOSITORY="owner/repo",
                GH_TOKEN="test",
            ),
            patch.object(release, "check_tag"),
            patch.object(release, "compare_assets", return_value=[]),
            patch.object(release, "request_json", return_value=existing),
            self.assertRaisesRegex(ValueError, "not immutable"),
        ):
            release.publish(self.package)

    def wait_with_responses(self, statuses, timeout=1200):
        responses = [{"id": ID, "status": status} for status in statuses]
        with (
            patch.object(release, "request_json", side_effect=responses),
            patch.object(release.time, "sleep"),
            patch.object(release.Path, "write_text") as write,
        ):
            release.wait_for_publication(ID, "f" * 64, timeout)
            return json.loads(write.call_args.args[0])

    def test_publication_requires_published_after_pending_and_validating(self):
        receipt = self.wait_with_responses(["pending", "validating", "published"])
        self.assertEqual(receipt["status"], "published")
        self.assertEqual(receipt["sha256"], "f" * 64)

    def test_failed_and_rejected_are_failures(self):
        for status in ("failed", "rejected", "unexpected"):
            with (
                self.subTest(status=status),
                self.assertRaisesRegex(ValueError, "did not succeed"),
            ):
                self.wait_with_responses([status])

    def test_pending_timeout_is_failure(self):
        with self.assertRaisesRegex(TimeoutError, "still pending"):
            self.wait_with_responses(["pending"], timeout=0)

    def test_rejects_status_for_another_submission(self):
        with (
            patch.object(
                release,
                "request_json",
                return_value={"id": "different", "status": "published"},
            ),
            patch.object(release.Path, "write_text"),
            self.assertRaisesRegex(ValueError, "different submission"),
        ):
            release.wait_for_publication(ID, "f" * 64)


if __name__ == "__main__":
    unittest.main()
