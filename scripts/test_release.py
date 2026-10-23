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
        """A tag with the wrong version would give users a package whose advertised version disagrees
        with its contents. This reads a real temporary manifest and accepts its matching tag while
        rejecting a branch, a different version and a version without the required prefix.
        """
        manifest = self.directory / "Cargo.toml"
        manifest.write_text('[package]\nversion = "0.1.0"\n', encoding="utf-8")
        release.check_tag("v0.1.0", manifest)
        for tag in ("master", "v0.2.0", "0.1.0"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.check_tag(tag, manifest)

    def test_rejects_wrong_component_digest_and_modified_schema(self):
        """Publication must stop if the component differs from the tested bytes or another packaged
        file changes afterward. This hashes real temporary files, checks an incorrect component
        digest, then changes the schema without updating its checksum. Both cases must fail.
        """
        checksum = hashlib.sha256(b"plugin.wasm").hexdigest()
        self.assertEqual(release.verify(self.package, checksum), checksum)
        with self.assertRaisesRegex(ValueError, "tested component"):
            release.verify(self.package, "0" * 64)
        (self.package / "schema.json").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "schema.json"):
            release.verify(self.package, checksum)

    def test_rejects_missing_extra_duplicate_and_traversal_checksums(self):
        """Missing or repeated checksum entries can hide an incomplete package, while a parent path
        can point outside it. This writes each malformed manifest to disk and runs package
        verification, then adds an unexpected file. Every case must fail before publication.
        """
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
        """A release rerun must stop when an existing asset has different bytes from the local build.
        The download substitute writes an actual conflicting file, which the production comparison
        hashes. This checks that differing contents cause an error before any replacement upload.
        """
        existing = {"draft": True, "assets": [{"name": "plugin.wasm"}]}

        def download(arguments, check):
            Path(arguments[-1], "plugin.wasm").write_bytes(b"different")

        with (
            patch.object(release.subprocess, "run", side_effect=download),
            self.assertRaisesRegex(ValueError, "Refusing to replace"),
        ):
            release.compare_assets(existing, "owner/repo", "v0.1.0", self.package)

    def test_existing_identical_draft_can_resume_missing_assets(self):
        """Interrupted uploads can leave a draft containing only some correct assets. This supplies
        downloaded bytes for that partial package and checks which files still need uploading.
        Marking the same release public must fail, because later uploads would change its contents.
        """
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

    def test_existing_published_release_is_not_mutated(self):
        """Rerunning a completed release should check it without uploading or publishing again. This
        drives the existing-release branch with controlled API responses and checks that requests
        carry no mutation payload or method. Subprocess activity catches an accidental second upload.
        """
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
            self.assertTrue(all(not call.kwargs for call in request.call_args_list))
            run.assert_not_called()

    def test_authentication_failure_does_not_create_release(self):
        """Treating a forbidden lookup like a missing release would incorrectly enter release
        creation after an authentication failure. This injects a 403 into the publication function
        and checks that the error reaches the caller without a second API request.
        """
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
            patch.object(release.subprocess, "run") as run,
        ):
            with self.assertRaises(HTTPError):
                release.publish(self.package)
            self.assertEqual(request.call_count, 1)
            run.assert_not_called()

    def test_release_stays_draft_until_uploaded_assets_match(self):
        """Publishing before uploaded files are checked can expose an incomplete release. These
        remote responses exercise both completed and incomplete uploads through publication.
        The incomplete case must raise before any request can make the draft public.
        """
        for incomplete in (False, True):
            with self.subTest(incomplete=incomplete):
                draft = {"id": 5, "draft": True, "assets": []}
                published = {**draft, "draft": False, "immutable": True}
                responses = [HTTPError("url", 404, "missing", {}, None), draft, draft]
                if not incomplete:
                    responses.append(published)
                events = []

                def request(*args, **kwargs):
                    events.append(("request", args, kwargs))
                    response = responses.pop(0)
                    if isinstance(response, Exception):
                        raise response
                    return response

                comparisons = iter([["plugin.wasm"], ["plugin.wasm"] if incomplete else []])

                def compare(*args):
                    events.append(("compare",))
                    return next(comparisons)

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
                    if incomplete:
                        with self.assertRaisesRegex(ValueError, "upload is incomplete"):
                            release.publish(self.package)
                    else:
                        release.publish(self.package)
                expected = ["request", "request", "compare", "upload", "request", "compare"]
                if not incomplete:
                    expected.append("request")
                    self.assertEqual(events[-1][1][2], {"draft": False})
                    self.assertEqual(events[-1][2], {"method": "PATCH"})
                self.assertEqual([event[0] for event in events], expected)
                self.assertTrue(events[1][1][2]["draft"])
                self.assertIn(
                    "https://github.com/owner/repo/blob/v0.1.0/CHANGELOG.md",
                    events[1][1][2]["body"],
                )
                self.assertNotIn("--clobber", events[3][1][0])

    def test_mutable_release_fails_publication_stage(self):
        """The workflow submits to the registry only after this publication stage succeeds. A public
        release without GitHub's immutability flag must therefore fail even when its assets match.
        This drives that existing-release branch and checks that the publication function raises.
        """
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
        """Registry submission starts asynchronous work; pending and validating still leave the plugin
        unavailable. This sends both intermediate responses before published and checks the final
        receipt. Returning early would leave an intermediate status in the result and fail.
        """
        receipt = self.wait_with_responses(["pending", "validating", "published"])
        self.assertEqual(receipt["status"], "published")
        self.assertEqual(receipt["sha256"], "f" * 64)

    def test_failed_and_rejected_are_failures(self):
        """A rejected submission or failed validation must make the workflow fail. An unfamiliar
        status must also stop it. These controlled responses exercise that decision in the polling
        function without creating real rejected registry submissions as a side effect of testing.
        """
        for status in ("failed", "rejected", "unexpected"):
            with (
                self.subTest(status=status),
                self.assertRaisesRegex(ValueError, "did not succeed"),
            ):
                self.wait_with_responses([status])

    def test_pending_timeout_is_failure(self):
        """A submission can stay pending past the workflow's deadline. Reporting success then would
        leave users trying to install an unpublished version. A zero timeout reaches the deadline
        check immediately and requires a useful error, without making the test wait for a timer.
        """
        with self.assertRaisesRegex(TimeoutError, "still pending"):
            self.wait_with_responses(["pending"], timeout=0)

    def test_rejects_status_for_another_submission(self):
        """A published response for another submission must not complete this release. This feeds
        the polling function a successful status with the wrong identity and checks its rejection.
        It catches a lookup or response mixup that could label an unrelated artifact as published.
        """
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
