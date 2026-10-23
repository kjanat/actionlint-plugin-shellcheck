import copy
import unittest
from pathlib import Path

import verify_installation


class InstallationProofTests(unittest.TestCase):
    def test_explicit_release_requires_both_version_and_digest(self):
        for version, checksum in (("v0.1.1", None), (None, "0" * 64)):
            with self.subTest(version=version), self.assertRaisesRegex(
                ValueError, "both release version and SHA-256"
            ):
                verify_installation.verify(Path("unused"), version, checksum)

    def test_contract_includes_packaged_wit_digest_with_lf_normalization(self):
        wit = (
            Path(__file__).resolve().parents[1] / "wit" / "analyzer.wit"
        ).read_bytes()
        expected = (
            "kjanat:actionlint/analyzer@0.1.0#sha256="
            "a0096f562ab3da46b30d0f025ad1c6ed0d46e5b7ea1a53660b3214e3270fcbee"
        )
        self.assertEqual(verify_installation.contract_identity(wit), expected)
        self.assertEqual(
            verify_installation.contract_identity(
                wit.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            ),
            expected,
        )

    def test_rejects_incomplete_wrong_or_additional_findings(self):
        result = {
            "completed": True,
            "exit_code": 1,
            "diagnostics": [
                {
                    "rule": "shellcheck",
                    "code": "SC2086",
                    "start": {"line": 6, "column": 19},
                    "end": {"line": 6, "column": 24},
                }
            ],
        }
        self.assertEqual(
            verify_installation.check_result(result), result["diagnostics"]
        )
        for field, value in (("completed", False), ("exit_code", 3)):
            invalid = copy.deepcopy(result)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_installation.check_result(invalid)
        for field, value in (
            ("rule", "shellcheck-rs"),
            ("code", "SC9999"),
            ("start", {"line": 1, "column": 6}),
        ):
            invalid = copy.deepcopy(result)
            invalid["diagnostics"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_installation.check_result(invalid)
        for findings in ([], result["diagnostics"] * 2):
            invalid = copy.deepcopy(result)
            invalid["diagnostics"] = findings
            with self.subTest(findings=findings), self.assertRaises(ValueError):
                verify_installation.check_result(invalid)


if __name__ == "__main__":
    unittest.main()
