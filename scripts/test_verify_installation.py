import copy
import unittest

import verify_installation


class InstallationProofTests(unittest.TestCase):
    def test_rejects_incomplete_wrong_or_additional_findings(self):
        result = {
            "completed": True,
            "exit_code": 1,
            "diagnostics": [
                {
                    "rule": "shellcheck-rs",
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
            ("rule", "shellcheck"),
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
