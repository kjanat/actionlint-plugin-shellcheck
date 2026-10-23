"""Prove catalogue installation and cached checking with the public actionlint CLI."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

REPOSITORY = "github.com/kjanat/actionlint-plugin-shellcheck"
WORKFLOW = """on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo $HOME
"""


def contract_identity(wit):
    checksum = hashlib.sha256(wit.replace(b"\r\n", b"\n")).hexdigest()
    return "kjanat:actionlint/analyzer@0.1.0#sha256=" + checksum


def execute(binary, arguments, root, environment, expected=0):
    result = subprocess.run(
        [str(binary), *arguments],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != expected:
        raise ValueError(
            f"{arguments}: exit {result.returncode}, expected {expected}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def run(binary, arguments, root, environment, expected=0):
    return json.loads(execute(binary, arguments, root, environment, expected).stdout)


def check_result(result):
    if result.get("completed") is not True or result.get("exit_code") != 1:
        raise ValueError("Lint did not complete with findings")
    diagnostics = result["diagnostics"]
    if len(diagnostics) != 1:
        raise ValueError(f"Expected only SC2086: {diagnostics}")
    finding = diagnostics[0]
    if (
        finding.get("rule") != "shellcheck"
        or finding.get("code") != "SC2086"
        or finding.get("start") != {"line": 6, "column": 19}
        or finding.get("end") != {"line": 6, "column": 24}
    ):
        raise ValueError(f"Wrong plugin diagnostic or source mapping: {finding}")
    return diagnostics


def verify(binary, version, checksum):
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Expected a lowercase SHA-256 digest")
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("Expected an exact v-prefixed release version")
    binary = binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="shellcheck-install-") as temporary:
        root = Path(temporary)
        # Project discovery needs a repository boundary; no commits or hooks needed.
        (root / ".git").mkdir()
        (root / "workflow.yml").write_text(WORKFLOW, encoding="utf-8")
        cache = root / "cache"
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith("ACTIONLINT_")
        }
        environment.update(
            XDG_CACHE_HOME=str(cache),
            LOCALAPPDATA=str(cache),
            HOME=str(root),
        )
        host = run(binary, ["version", "--json"], root, environment)
        run(
            binary,
            ["plugin", "install", REPOSITORY, "--version", version, "--json"],
            root,
            environment,
        )
        lock_path = root / ".github" / "actionlint.plugins.lock.json"
        locked = lock_path.read_bytes()
        pins = json.loads(locked)["plugins"]
        if len(pins) != 1:
            raise ValueError(f"Expected exactly one installed plugin: {pins}")
        pin = pins[0]
        expected = {
            "name": REPOSITORY,
            "plugin_id": "shellcheck-rs",
            "selector": version,
            "version": version,
            "sha256": checksum,
            "kind": "component",
            "contract": contract_identity(
                (
                    Path(__file__).resolve().parents[1] / "wit" / "analyzer.wit"
                ).read_bytes()
            ),
        }
        if any(pin.get(key) != value for key, value in expected.items()):
            raise ValueError(f"Unexpected installed pin: {pin}")
        arguments = ["check", "--json", "--no-ruff", "workflow.yml"]
        diagnostics = check_result(run(binary, arguments, root, environment, 1))
        # Go's HTTP transport honors these variables. No remote artifact or
        # catalogue is available on the second check; verified cache bytes suffice.
        offline = {
            key: value
            for key, value in environment.items()
            if key.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
        }
        offline.update(
            HTTP_PROXY="http://127.0.0.1:1",
            HTTPS_PROXY="http://127.0.0.1:1",
            ALL_PROXY="http://127.0.0.1:1",
            NO_PROXY="",
        )
        if check_result(run(binary, arguments, root, offline, 1)) != diagnostics:
            raise ValueError("Cached checking changed diagnostics")
        if lock_path.read_bytes() != locked:
            raise ValueError("Checking changed the installed lock")
        artifacts = list(root.rglob(checksum))
        if not artifacts or not any(
            path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == checksum
            for path in artifacts
        ):
            raise ValueError(
                "Verified release bytes are missing from the isolated cache"
            )
        cached = next(path for path in artifacts if path.is_file())
        cached.unlink()
        missing = execute(binary, arguments, root, offline, 3)
        if missing.stdout.strip() or "plugin" not in missing.stderr.lower():
            raise ValueError(
                "Offline checking without the plugin must report a plugin error: "
                + missing.stderr
            )
        return {
            "host": host,
            "pin": pin,
            "diagnostic": diagnostics[0],
            "locked_check_with_blocked_proxy": "passed",
            "missing_artifact_with_blocked_proxy": "rejected",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actionlint", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    arguments = parser.parse_args()
    print(
        json.dumps(
            verify(arguments.actionlint, arguments.version, arguments.sha256), indent=2
        )
    )


if __name__ == "__main__":
    main()
