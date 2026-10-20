"""Publish tested bytes; never replace release assets or equate queued with published."""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import UUID

FILES = ("plugin.wasm", "metadata.json", "schema.json", "LICENSE")
ORIGIN = "https://registry.actionlint.kjanat.dev"


def check_tag(tag, manifest=Path("Cargo.toml")):
    version = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["version"]
    if tag != "v" + version or not re.fullmatch(
        r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag
    ):
        raise ValueError(f"Release tag must equal v{version}")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(directory=Path("artifacts"), expected=None):
    names = set(FILES) | {"SHA256SUMS"}
    if {path.name for path in directory.iterdir()} != names:
        raise ValueError("Package must contain exactly the five release files")
    checksums = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.]+)", line)
        if match is None or match[2] not in FILES or match[2] in checksums:
            raise ValueError("Malformed package checksums")
        checksums[match[2]] = match[1]
    if set(checksums) != set(FILES):
        raise ValueError("Incomplete package checksums")
    for name, checksum in checksums.items():
        if digest(directory / name) != checksum:
            raise ValueError(f"Package checksum mismatch: {name}")
    if expected is not None and checksums["plugin.wasm"] != expected:
        raise ValueError("Package differs from the tested component")
    return checksums["plugin.wasm"]


def request_json(url, token=None, payload=None, method=None):
    headers = {"User-Agent": "actionlint-plugin-shellcheck-release/1"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
        headers["Accept"] = "application/vnd.github+json"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    with urlopen(
        Request(url, data=data, headers=headers, method=method), timeout=30
    ) as response:
        return json.load(response)


def compare_assets(release, repository, tag, directory):
    names = [asset["name"] for asset in release["assets"]]
    expected = set(FILES) | {"SHA256SUMS"}
    if len(names) != len(set(names)) or not set(names) <= expected:
        raise ValueError("Existing release has unexpected or duplicate assets")
    with tempfile.TemporaryDirectory(prefix="shellcheck-release-") as temporary:
        for name in names:
            subprocess.run(
                [
                    "gh",
                    "release",
                    "download",
                    tag,
                    "--repo",
                    repository,
                    "--pattern",
                    name,
                    "--dir",
                    temporary,
                ],
                check=True,
            )
            if digest(Path(temporary) / name) != digest(directory / name):
                raise ValueError(f"Refusing to replace different release bytes: {name}")
    missing = sorted(expected - set(names))
    if missing and not release["draft"]:
        raise ValueError("Published release is incomplete; refusing to change it")
    return missing


def publish(directory=Path("artifacts")):
    tag = os.environ["RELEASE_TAG"]
    check_tag(tag)
    verify(directory, os.environ["EXPECTED_SHA256"])
    repository = os.environ["GITHUB_REPOSITORY"]
    token = os.environ["GH_TOKEN"]
    endpoint = f"https://api.github.com/repos/{repository}/releases"
    try:
        release = request_json(endpoint + "/tags/" + tag, token)
    except HTTPError as error:
        if error.code != 404:
            raise
        release = request_json(
            endpoint,
            token,
            {
                "tag_name": tag,
                "name": tag,
                "draft": True,
                "prerelease": "-" in tag,
                "body": "ShellCheck component for actionlint. SHA256SUMS records the tested package.\n"
                "Registry publication is tracked by the Release workflow; a release alone is not admission.",
            },
        )
    missing = compare_assets(release, repository, tag, directory)
    if missing:
        subprocess.run(
            [
                "gh",
                "release",
                "upload",
                tag,
                "--repo",
                repository,
                *[str(directory / name) for name in missing],
            ],
            check=True,
        )
    # Download every uploaded asset before making the draft public or submitting it.
    release = request_json(endpoint + "/" + str(release["id"]), token)
    if compare_assets(release, repository, tag, directory):
        raise ValueError("Release upload is incomplete")
    if release["draft"]:
        release = request_json(
            endpoint + "/" + str(release["id"]), token, {"draft": False}, method="PATCH"
        )
    if release.get("immutable") is not True:
        raise ValueError(
            "Release is not immutable; enable repository release immutability before publishing"
        )


def wait_for_publication(identifier, expected, timeout=1200):
    identifier = str(UUID(identifier))
    url = ORIGIN + "/v1/submissions/" + identifier
    deadline = time.monotonic() + timeout
    receipt = {
        "id": identifier,
        "sha256": expected,
        "status_url": url,
        "status": "pending",
    }
    while True:
        Path("publication.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        response = request_json(url)
        if response.get("id") != identifier:
            raise ValueError("Registry returned a different submission")
        status = response.get("status")
        receipt["status"] = status
        receipt["response"] = response
        Path("publication.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Registry submission {identifier}: {status}", flush=True)
        if status == "published":
            return
        if status not in ("pending", "validating"):
            raise ValueError(f"Registry publication did not succeed: {status}; {url}")
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Registry publication still {status}; inspect {url} and rerun this tag workflow"
            )
        time.sleep(30)


def main():
    command = sys.argv[1]
    if command == "check-tag":
        check_tag(os.environ["RELEASE_TAG"])
    elif command == "verify":
        checksum = verify()
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"sha256={checksum}\n")
    elif command == "publish":
        publish()
    elif command == "wait":
        wait_for_publication(os.environ["SUBMISSION_ID"], os.environ["EXPECTED_SHA256"])
    else:
        raise ValueError("Unknown release command")


if __name__ == "__main__":
    main()
