#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def update_json_version(path: Path, version: str) -> None:
    data = json.loads(path.read_text())
    data["version"] = version
    packages = data.get("packages", {})
    if "" in packages:
        packages[""]["version"] = version
    path.write_text(json.dumps(data, indent=2) + "\n")


def update_client_link_version(path: Path, version: str) -> None:
    data = json.loads(path.read_text())
    packages = data.get("packages", {})
    for package_path, package_data in packages.items():
        if not isinstance(package_path, str) or not package_path.endswith("/client"):
            continue
        if isinstance(package_data, dict) and package_data.get("name") == "@corpollc/qntm":
            package_data["version"] = version
    path.write_text(json.dumps(data, indent=2) + "\n")


def update_uv_lock_project_version(path: Path, version: str) -> None:
    text = path.read_text()
    pattern = r'(\[\[package\]\]\nname = "qntm"\nversion = ").*?(")'
    updated, count = re.subn(pattern, rf"\g<1>{version}\2", text, count=1)
    if count != 1:
        fail(f"failed to update uv lock version in {path}")
    path.write_text(updated)


def replace_in_file(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        fail(f"failed to update version in {path}")
    path.write_text(updated)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: set_release_version.py <version>")

    version = sys.argv[1].strip()
    if not SEMVER_RE.match(version):
        fail(f"invalid version: {version}")

    update_json_version(REPO_ROOT / "client/package.json", version)
    update_json_version(REPO_ROOT / "client/package-lock.json", version)
    update_client_link_version(REPO_ROOT / "echo-worker/package-lock.json", version)
    update_client_link_version(REPO_ROOT / "gateway-worker/package-lock.json", version)
    update_client_link_version(REPO_ROOT / "integration/package-lock.json", version)
    update_client_link_version(REPO_ROOT / "openclaw-qntm/package-lock.json", version)
    update_client_link_version(REPO_ROOT / "ui/aim-chat/package-lock.json", version)
    update_client_link_version(REPO_ROOT / "ui/tui/package-lock.json", version)
    replace_in_file(
        REPO_ROOT / "python-dist/pyproject.toml",
        r'^version = ".*"$',
        f'version = "{version}"',
    )
    update_uv_lock_project_version(REPO_ROOT / "python-dist/uv.lock", version)
    replace_in_file(
        REPO_ROOT / "python-dist/src/qntm/__init__.py",
        r'^__version__ = ".*"$',
        f'__version__ = "{version}"',
    )
    replace_in_file(
        REPO_ROOT / "python-dist/tests/test_version.py",
        r'^    assert __version__ == ".*"$',
        f'    assert __version__ == "{version}"',
    )
    replace_in_file(
        REPO_ROOT / "python-dist/tests/test_version.py",
        r'^            "version": ".*",$',
        f'            "version": "{version}",',
    )

    print(f"updated release version to {version}")


if __name__ == "__main__":
    main()
