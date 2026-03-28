"""Tests for package version and spec metadata surfaces."""

import tomllib
from pathlib import Path


def test_python_package_exports_spec_version():
    from qntm import PROTOCOL_VERSION, SPEC_VERSION, __version__

    assert __version__ == "0.4.20"
    assert SPEC_VERSION == "QSP-v1.1"
    assert PROTOCOL_VERSION == 1


def test_pyproject_spec_version_matches_runtime():
    from qntm import SPEC_VERSION

    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text())
    assert data["tool"]["qntm"]["spec-version"] == SPEC_VERSION


def test_cli_version_reports_spec_metadata(monkeypatch):
    from qntm.cli import cmd_version
    from qntm.constants import PROTOCOL_VERSION, SPEC_VERSION

    captured = {}

    def fake_output(kind, data, ok=True):
        captured["kind"] = kind
        captured["data"] = data
        captured["ok"] = ok

    monkeypatch.setattr("qntm.cli._output", fake_output)
    cmd_version(None)

    assert captured == {
        "kind": "version",
        "data": {
            "version": "0.4.20",
            "spec_version": SPEC_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "runtime": "python",
            "update_hint": "",
        },
        "ok": True,
    }
