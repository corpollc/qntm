"""Private permissions and failure-safe storage of signing and conversation keys."""
import json
import os
from pathlib import Path
import stat

import pytest

from qntm import cli
from qntm.identity import generate_identity
from qntm.storage import load_json, private_directory, save_json


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_new_state_is_private_under_any_umask(tmp_path, umask):
    profile = tmp_path / "profile"
    previous = os.umask(umask)
    try:
        cli._save_identity(str(profile), generate_identity())
        cli._save_conversations(str(profile), [])
        cli._save_history(str(profile), "ab" * 16, [{"unsafe_body": "private"}])
    finally:
        os.umask(previous)
    for path in [profile, profile / "chats"]:
        assert mode(path) == 0o700
    for path in profile.rglob("*.json"):
        assert mode(path) == 0o600


def test_read_repairs_existing_permissions_without_changing_contents(tmp_path):
    path = tmp_path / "identity.json"
    path.write_text('{"private_key": "sensitive"}')
    path.chmod(0o644)
    tmp_path.chmod(0o755)
    assert load_json(path) == {"private_key": "sensitive"}
    assert mode(tmp_path) == 0o700
    assert mode(path) == 0o600
    assert path.read_text() == '{"private_key": "sensitive"}'


@pytest.mark.parametrize("failure", ["serialize", "fsync", "replace"])
def test_failed_write_preserves_original_and_cleans_temporary_file(tmp_path, monkeypatch, failure):
    path = tmp_path / "keys.json"
    save_json(path, {"key": "original"})
    if failure != "serialize":
        def fail(*_):
            raise OSError("simulated interruption")
        monkeypatch.setattr(os, failure, fail)
    with pytest.raises((TypeError, OSError)):
        save_json(path, {"key": object() if failure == "serialize" else "replacement"})
    assert json.loads(path.read_text()) == {"key": "original"}
    assert mode(path) == 0o600
    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_replacement_is_private_before_publication(tmp_path, monkeypatch):
    path = tmp_path / "keys.json"
    save_json(path, {"key": "old"})
    replace = os.replace
    def inspect(source, destination):
        assert mode(Path(source)) == 0o600
        assert load_json(path) == {"key": "old"}
        replace(source, destination)
    monkeypatch.setattr(os, "replace", inspect)
    save_json(path, {"key": "new"})
    assert load_json(path) == {"key": "new"}
    assert mode(path) == 0o600


def test_symlinks_and_hardlinks_cannot_redirect_private_io(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"keep":true}')
    outside.chmod(0o644)
    profile = tmp_path / "profile"
    profile.mkdir()
    linked = profile / "identity.json"
    linked.symlink_to(outside)
    for operation in [lambda: load_json(linked), lambda: save_json(linked, {})]:
        with pytest.raises(ValueError, match="symlink"):
            operation()
    assert mode(outside) == 0o644
    linked.unlink()
    os.link(outside, linked)
    with pytest.raises(ValueError, match="hard links"):
        save_json(linked, {})
    assert outside.read_text() == '{"keep":true}'


def test_dangling_and_directory_symlinks_are_rejected(tmp_path):
    linked = tmp_path / "keys.json"
    linked.symlink_to(tmp_path / "missing")
    with pytest.raises(ValueError, match="symlink"):
        load_json(linked)
    profile = tmp_path / "profile"
    profile.symlink_to(tmp_path / "target", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        private_directory(profile)


def test_shared_directories_are_not_chmodded():
    import tempfile
    for path in [Path.home(), Path(tempfile.gettempdir()), Path("/")]:
        original = mode(path)
        with pytest.raises(ValueError, match="dedicated"):
            private_directory(path)
        assert mode(path) == original


def test_announce_and_naming_use_private_storage(tmp_path):
    from qntm.announce import save_announce_store, load_announce_store
    from qntm.naming import NamingStore
    path = str(tmp_path / "profile")
    save_announce_store(path, {"channels": {"test": {"private_key": "private"}}})
    assert load_announce_store(path)["channels"]["test"]["private_key"] == "private"
    NamingStore(path).set_identity_name("ab" * 16, "Peer")
    for file in Path(path).iterdir():
        assert mode(file) == 0o600
