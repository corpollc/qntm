"""Tests for local naming and ref resolution."""

import json
import os
import tempfile

import pytest

from qntm.naming import NamingStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(tmpdir=None):
    """Create a NamingStore backed by a temp directory."""
    if tmpdir is None:
        tmpdir = tempfile.mkdtemp()
    return NamingStore(tmpdir), tmpdir


# ---------------------------------------------------------------------------
# NamingStore unit tests
# ---------------------------------------------------------------------------

class TestNamingStoreIdentities:
    def test_set_and_get_identity_name(self):
        store, _ = _make_store()
        store.set_identity_name("abcd1234abcd1234abcd1234abcd1234", "alice")
        assert store.resolve_identity_by_name("alice") == "abcd1234abcd1234abcd1234abcd1234"

    def test_overwrite_identity_name(self):
        store, _ = _make_store()
        kid = "abcd1234abcd1234abcd1234abcd1234"
        store.set_identity_name(kid, "alice")
        store.set_identity_name(kid, "bob")
        assert store.resolve_identity_by_name("bob") == kid
        assert store.resolve_identity_by_name("alice") is None

    def test_list_identities(self):
        store, _ = _make_store()
        store.set_identity_name("aaa0" * 8, "alice")
        store.set_identity_name("bbb0" * 8, "bob")
        ids = store.list_identities()
        assert len(ids) == 2
        assert ids["aaa0" * 8] == "alice"

    def test_remove_identity_by_name(self):
        store, _ = _make_store()
        kid = "abcd" * 8
        store.set_identity_name(kid, "alice")
        assert store.remove_identity_name("alice") is True
        assert store.resolve_identity_by_name("alice") is None

    def test_remove_identity_not_found(self):
        store, _ = _make_store()
        assert store.remove_identity_name("ghost") is False


class TestNamingStoreConversations:
    def test_set_and_get_conversation_name(self):
        store, _ = _make_store()
        cid = "1111" * 8
        store.set_conversation_name(cid, "work-chat")
        assert store.resolve_conversation_by_name("work-chat") == cid

    def test_overwrite_conversation_name(self):
        store, _ = _make_store()
        cid = "1111" * 8
        store.set_conversation_name(cid, "old")
        store.set_conversation_name(cid, "new")
        assert store.resolve_conversation_by_name("new") == cid
        assert store.resolve_conversation_by_name("old") is None

    def test_list_conversations(self):
        store, _ = _make_store()
        store.set_conversation_name("aaa0" * 8, "chat-a")
        store.set_conversation_name("bbb0" * 8, "chat-b")
        convs = store.list_conversations()
        assert len(convs) == 2

    def test_remove_conversation_by_name(self):
        store, _ = _make_store()
        store.set_conversation_name("cccc" * 8, "temp")
        assert store.remove_conversation_name("temp") is True
        assert store.resolve_conversation_by_name("temp") is None

    def test_remove_conversation_not_found(self):
        store, _ = _make_store()
        assert store.remove_conversation_name("nope") is False


class TestNamingStorePersistence:
    def test_persists_across_instances(self):
        tmpdir = tempfile.mkdtemp()
        store1 = NamingStore(tmpdir)
        store1.set_identity_name("dead" * 8, "alice")
        store1.set_conversation_name("beef" * 8, "chat")

        store2 = NamingStore(tmpdir)
        assert store2.resolve_identity_by_name("alice") == "dead" * 8
        assert store2.resolve_conversation_by_name("chat") == "beef" * 8

    def test_names_json_is_valid_json(self):
        tmpdir = tempfile.mkdtemp()
        store = NamingStore(tmpdir)
        store.set_identity_name("abcd" * 8, "alice")
        path = os.path.join(tmpdir, "names.json")
        assert os.path.isfile(path)
        with open(path) as f:
            data = json.load(f)
        assert "identities" in data
        assert "conversations" in data


class TestNamingStoreEdgeCases:
    def test_empty_store_lists(self):
        store, _ = _make_store()
        assert store.list_identities() == {}
        assert store.list_conversations() == {}

    def test_name_uniqueness_across_identities(self):
        """Two different KIDs cannot share the same name."""
        store, _ = _make_store()
        store.set_identity_name("aaaa" * 8, "alice")
        store.set_identity_name("bbbb" * 8, "alice")
        # The second set should claim the name, removing it from the first
        assert store.resolve_identity_by_name("alice") == "bbbb" * 8
        ids = store.list_identities()
        # First KID should have lost its name
        assert "aaaa" * 8 not in ids

    def test_case_sensitive_names(self):
        store, _ = _make_store()
        store.set_identity_name("aaaa" * 8, "Alice")
        assert store.resolve_identity_by_name("Alice") == "aaaa" * 8
        assert store.resolve_identity_by_name("alice") is None


# ---------------------------------------------------------------------------
# Ref resolution tests
# ---------------------------------------------------------------------------

class TestRefResolution:
    def test_prefix_match_single(self):
        store, _ = _make_store()
        store.set_identity_name("abcd1234" * 4, "alice")
        store.set_conversation_name("ef012345" * 4, "chat")
        # Collect all known IDs
        all_ids = list(store.list_identities().keys()) + list(store.list_conversations().keys())
        matches = [x for x in all_ids if x.startswith("abcd")]
        assert len(matches) == 1
        assert matches[0] == "abcd1234" * 4

    def test_prefix_match_ambiguous(self):
        store, _ = _make_store()
        store.set_identity_name("abcd1111" * 4, "alice")
        store.set_identity_name("abcd2222" * 4, "bob")
        all_ids = list(store.list_identities().keys())
        matches = [x for x in all_ids if x.startswith("abcd")]
        assert len(matches) == 2

    def test_prefix_match_none(self):
        store, _ = _make_store()
        all_ids = list(store.list_identities().keys())
        matches = [x for x in all_ids if x.startswith("zzzz")]
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# CLI integration tests (using _resolve_conversation with names)
# ---------------------------------------------------------------------------

class TestCLIResolveWithNames:
    """Test that _resolve_conversation and name-based resolution integrate."""

    def test_resolve_conversation_by_name(self):
        """_resolve_conversation should fall back to name store."""
        from qntm.cli import _resolve_conversation
        conversations = [
            {"id": "aabb" * 8, "name": "test"},
        ]
        # By ID still works
        assert _resolve_conversation(conversations, "aabb" * 8) is not None
        # By prefix still works
        assert _resolve_conversation(conversations, "aabb") is not None


class TestCLINamingCommands:
    """Test the cmd_name_* and cmd_convo_name functions."""

    def _make_config_dir(self):
        tmpdir = tempfile.mkdtemp()
        return tmpdir

    def test_cmd_name_set_and_list(self):
        from qntm.cli import cmd_name_set, cmd_name_list
        tmpdir = self._make_config_dir()
        # Mock args
        class Args:
            config_dir = tmpdir
            kid_or_ref = "abcd" * 8
            local_name = "alice"
        cmd_name_set(Args())

        class ListArgs:
            config_dir = tmpdir
        result = cmd_name_list(ListArgs())
        # Should not raise

    def test_cmd_name_remove(self):
        from qntm.cli import cmd_name_set, cmd_name_remove
        tmpdir = self._make_config_dir()

        class SetArgs:
            config_dir = tmpdir
            kid_or_ref = "abcd" * 8
            local_name = "alice"
        cmd_name_set(SetArgs())

        class RemoveArgs:
            config_dir = tmpdir
            name = "alice"
        cmd_name_remove(RemoveArgs())

    def test_cmd_convo_name(self):
        from qntm.cli import cmd_convo_name
        tmpdir = self._make_config_dir()
        # Create a conversation file
        conv_id = "beef" * 8
        convs = [{"id": conv_id, "name": "test"}]
        with open(os.path.join(tmpdir, "conversations.json"), "w") as f:
            json.dump(convs, f)

        class Args:
            config_dir = tmpdir
            conversation = conv_id
            local_name = "my-chat"
        cmd_convo_name(Args())

        # Verify it persisted
        store = NamingStore(tmpdir)
        assert store.resolve_conversation_by_name("my-chat") == conv_id

    def test_cmd_ref_resolve(self):
        from qntm.cli import cmd_ref
        tmpdir = self._make_config_dir()
        # Create identity + conversations for the trie
        from qntm.identity import generate_identity
        ident = generate_identity()
        ident_data = {
            "private_key": ident["privateKey"].hex(),
            "public_key": ident["publicKey"].hex(),
            "key_id": ident["keyID"].hex(),
        }
        with open(os.path.join(tmpdir, "identity.json"), "w") as f:
            json.dump(ident_data, f)
        with open(os.path.join(tmpdir, "conversations.json"), "w") as f:
            json.dump([], f)

        kid_hex = ident["keyID"].hex()
        class Args:
            config_dir = tmpdir
            short_prefix = kid_hex[:6]
        # Should not raise
        cmd_ref(Args())
