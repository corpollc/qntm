"""Local naming store for identities and conversations.

Persists a simple JSON dict at <config_dir>/names.json:
{
    "identities": { "<kid_hex>": "<local_name>", ... },
    "conversations": { "<conv_id_hex>": "<local_name>", ... }
}
"""

import json
import os


class NamingStore:
    """Manage local nicknames for KIDs and conversation IDs."""

    def __init__(self, config_dir: str):
        self._path = os.path.join(config_dir, "names.json")
        self._data = self._load()

    def _load(self) -> dict:
        if os.path.isfile(self._path):
            with open(self._path) as f:
                return json.load(f)
        return {"identities": {}, "conversations": {}}

    def _save(self):
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w") as f:
            json.dump(self._data, f, indent=2)
            f.write("\n")

    # --- Identities ---

    def set_identity_name(self, kid_hex: str, name: str):
        """Assign a local name to a KID. Names are unique: if another KID
        already has this name, it loses it."""
        # Remove name from any other KID
        to_remove = [
            k for k, v in self._data["identities"].items()
            if v == name and k != kid_hex
        ]
        for k in to_remove:
            del self._data["identities"][k]
        self._data["identities"][kid_hex] = name
        self._save()

    def resolve_identity_by_name(self, name: str) -> str | None:
        """Look up a KID by its local name. Returns kid_hex or None."""
        for kid, n in self._data["identities"].items():
            if n == name:
                return kid
        return None

    def list_identities(self) -> dict[str, str]:
        """Return {kid_hex: name} for all named identities."""
        return dict(self._data["identities"])

    def remove_identity_name(self, name: str) -> bool:
        """Remove a name by its display name. Returns True if found."""
        for kid, n in list(self._data["identities"].items()):
            if n == name:
                del self._data["identities"][kid]
                self._save()
                return True
        return False

    # --- Conversations ---

    def set_conversation_name(self, conv_id_hex: str, name: str):
        """Assign a local name to a conversation ID. Names are unique."""
        to_remove = [
            k for k, v in self._data["conversations"].items()
            if v == name and k != conv_id_hex
        ]
        for k in to_remove:
            del self._data["conversations"][k]
        self._data["conversations"][conv_id_hex] = name
        self._save()

    def resolve_conversation_by_name(self, name: str) -> str | None:
        """Look up a conversation ID by its local name. Returns hex or None."""
        for cid, n in self._data["conversations"].items():
            if n == name:
                return cid
        return None

    def list_conversations(self) -> dict[str, str]:
        """Return {conv_id_hex: name} for all named conversations."""
        return dict(self._data["conversations"])

    def remove_conversation_name(self, name: str) -> bool:
        """Remove a conversation name. Returns True if found."""
        for cid, n in list(self._data["conversations"].items()):
            if n == name:
                del self._data["conversations"][cid]
                self._save()
                return True
        return False

    # --- Ref resolution helpers ---

    def all_known_ids(self) -> list[str]:
        """Return all known KIDs and conversation IDs."""
        return list(self._data["identities"].keys()) + list(
            self._data["conversations"].keys()
        )
