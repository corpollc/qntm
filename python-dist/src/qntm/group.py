"""Group conversation management for QSP.

Implements group genesis, member add/remove, rekey, and group state tracking.
Follows the archived Go reference implementation in attic/go/group/group.go and
attic/go/group/rekey.go.
"""

import time

from .cbor import marshal_canonical, unmarshal
from .crypto import QSP1Suite
from .identity import base64url_encode, key_id_from_public_key

_suite = QSP1Suite()


# --- Body construction helpers ---


def create_group_genesis_body(
    group_name: str,
    description: str,
    creator_identity: dict,
    founding_member_keys: list[bytes],
) -> bytes:
    """Create a CBOR-encoded group_genesis body.

    The creator is always included as the first member with role "admin".
    Additional founding_member_keys are added with role "member".
    """
    now = int(time.time())
    creator_kid = key_id_from_public_key(creator_identity["publicKey"])

    members = [
        {
            "key_id": creator_kid,
            "public_key": creator_identity["publicKey"],
            "role": "admin",
            "added_at": now,
            "added_by": creator_kid,
        }
    ]

    for pk in founding_member_keys:
        kid = key_id_from_public_key(pk)
        # Skip duplicates (e.g. creator passed again)
        if kid == creator_kid:
            continue
        if any(bytes(m["key_id"]) == kid for m in members):
            continue
        members.append({
            "key_id": kid,
            "public_key": pk,
            "role": "member",
            "added_at": now,
            "added_by": creator_kid,
        })

    body = {
        "created_at": now,
        "description": description,
        "founding_members": members,
        "group_name": group_name,
    }
    return marshal_canonical(body)


def parse_group_genesis_body(data: bytes) -> dict:
    """Parse a CBOR-encoded group_genesis body."""
    return unmarshal(data)


def create_group_add_body(
    adder_identity: dict,
    new_member_keys: list[bytes],
) -> bytes:
    """Create a CBOR-encoded group_add body."""
    now = int(time.time())
    adder_kid = key_id_from_public_key(adder_identity["publicKey"])

    new_members = []
    for pk in new_member_keys:
        kid = key_id_from_public_key(pk)
        new_members.append({
            "key_id": kid,
            "public_key": pk,
            "role": "member",
            "added_at": now,
            "added_by": adder_kid,
        })

    body = {
        "added_at": now,
        "new_members": new_members,
    }
    return marshal_canonical(body)


def parse_group_add_body(data: bytes) -> dict:
    """Parse a CBOR-encoded group_add body."""
    return unmarshal(data)


def create_group_remove_body(
    removed_member_kids: list[bytes],
    reason: str = "",
) -> bytes:
    """Create a CBOR-encoded group_remove body."""
    now = int(time.time())
    body = {
        "reason": reason,
        "removed_at": now,
        "removed_members": removed_member_kids,
    }
    return marshal_canonical(body)


def parse_group_remove_body(data: bytes) -> dict:
    """Parse a CBOR-encoded group_remove body."""
    return unmarshal(data)


def create_group_rekey_body(
    new_group_key: bytes,
    new_epoch: int,
    members: list[dict],
    conv_id: bytes,
) -> bytes:
    """Create a CBOR-encoded group_rekey body.

    members is a list of dicts with "kid" (bytes) and "public_key" (bytes).
    Each member gets the new_group_key wrapped for their public key.
    """
    wrapped_keys = {}
    for m in members:
        kid = m["kid"]
        pk = m["public_key"]
        kid_str = base64url_encode(kid)
        wrapped = _suite.wrap_key_for_recipient(new_group_key, pk, kid, conv_id)
        wrapped_keys[kid_str] = wrapped

    body = {
        "new_conv_epoch": new_epoch,
        "wrapped_keys": wrapped_keys,
    }
    return marshal_canonical(body)


def parse_group_rekey_body(data: bytes) -> dict:
    """Parse a CBOR-encoded group_rekey body."""
    return unmarshal(data)


# --- Group state ---


class GroupState:
    """Tracks the current state of a group conversation.

    Mirrors the Go GroupState struct.
    """

    def __init__(self):
        self.group_name: str = ""
        self.description: str = ""
        self.created_at: int = 0
        # members: kid (bytes) -> member info dict
        self.members: dict[bytes, dict] = {}
        # admins: set of kid (bytes)
        self.admins: set[bytes] = set()
        # creator kid
        self.creator: bytes | None = None

    def apply_genesis(self, parsed_body: dict) -> None:
        """Apply a parsed group_genesis body to update state."""
        self.group_name = parsed_body.get("group_name", "")
        self.description = parsed_body.get("description", "")
        self.created_at = parsed_body.get("created_at", 0)

        for member in parsed_body.get("founding_members", []):
            kid = bytes(member["key_id"])
            self.members[kid] = member
            role = member.get("role", "member")
            if role == "admin":
                self.admins.add(kid)
                if self.creator is None:
                    self.creator = kid

    def apply_add(self, parsed_body: dict) -> None:
        """Apply a parsed group_add body to update state."""
        for member in parsed_body.get("new_members", []):
            kid = bytes(member["key_id"])
            self.members[kid] = member
            role = member.get("role", "member")
            if role == "admin":
                self.admins.add(kid)

    def apply_remove(self, parsed_body: dict) -> None:
        """Apply a parsed group_remove body to update state."""
        for kid_raw in parsed_body.get("removed_members", []):
            kid = bytes(kid_raw)
            # Don't allow removing the creator
            if kid == self.creator:
                continue
            self.members.pop(kid, None)
            self.admins.discard(kid)

    def is_member(self, kid: bytes) -> bool:
        return bytes(kid) in self.members

    def is_admin(self, kid: bytes) -> bool:
        return bytes(kid) in self.admins

    def member_count(self) -> int:
        return len(self.members)

    def list_members(self) -> list[bytes]:
        return list(self.members.keys())

    def list_admins(self) -> list[bytes]:
        return list(self.admins)

    def to_dict(self) -> dict:
        """Serialize state for JSON storage."""
        members_list = []
        for kid, info in self.members.items():
            members_list.append({
                "key_id": kid.hex(),
                "public_key": bytes(info.get("public_key", b"")).hex(),
                "role": info.get("role", "member"),
                "added_at": info.get("added_at", 0),
                "added_by": bytes(info.get("added_by", b"")).hex(),
            })
        return {
            "group_name": self.group_name,
            "description": self.description,
            "created_at": self.created_at,
            "members": members_list,
            "admins": [k.hex() for k in self.admins],
            "creator": self.creator.hex() if self.creator else "",
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GroupState":
        """Deserialize state from JSON storage."""
        state = cls()
        state.group_name = data.get("group_name", "")
        state.description = data.get("description", "")
        state.created_at = data.get("created_at", 0)
        state.creator = bytes.fromhex(data["creator"]) if data.get("creator") else None

        for m in data.get("members", []):
            kid = bytes.fromhex(m["key_id"])
            state.members[kid] = {
                "key_id": kid,
                "public_key": bytes.fromhex(m.get("public_key", "")),
                "role": m.get("role", "member"),
                "added_at": m.get("added_at", 0),
                "added_by": bytes.fromhex(m.get("added_by", "")),
            }

        for kid_hex in data.get("admins", []):
            state.admins.add(bytes.fromhex(kid_hex))

        return state


# --- High-level operations ---


def process_group_message(body_type: str, body_bytes: bytes, state: GroupState) -> None:
    """Process a group management message and update state.

    Handles body_types: group_genesis, group_add, group_remove.
    group_rekey is processed separately.
    Non-group messages are ignored.
    """
    if body_type == "group_genesis":
        state.apply_genesis(parse_group_genesis_body(body_bytes))
    elif body_type == "group_add":
        state.apply_add(parse_group_add_body(body_bytes))
    elif body_type == "group_remove":
        state.apply_remove(parse_group_remove_body(body_bytes))
    # Other body types (text, group_rekey, etc.) are ignored


def create_rekey(
    sender_identity: dict,
    conversation: dict,
    state: GroupState,
    conv_id: bytes,
) -> tuple[bytes, bytes]:
    """Create a rekey body and return (body_bytes, new_group_key).

    Wraps a fresh group key for all current members.
    """
    new_group_key = _suite.generate_group_key()
    new_epoch = conversation["currentEpoch"] + 1

    members = []
    for kid, info in state.members.items():
        pk = info.get("public_key")
        if pk:
            members.append({"kid": kid, "public_key": bytes(pk)})

    body_bytes = create_group_rekey_body(
        new_group_key=new_group_key,
        new_epoch=new_epoch,
        members=members,
        conv_id=conv_id,
    )
    return body_bytes, new_group_key


def apply_rekey(conversation: dict, new_group_key: bytes, new_epoch: int) -> None:
    """Apply a rekey to a conversation, updating keys and epoch."""
    conv_id = conversation["id"]
    aead_key, nonce_key = _suite.derive_epoch_keys(new_group_key, conv_id, new_epoch)

    conversation["currentEpoch"] = new_epoch
    conversation["keys"]["root"] = new_group_key
    conversation["keys"]["aeadKey"] = aead_key
    conversation["keys"]["nonceKey"] = nonce_key
