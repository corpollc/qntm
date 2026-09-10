"""Recipient-encrypted welcomes for an authorized contact addition.

Hosts publish the addition and rekey successfully before releasing any welcome,
and persist the exact prepared envelopes for uncertain-send recovery. Preparing
an operation neither sends messages nor modifies the supplied local checkpoint.
"""
import copy
import time

from .cbor import marshal_canonical, unmarshal
from .crypto import QSP1Suite
from .ed25519 import is_valid_ed25519_public_key
from .gate import seal_secret, open_secret
from .group import GroupState, create_group_add_body, parse_group_add_body, create_rekey, apply_rekey
from .identity import generate_message_id, key_id_from_public_key, validate_identity
from .message import create_message

_suite = QSP1Suite()
_DOMAIN = "qntm/group-welcome/v1"
MAX_GROUP_WELCOME_BYTES = 65536
GROUP_WELCOME_TTL = 604800
_MAX_EPOCH = 0xffffffff


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _uint(value):
    return type(value) is int and 0 <= value <= 9007199254740991


def _bytes(value, size):
    return isinstance(value, bytes) and len(value) == size


def _fields(value, names):
    return isinstance(value, dict) and set(value) == set(names.split(","))


def _header(envelope):
    return {key: envelope[key] for key in (
        "v", "suite", "kind", "conv_id", "msg_id", "conv_epoch", "created_ts", "expiry_ts",
    )}


def _validate_snapshot(value):
    _require(_fields(value, "group_name,description,created_at,founding_members"), "Invalid group snapshot")
    _require(isinstance(value["group_name"], str) and len(value["group_name"].encode()) <= 256
             and isinstance(value["description"], str) and len(value["description"].encode()) <= 4096
             and _uint(value["created_at"]), "Invalid group snapshot metadata")
    members = value["founding_members"]
    _require(isinstance(members, list) and 0 < len(members) <= 128, "Invalid group snapshot size")
    seen = set()
    for member in members:
        _require(_fields(member, "key_id,public_key,role,added_at,added_by")
                 and _bytes(member["key_id"], 16) and _bytes(member["public_key"], 32)
                 and is_valid_ed25519_public_key(member["public_key"])
                 and member["key_id"] == key_id_from_public_key(member["public_key"])
                 and member["role"] in ("admin", "member") and _uint(member["added_at"])
                 and _bytes(member["added_by"], 16), "Invalid group snapshot member")
        _require(member["key_id"] not in seen, "Duplicate group snapshot member")
        seen.add(member["key_id"])
    _require(members[0]["role"] == "admin", "Invalid group creator")


def prepare_group_addition(identity, conversation, state, recipients, ttl=GROUP_WELCOME_TTL):
    """Prepare one authorized contact addition with fresh keys.

    state is a trusted local checkpoint. Gateway-governed membership uses its
    governance operation instead. Post addition and rekey before welcomes.
    """
    validate_identity(identity)
    _require(conversation.get("type") == "group" and _bytes(conversation.get("id"), 16)
             and _uint(conversation.get("currentEpoch")) and conversation["currentEpoch"] < _MAX_EPOCH,
             "Invalid group addition context")
    snapshot = state.snapshot()
    _validate_snapshot(snapshot)
    _require(state.is_admin(identity["keyID"]), "Only a group administrator may add contacts")
    _require(isinstance(recipients, list) and len(recipients) > 0
             and state.member_count() + len(recipients) <= 128, "Invalid added contact count")
    _require(_uint(ttl) and 0 < ttl <= GROUP_WELCOME_TTL, "Invalid welcome lifetime")
    seen = set()
    for recipient in recipients:
        _require(_bytes(recipient, 32) and is_valid_ed25519_public_key(recipient), "Invalid contact public key")
        kid = key_id_from_public_key(recipient)
        _require(not state.is_member(kid) and kid not in seen, "Contact is already a group member")
        seen.add(kid)
    _require(sorted(conversation["participants"]) == sorted(state.list_members()), "Group roster differs from conversation")
    _require(_bytes(conversation["keys"]["root"], 32), "Invalid source group key")
    aead, nonce = _suite.derive_epoch_keys(conversation["keys"]["root"], conversation["id"], conversation["currentEpoch"])
    _require(aead == conversation["keys"]["aeadKey"] and nonce == conversation["keys"]["nonceKey"],
             "Source group keys do not match the epoch")
    next_state = GroupState()
    next_state.apply_genesis(snapshot)
    body = parse_group_add_body(create_group_add_body(identity, recipients))
    addition = create_message(identity, conversation, "group_add",
                              marshal_canonical({**body, "group_epoch": conversation["currentEpoch"]}), ttl_seconds=ttl)
    next_state.apply_add(body)
    rekey_body, new_key = create_rekey(identity, conversation, next_state, conversation["id"])
    rekey = create_message(identity, conversation, "group_rekey",
                           marshal_canonical({**unmarshal(rekey_body), "group_epoch": conversation["currentEpoch"]}),
                           ttl_seconds=ttl)
    next_conversation = copy.deepcopy(conversation)
    next_conversation["participants"] = next_state.list_members()
    apply_rekey(next_conversation, new_key, conversation["currentEpoch"] + 1)
    next_conversation.pop("inviteToken", None)
    welcomes = []
    for recipient in recipients:
        envelope = {"v": 1, "suite": "QSP-1", "kind": "group_welcome", "conv_id": conversation["id"],
                    "msg_id": generate_message_id(), "conv_epoch": next_conversation["currentEpoch"],
                    "created_ts": addition["created_ts"], "expiry_ts": addition["expiry_ts"]}
        payload = {"proto": _DOMAIN, "envelope": _header(envelope),
                   "inviter_ik_pk": identity["publicKey"], "recipient_ik_pk": recipient,
                   "group_key": new_key, "group_state": next_state.snapshot(),
                   "addition_id": addition["msg_id"], "rekey_id": rekey["msg_id"]}
        signature = _suite.sign(identity["privateKey"], marshal_canonical(payload))
        envelope["ciphertext"] = seal_secret(identity["privateKey"], recipient,
                                              marshal_canonical({"payload": payload, "signature": signature}))
        _require(len(marshal_canonical(envelope)) <= MAX_GROUP_WELCOME_BYTES, "Group welcome exceeds size limit")
        welcomes.append(envelope)
    return {"conversation": next_conversation, "state": next_state,
            "addition": addition, "rekey": rekey, "welcomes": welcomes}


def is_group_welcome_envelope(value):
    """Recognize the transport kind only; this is not authentication."""
    return isinstance(value, dict) and value.get("kind") == "group_welcome"


def open_group_welcome(identity, wire, *, conversation_id, inviter_public_key, at=None):
    """Open using the pinned contact and group, never a self-asserted inviter.

    Hosts must reject rollback and replay subsequent group updates before
    enabling sends/actions. This function returns bootstrap data, not a profile.
    """
    validate_identity(identity)
    _require(_bytes(inviter_public_key, 32) and is_valid_ed25519_public_key(inviter_public_key)
             and _bytes(conversation_id, 16), "Invalid pinned group contact")
    _require(isinstance(wire, bytes) and 0 < len(wire) <= MAX_GROUP_WELCOME_BYTES, "Invalid group welcome size")
    value = unmarshal(wire)
    _require(_fields(value, "v,suite,kind,conv_id,msg_id,conv_epoch,created_ts,expiry_ts,ciphertext")
             and type(value["v"]) is int and value["v"] == 1 and value["suite"] == "QSP-1"
             and value["kind"] == "group_welcome" and _bytes(value["conv_id"], 16) and _bytes(value["msg_id"], 16)
             and _uint(value["conv_epoch"]) and 0 < value["conv_epoch"] <= _MAX_EPOCH
             and _uint(value["created_ts"]) and value["created_ts"] > 0 and _uint(value["expiry_ts"])
             and 0 < value["expiry_ts"] - value["created_ts"] <= GROUP_WELCOME_TTL
             and isinstance(value["ciphertext"], bytes) and len(value["ciphertext"]) >= 40,
             "Invalid group welcome envelope")
    _require(wire == marshal_canonical(value), "Group welcome must use canonical CBOR")
    if at is None:
        at = int(time.time())
    _require(_uint(at) and value["created_ts"] <= at + 600 and at <= value["expiry_ts"],
             "Group welcome is expired or not yet valid")
    _require(value["conv_id"] == conversation_id, "Welcome belongs to a different group")
    plaintext = open_secret(identity["privateKey"], inviter_public_key, value["ciphertext"])
    opened = unmarshal(plaintext)
    _require(_fields(opened, "payload,signature") and _bytes(opened["signature"], 64), "Invalid signed group welcome")
    _require(plaintext == marshal_canonical(opened), "Signed group welcome must use canonical CBOR")
    payload = opened["payload"]
    _require(_fields(payload, "proto,envelope,inviter_ik_pk,recipient_ik_pk,group_key,group_state,addition_id,rekey_id")
             and payload["proto"] == _DOMAIN and _bytes(payload["inviter_ik_pk"], 32)
             and _bytes(payload["recipient_ik_pk"], 32) and _bytes(payload["group_key"], 32)
             and _bytes(payload["addition_id"], 16) and _bytes(payload["rekey_id"], 16), "Invalid group welcome payload")
    _require(payload["inviter_ik_pk"] == inviter_public_key and payload["recipient_ik_pk"] == identity["publicKey"],
             "Welcome contact binding differs")
    _require(marshal_canonical(payload["envelope"]) == marshal_canonical(_header(value)),
             "Welcome envelope differs from signed context")
    _require(_suite.verify(inviter_public_key, marshal_canonical(payload), opened["signature"]),
             "Invalid group welcome signature")
    _validate_snapshot(payload["group_state"])
    state = GroupState()
    state.apply_genesis(payload["group_state"])
    _require(state.is_admin(key_id_from_public_key(inviter_public_key)) and state.is_member(identity["keyID"]),
             "Welcome does not establish an admitted contact and administrator")
    aead, nonce = _suite.derive_epoch_keys(payload["group_key"], conversation_id, value["conv_epoch"])
    conversation = {"id": conversation_id, "type": "group", "name": state.group_name,
                    "keys": {"root": payload["group_key"], "aeadKey": aead, "nonceKey": nonce},
                    "participants": state.list_members(), "createdAt": state.created_at, "currentEpoch": value["conv_epoch"]}
    return {"conversation": conversation, "state": state, "inviter_public_key": inviter_public_key,
            "addition_id": payload["addition_id"], "rekey_id": payload["rekey_id"], "message_id": value["msg_id"]}
