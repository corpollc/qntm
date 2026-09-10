"""Participant invitations and verification of the gateway's signed chat acceptance."""
import hashlib
import json

from .cbor import marshal_canonical
from .gate import seal_secret
from .identity import base64url_encode, base64url_decode, key_id_from_public_key
from .ed25519 import is_valid_ed25519_public_key


def gateway_access(conversation):
    return {
        "conv_id": conversation["id"].hex(),
        "conv_aead_key": base64url_encode(conversation["keys"]["aeadKey"]),
        "conv_nonce_key": base64url_encode(conversation["keys"]["nonceKey"]),
        "conv_epoch": conversation["currentEpoch"],
    }


def valid_gateway(public_key, kid):
    try:
        pk = base64url_decode(public_key)
        return is_valid_ed25519_public_key(pk) and base64url_encode(pk) == public_key and base64url_encode(key_id_from_public_key(pk)) == kid
    except (ValueError, TypeError):
        return False


def create_gateway_invite_body(invitation, conversation, participants, floor):
    if not valid_gateway(invitation["gateway_public_key"], invitation["gateway_kid"]):
        raise ValueError("Invalid gateway identity")
    if type(floor) is not int or not 1 <= floor <= len(participants):
        raise ValueError("Invalid gateway approval threshold")
    return {
        "type": "gate.promote", "invitation_id": invitation["invitation_id"],
        "conv_id": conversation["id"].hex(), "conv_epoch": conversation["currentEpoch"],
        "gateway_kid": invitation["gateway_kid"], "gateway_public_key": invitation["gateway_public_key"],
        "expires_at": invitation["expires_at"],
        "keys_hash": hashlib.sha256(marshal_canonical(gateway_access(conversation))).hexdigest(),
        "participants": participants, "rules": [{"service": "*", "endpoint": "*", "verb": "*", "m": floor}], "floor": floor,
    }


def seal_gateway_bootstrap(identity, invitation, conversation, message_id, sequence):
    material = {**gateway_access(conversation), "invitation_msg_id": message_id, "invitation_seq": sequence}
    return {
        "invitation_id": invitation["invitation_id"], "inviter_public_key": base64url_encode(identity["publicKey"]),
        "sealed": base64url_encode(seal_secret(identity["privateKey"], base64url_decode(invitation["gateway_public_key"]),
                                               json.dumps(material, separators=(",", ":")).encode())),
    }


def matches_gateway_acceptance(acceptance, sender_kid, invitation_msg_id, invitation_text):
    """Call only after verifying the envelope, against a locally verified invitation."""
    try:
        invite = json.loads(invitation_text)
        return (invite["type"] == "gate.promote" and acceptance["type"] == "gate.accept"
                and valid_gateway(invite["gateway_public_key"], invite["gateway_kid"])
                and sender_kid == invite["gateway_kid"]
                and all(acceptance[key] == invite[key] for key in ("gateway_kid", "gateway_public_key", "invitation_id", "conv_id", "conv_epoch"))
                and acceptance["invitation_msg_id"] == invitation_msg_id
                and acceptance["invitation_hash"] == hashlib.sha256(invitation_text.encode()).hexdigest())
    except (ValueError, KeyError, TypeError):
        return False
