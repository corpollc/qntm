"""Recipient-sealed guidance intake. Public intake invite holders cannot read requests."""
import json
from pathlib import Path

from .gate import seal_secret, open_secret
from .identity import key_id_from_public_key, base64url_encode, base64url_decode
from .invite import (create_invite, invite_from_url, invite_to_token, create_conversation,
                     derive_conversation_keys, add_participant)
from .message import create_message, decrypt_message

INTAKE_TYPE = "guidance.sealed.v1"
DOMAIN = "qntm.guidance.request.v1"
PROCESSING_NOTICE = ("Free guidance provided by Corpo. Requests are processed by Grok for triage "
                     "and may be passed to the Corpo team. No automated substantive advice or response is promised.")


def providers(category=None):
    records = json.loads(Path(__file__).with_name("guidance_providers.json").read_text())
    return [p for p in records if category is None or p["category"] == category]


def intake_conversation(provider):
    if provider.get("category") not in ("legal", "ethical", "law_enforcement") or provider.get("delivery") != "sealed_intake_v1":
        raise ValueError("Invalid guidance provider")
    invite = invite_from_url(provider["intake_invite"])
    if (invite["type"] != "direct" or invite["conv_id"].hex() != provider["conversation_id"] or
            invite["inviter_ik_pk"].hex() != provider["recipient_public_key"] or
            key_id_from_public_key(invite["inviter_ik_pk"]).hex() != provider["recipient_key_id"]):
        raise ValueError("Guidance provider key or intake mismatch")
    return create_conversation(invite, derive_conversation_keys(invite))


def validate_text(question, context):
    if (not isinstance(question, str) or not question.strip() or len(question) > 4000 or
            not isinstance(context, str) or len(context) > 8000):
        raise ValueError("Guidance requires a question of 1–4,000 characters and context of at most 8,000 characters")


def create_intake(identity, provider, question, context=""):
    intake = intake_conversation(provider)
    question, context = question.strip(), context.strip()
    validate_text(question, context)
    reply_invite = create_invite(identity)
    reply = create_conversation(reply_invite, derive_conversation_keys(reply_invite))
    add_participant(reply, bytes.fromhex(provider["recipient_public_key"]))
    payload = {"domain": DOMAIN, "category": provider["category"], "recipient_key_id": provider["recipient_key_id"],
               "request_id": reply_invite["conv_id"].hex(), "reply_invite": invite_to_token(reply_invite),
               "question": question, "context": context}
    sealed = seal_secret(identity["privateKey"], bytes.fromhex(provider["recipient_public_key"]), json.dumps(payload).encode())
    envelope = create_message(identity, intake, INTAKE_TYPE, base64url_encode(sealed).encode(), None, 7 * 86400)
    return {"envelope": envelope, "reply_invite": reply_invite, "reply_conversation": reply, "request_id": payload["request_id"]}


def open_intake(identity, provider, envelope):
    if identity["publicKey"].hex() != provider["recipient_public_key"] or len(envelope["ciphertext"]) > 100000:
        raise ValueError("Invalid guidance recipient or request size")
    message = decrypt_message(envelope, intake_conversation(provider))
    inner = message["inner"]
    if inner["body_type"] != INTAKE_TYPE:
        raise ValueError("Expected a sealed guidance request")
    raw = open_secret(identity["privateKey"], bytes(inner["sender_ik_pk"]), base64url_decode(bytes(inner["body"]).decode()))
    if len(raw) > 60000:
        raise ValueError("Guidance request too large")
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {"domain", "category", "recipient_key_id", "request_id", "reply_invite", "question", "context"} or
            value["domain"] != DOMAIN or value["category"] != provider["category"] or value["recipient_key_id"] != provider["recipient_key_id"] or
            not isinstance(value["reply_invite"], str) or len(value["reply_invite"]) > 2048):
        raise ValueError("Invalid guidance payload")
    validate_text(value["question"], value["context"])
    reply = invite_from_url(value["reply_invite"])
    if (reply["type"] != "direct" or reply["inviter_ik_pk"] != inner["sender_ik_pk"] or
            value["request_id"] != reply["conv_id"].hex() or value["request_id"] == provider["conversation_id"]):
        raise ValueError("Guidance reply destination does not match sender")
    return {"request_id": value["request_id"], "question": value["question"], "context": value["context"],
            "sender_public_key": bytes(inner["sender_ik_pk"]), "sender_key_id": bytes(inner["sender_kid"]).hex(),
            "reply_invite": reply, "message": message}
