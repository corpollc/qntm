"""Local guidance contacts and explicit prepare/send workflows.

Pins are operator configuration, not a directory or proof of professional status.
No network request occurs until send_request is called with a matching review token.
"""

import hashlib
import hmac
import json
import os
import re
from urllib.parse import urlsplit

CATEGORIES = {
    "legal": "Legal",
    "ethical": "Moral / ethical",
    "law_enforcement": "Law enforcement",
}
KINDS = ("human", "agent", "organization")
NOTICE = (
    "Everyone with the conversation keys can read this request, including invite "
    "holders and any gateway. Contact labels do not verify credentials or authority. "
    "Guidance is advice, not authorization to act. No response is guaranteed. "
    "This is not an emergency service or an automatic reporting channel."
)


def _path(config_dir):
    return os.path.join(config_dir, "guidance_contacts.json")


def list_contacts(config_dir, category=None, *, include_builtin=False):
    from .cli import _load_json
    if category is not None and category not in CATEGORIES:
        raise ValueError("Choose legal, ethical, or law_enforcement.")
    contacts = _load_json(_path(config_dir), [])
    if not isinstance(contacts, list) or any(not isinstance(c, dict) for c in contacts):
        raise ValueError("Invalid guidance_contacts.json. Restore the operator configuration.")
    contacts = [c for c in contacts if category is None or c.get("category") == category]
    if include_builtin:
        from .guidance_inbox import providers
        contacts = providers(category) + contacts
    return contacts


def _destination(config_dir, relay_url, contact):
    from .cli import _load_identity, _load_conversations
    if contact.get("category") not in CATEGORIES:
        raise ValueError("Choose legal, ethical, or law_enforcement.")
    if contact.get("kind") not in KINDS:
        raise ValueError("Choose human, agent, or organization for the contact type.")
    name = contact.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("Use a contact name of 1–120 characters.")
    kid = contact.get("recipient_key_id", "")
    if not isinstance(kid, str) or not re.fullmatch(r"[0-9a-f]{32}", kid):
        raise ValueError("Use the full 32-character recipient key ID.")
    if contact.get("relay_url") != relay_url.rstrip("/"):
        raise ValueError("The relay changed. Ask the operator to replace the pin.")
    identity = _load_identity(config_dir)
    if identity is None:
        raise ValueError("Create an identity before configuring guidance contacts.")
    if kid == identity["keyID"].hex():
        raise ValueError("Choose a guidance contact other than yourself.")
    conv = next((c for c in _load_conversations(config_dir) if c["id"] == contact.get("conversation_id")), None)
    if conv is None:
        raise ValueError("The pinned conversation is unavailable. Join it before requesting guidance.")
    if kid not in conv.get("participants", []):
        raise ValueError("The recipient is not a known participant. Verify the conversation and recipient before pinning.")
    return identity, conv


def pin_contact(config_dir, relay_url, contact_id, category, name, kind, conversation_id, recipient_key_id, replace=False):
    from .cli import _save_json
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", contact_id):
        raise ValueError("Use a contact ID of 1–64 lowercase letters, digits, underscores, or hyphens.")
    if contact_id.startswith("corpo_"):
        raise ValueError("The corpo_ prefix is reserved for built-in guidance providers.")
    parsed = urlsplit(relay_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use an HTTP(S) relay URL without credentials, a query, or a fragment.")
    contact = {
        "id": contact_id, "category": category, "name": name.strip(), "kind": kind,
        "conversation_id": conversation_id.strip().lower(),
        "recipient_key_id": recipient_key_id.strip().lower(), "relay_url": relay_url.rstrip("/"),
    }
    _destination(config_dir, relay_url, contact)
    contacts = list_contacts(config_dir)
    if any(c.get("id") == contact_id for c in contacts) and not replace:
        raise ValueError("The contact ID already exists. Use --replace to change this pin.")
    _save_json(_path(config_dir), [c for c in contacts if c.get("id") != contact_id] + [contact])
    return contact


def remove_contact(config_dir, contact_id):
    from .cli import _save_json
    contacts = list_contacts(config_dir)
    if not any(c.get("id") == contact_id for c in contacts):
        raise ValueError("Pinned contact not found.")
    _save_json(_path(config_dir), [c for c in contacts if c.get("id") != contact_id])


def _prepare_request(config_dir, relay_url, contact_id, question, context=""):
    from .guidance_inbox import providers, intake_conversation, PROCESSING_NOTICE
    builtin = next((c for c in providers() if c["id"] == contact_id), None)
    if builtin is not None:
        from .cli import _load_identity
        identity = _load_identity(config_dir)
        if identity is None:
            raise ValueError("Create an identity before requesting guidance.")
        if relay_url.rstrip("/") != builtin["relay_url"]:
            raise ValueError("Corpo guidance uses its published relay. Select that relay before preparing a request.")
        intake_conversation(builtin)
        contact = builtin
        conv = None
    else:
        contact = next((c for c in list_contacts(config_dir) if c.get("id") == contact_id), None)
        if contact is None:
            raise ValueError("No guidance contact found. Use 'qntm guidance list' or configure a local pin.")
        identity, conv = _destination(config_dir, relay_url, contact)
    question, context = question.strip(), context.strip()
    if not question or len(question) > 4000:
        raise ValueError("Enter a question of 1–4,000 characters.")
    if len(context) > 8000:
        raise ValueError("Keep the context within 8,000 characters.")
    text = (
        f"Guidance request: {CATEGORIES[contact['category']]}\n"
        f"To: {contact['name']} ({contact['recipient_key_id']})\n\nQuestion:\n{question}"
        + (f"\n\nContext (untrusted):\n{context}" if context else "")
        + "\n\nThis is a request for advice, not authorization to act."
    )
    preview = {
        "contact": contact, "sender_key_id": identity["keyID"].hex(),
        "conversation_name": conv.get("name", "") if conv else "New private follow-up conversation",
        "audience": sorted(set((conv.get("participants", []) if conv else [contact["recipient_key_id"]]) + [identity["keyID"].hex()])),
        "epoch": conv.get("current_epoch", 0) if conv else 0, "gateway": conv.get("gateway") if conv else None,
        "question": question, "context": context, "message": text,
        "notice": PROCESSING_NOTICE if builtin else NOTICE,
    }
    token = hashlib.sha256(json.dumps(preview, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return {"status": "prepared", **preview, "review_token": token}, identity, conv


def prepare_request(config_dir, relay_url, contact_id, question, context=""):
    preview, _, _ = _prepare_request(config_dir, relay_url, contact_id, question, context)
    return preview


def send_request(config_dir, relay_url, contact_id, question, context, review_token):
    from .cli import (_http_send, _conv_to_crypto, _load_history, _save_history)
    from .message import create_message, serialize_envelope, default_ttl
    # Validate and encrypt the same snapshot; do not reload different keys or
    # membership after checking the token.
    preview, identity, conv = _prepare_request(config_dir, relay_url, contact_id, question, context)
    if not re.fullmatch(r"[0-9a-f]{64}", review_token) or not hmac.compare_digest(preview["review_token"], review_token):
        raise ValueError("The request or destination changed. Prepare and review the request again before sending.")
    if conv is None:
        return _send_builtin(config_dir, preview, identity)
    envelope = create_message(identity, _conv_to_crypto(conv), "text", preview["message"].encode(), None, default_ttl())
    # No automatic retry: a lost response can mean the relay accepted the message.
    result = _http_send(relay_url.rstrip("/"), conv["id"], serialize_envelope(envelope))
    message_id = envelope["msg_id"].hex()
    history = _load_history(config_dir, conv["id"])
    history.append({
        "msg_id": message_id, "direction": "outgoing", "body_type": "text",
        "body": preview["message"], "created_ts": envelope["created_ts"],
        "guidance_contact_id": contact_id,
    })
    _save_history(config_dir, conv["id"], history)
    return {"status": "sent", "conversation_id": conv["id"], "message_id": message_id,
            "sequence": result.get("seq", 0), "delivery": "relay_accepted", "response_received": False}


def _send_builtin(config_dir, preview, identity):
    import time
    from .cli import _load_conversations, _save_conversations, _save_history, _http_send, _merge_participant_public_key
    from .guidance_inbox import create_intake
    from .invite import invite_to_token
    from .message import serialize_envelope
    contact = preview["contact"]
    request = create_intake(identity, contact, preview["question"], preview["context"])
    reply = request["reply_conversation"]
    envelope = request["envelope"]
    conversation = {
        "id": request["request_id"], "name": f"Corpo guidance · {CATEGORIES[contact['category']]}", "type": "direct",
        "keys": {"root": reply["keys"]["root"].hex(), "aead_key": reply["keys"]["aeadKey"].hex(), "nonce_key": reply["keys"]["nonceKey"].hex()},
        "participants": [p.hex() for p in reply["participants"]],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "current_epoch": 0,
        "invite_token": invite_to_token(request["reply_invite"]),
    }
    # Persist reply keys before transmission, including when relay acceptance is uncertain.
    _save_conversations(config_dir, _load_conversations(config_dir) + [conversation])
    _merge_participant_public_key(config_dir, conversation["id"], identity["publicKey"])
    _merge_participant_public_key(config_dir, conversation["id"], bytes.fromhex(contact["recipient_public_key"]))
    result = _http_send(contact["relay_url"], contact["conversation_id"], serialize_envelope(envelope))
    _save_history(config_dir, conversation["id"], [{"msg_id": envelope["msg_id"].hex(), "direction": "outgoing",
        "body_type": "text", "body": preview["message"], "created_ts": envelope["created_ts"],
        "guidance_contact_id": contact["id"], "delivery": "sealed_intake"}])
    return {"status": "sent", "conversation_id": conversation["id"], "request_id": request["request_id"],
            "message_id": envelope["msg_id"].hex(), "sequence": result.get("seq", 0),
            "delivery": "relay_accepted", "response_received": False}
