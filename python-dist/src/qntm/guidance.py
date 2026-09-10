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


def list_contacts(config_dir, category=None):
    from .cli import _load_json
    if category is not None and category not in CATEGORIES:
        raise ValueError("Choose legal, ethical, or law_enforcement.")
    contacts = _load_json(_path(config_dir), [])
    if not isinstance(contacts, list) or any(not isinstance(c, dict) for c in contacts):
        raise ValueError("Invalid guidance_contacts.json. Restore the operator configuration.")
    return [c for c in contacts if category is None or c.get("category") == category]


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
    if conv.get('group_session'):
        from .group_session import assert_group_can_send
        assert_group_can_send(identity, conv['group_session'])
    return identity, conv


def pin_contact(config_dir, relay_url, contact_id, category, name, kind, conversation_id, recipient_key_id, replace=False):
    from .cli import _save_json
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", contact_id):
        raise ValueError("Use a contact ID of 1–64 lowercase letters, digits, underscores, or hyphens.")
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
    contact = next((c for c in list_contacts(config_dir) if c.get("id") == contact_id), None)
    if contact is None:
        raise ValueError("No pinned contact found. Ask the operator to configure one with 'qntm guidance pin'.")
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
        "conversation_name": conv.get("name", ""),
        "audience": sorted(set(conv.get("participants", []) + [identity["keyID"].hex()])),
        "epoch": conv.get("current_epoch", 0), "gateway": conv.get("gateway"),
        "question": question, "context": context, "message": text, "notice": NOTICE,
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
    if conv.get('group_session'):
        from .group_client import GroupClient
        GroupClient(config_dir, identity, relay_url).sync(conv['id'])
        # Refresh before comparing the reviewed audience, never after it.
        preview, identity, conv = _prepare_request(config_dir, relay_url, contact_id, question, context)
        if conv.get('group_operation'):
            raise ValueError('A group operation is pending; finish it before sending guidance')
    if not re.fullmatch(r"[0-9a-f]{64}", review_token) or not hmac.compare_digest(preview["review_token"], review_token):
        raise ValueError("The request or destination changed. Prepare and review the request again before sending.")
    envelope = create_message(identity, _conv_to_crypto(conv), "text", preview["message"].encode(), None, default_ttl())
    # No automatic retry: a lost response can mean the relay accepted the message.
    result = _http_send(relay_url.rstrip("/"), conv["id"], serialize_envelope(envelope))
    message_id = envelope["msg_id"].hex()
    history = _load_history(config_dir, conv["id"])
    history.append({
        "msg_id": message_id, "direction": "outgoing", "body_type": "text",
        "body": preview["message"], "created_ts": envelope["created_ts"],
        "guidance_contact_id": contact_id,
        "relay_receipt_sequence": result.get('seq', 0),
    })
    _save_history(config_dir, conv["id"], history)
    return {"status": "sent", "conversation_id": conv["id"], "message_id": message_id,
            "sequence": result.get("seq", 0), "delivery": "relay_accepted", "response_received": False}
