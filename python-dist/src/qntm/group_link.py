"""Public group locators, with no key material granting group access."""
import re
from urllib.parse import urlsplit, urlunsplit

from .cbor import marshal_canonical, unmarshal
from .ed25519 import is_valid_ed25519_public_key
from .identity import base64url_decode, base64url_encode

MAX_GROUP_LINK_BYTES = 4096


def _transport_url(value):
    if (not isinstance(value, str) or not re.match(r"https?://", value, re.I) or len(value) > 2048
            or re.search(r"[\s\x00-\x1f\x7f?#\\]", value)):
        raise ValueError("Invalid group relay URL")
    parsed = urlsplit(value)
    _ = parsed.port  # Reject invalid/out-of-range ports like the browser URL parser.
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid group relay URL")
    return value.rstrip("/")


def _validate(conversation_id, inviter_public_key, relay_url):
    if not isinstance(conversation_id, bytes) or len(conversation_id) != 16 or not is_valid_ed25519_public_key(inviter_public_key):
        raise ValueError("Invalid group locator identity")
    _transport_url(relay_url)


def create_group_link(conversation_id, inviter_public_key, relay_url, base_url="https://chat.corpo.llc"):
    _validate(conversation_id, inviter_public_key, relay_url)
    if not re.match(r"https?://", base_url, re.I) or re.search(r"[\s\x00-\x1f\x7f\\]", base_url):
        raise ValueError("Invalid group link URL")
    base = urlsplit(base_url)
    _ = base.port
    if base.scheme not in ("https", "http") or not base.hostname or base.username or base.password:
        raise ValueError("Invalid group link URL")
    wire = marshal_canonical({"v": 1, "type": "qntm.group", "conv_id": conversation_id,
                              "inviter_ik_pk": inviter_public_key, "relay_url": _transport_url(relay_url)})
    if len(wire) > MAX_GROUP_LINK_BYTES:
        raise ValueError("Group link exceeds size limit")
    return urlunsplit((base.scheme, base.netloc, base.path or "/", "", "group=" + base64url_encode(wire)))


def parse_group_link(value):
    """Parse without approving the contact, contacting a relay or granting access.

    Hosts confirm the link/contact and relay before fetching a sealed welcome.
    """
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("Invalid group link size")
    if not re.match(r"https?://", value, re.I) or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ValueError("Invalid group link")
    url = urlsplit(value)
    _ = url.port
    if (url.scheme not in ("https", "http") or not url.hostname or url.username or url.password
            or url.query or not re.fullmatch(r"group=[A-Za-z0-9_-]+", url.fragment)):
        raise ValueError("Invalid group link")
    encoded = url.fragment[6:]
    wire = base64url_decode(encoded)
    if not 0 < len(wire) <= MAX_GROUP_LINK_BYTES or base64url_encode(wire) != encoded:
        raise ValueError("Invalid group locator encoding")
    body = unmarshal(wire)
    if (not isinstance(body, dict) or set(body) != {"v", "type", "conv_id", "inviter_ik_pk", "relay_url"}
            or type(body["v"]) is not int or body["v"] != 1 or body["type"] != "qntm.group"
            or wire != marshal_canonical(body)):
        raise ValueError("Invalid group locator")
    _validate(body["conv_id"], body["inviter_ik_pk"], body["relay_url"])
    return {"conversation_id": body["conv_id"], "inviter_public_key": body["inviter_ik_pk"],
            "relay_url": _transport_url(body["relay_url"])}
