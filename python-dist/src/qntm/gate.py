"""Gate: multisig threshold authorization for external API execution.

Provides Ed25519 request/approval signing, threshold rule matching,
recipes, secret sealing, and an HTTP client for the qntm-gate server.
"""

import hashlib
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote, urlencode, urlsplit

import httpx
import nacl.bindings

from .cbor import marshal_canonical
from .crypto import (
    QSP1Suite,
    ed25519_private_key_to_x25519,
    ed25519_public_key_to_x25519,
)

_suite = QSP1Suite()


# ---------------------------------------------------------------------------
# Message type constants (mirrors Go GateMessageType)
# ---------------------------------------------------------------------------

GATE_MESSAGE_REQUEST: str = "gate.request"
GATE_MESSAGE_APPROVAL: str = "gate.approval"
GATE_MESSAGE_EXECUTED: str = "gate.executed"
GATE_MESSAGE_PROMOTE: str = "gate.promote"
GATE_MESSAGE_SECRET: str = "gate.secret"
GATE_MESSAGE_CONFIG: str = "gate.config"
GATE_MESSAGE_DISAPPROVAL: str = "gate.disapproval"
GATE_MESSAGE_REVOKE: str = "gate.revoke"
GATE_MESSAGE_EXPIRED: str = "gate.expired"


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class ThresholdRule:
    service: str
    endpoint: str
    verb: str
    m: int


@dataclass
class Credential:
    id: str
    service: str
    value: str
    header_name: str
    header_value: str
    description: str = ""


# ---------------------------------------------------------------------------
# Recipe types (mirrors Go Recipe, RecipeParam)
# ---------------------------------------------------------------------------

@dataclass
class RecipeParam:
    name: str
    description: str
    required: bool
    type: str  # "string", "integer", "boolean"
    default: str = ""


@dataclass
class Recipe:
    name: str
    description: str
    service: str
    verb: str
    endpoint: str
    target_url: str
    risk_tier: str
    threshold: int
    params: Optional[str] = None  # JSON schema for parameters
    content_type: Optional[str] = None
    path_params: list[RecipeParam] = field(default_factory=list)
    query_params: list[RecipeParam] = field(default_factory=list)
    body_schema: Optional[str] = None  # JSON string of body schema
    body_example: Optional[str] = None


# ---------------------------------------------------------------------------
# Gateway payload types (PromotePayload, SecretPayload, etc.)
# ---------------------------------------------------------------------------

@dataclass
class PromotePayload:
    conv_id: str
    gateway_kid: str
    participants: dict[str, str]  # kid -> base64url public key
    rules: list[ThresholdRule]
    floor: int


@dataclass
class RevokePayload:
    secret_id: Optional[str] = None  # Revoke specific secret by ID
    service: Optional[str] = None  # Revoke all secrets for service


@dataclass
class SecretPayload:
    secret_id: str
    service: str
    header_name: str
    header_template: str  # e.g. "Bearer {value}"
    encrypted_blob: str  # base64-encoded NaCl box ciphertext
    sender_kid: str
    ttl: int = 0  # seconds until expiry; 0 means no expiry
    allowed_origins: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Service origin allowlists & canonicalization
# ---------------------------------------------------------------------------

BUILTIN_SERVICE_ORIGINS: dict[str, list[str]] = {
    "github": ["https://api.github.com"],
    "openai": ["https://api.openai.com"],
    "anthropic": ["https://api.anthropic.com"],
    "gemini": ["https://generativelanguage.googleapis.com"],
    "stripe": ["https://api.stripe.com"],
    "hackernews": ["https://hacker-news.firebaseio.com"],
    "httpbin": ["https://httpbin.org"],
    "dadjokes": ["https://icanhazdadjoke.com"],
    "trivia": ["https://opentdb.com"],
    "dogs": ["https://dog.ceo"],
    "fun": ["http://localhost:9090"],
}


def _is_disallowed_https_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_disallowed_https_ip(ip.ipv4_mapped)
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
        or not ip.is_global
    )


def canonicalize_origin(origin: str) -> str:
    """Validate and canonicalize an HTTP(S) origin string."""
    if not isinstance(origin, str) or not origin:
        raise ValueError("Origin must be a non-empty string")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in origin):
        raise ValueError(f"Invalid characters in origin: {origin!r}")
    if "\\" in origin or "?" in origin or "#" in origin:
        raise ValueError(f"Origin must not contain backslashes, query, or fragment: {origin!r}")

    parsed = urlsplit(origin)
    scheme = parsed.scheme.lower()
    if scheme not in ("https", "http") or not parsed.netloc:
        raise ValueError(f"Origin must use https:// (or loopback http://): {origin!r}")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise ValueError("Origin must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Origin must not contain a path, query, or fragment")
    if parsed.netloc.endswith(":"):
        raise ValueError("Invalid empty port in origin")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in origin: {origin!r}") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"Port out of range in origin: {origin!r}")

    hostname = parsed.hostname
    if not hostname or "%" in hostname or "/" in hostname:
        raise ValueError(f"Invalid hostname in origin: {origin!r}")

    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.split(".")
        if all(lbl.isdigit() or lbl.lower().startswith("0x") for lbl in labels if lbl):
            raise ValueError(f"Invalid numeric IP literal in origin: {origin!r}")
        if ":" in hostname or ".." in hostname or hostname.startswith(".") or hostname.endswith("."):
            raise ValueError(f"Invalid hostname in origin: {origin!r}")

    if ip_obj is not None:
        if scheme == "https" and _is_disallowed_https_ip(ip_obj):
            raise ValueError(f"Non-public IP literal not permitted for https:// origin: {origin!r}")
        check_host = ip_obj.compressed
        host_str = f"[{ip_obj.compressed}]" if isinstance(ip_obj, ipaddress.IPv6Address) else ip_obj.compressed
    else:
        check_host = hostname.lower()
        host_str = check_host

    if scheme == "http" and check_host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(f"Insecure http:// origin is only allowed for localhost, 127.0.0.1, or ::1: {origin!r}")

    default_port = 443 if scheme == "https" else 80
    netloc = host_str if (port is None or port == default_port) else f"{host_str}:{port}"
    return f"{scheme}://{netloc}"


def _lookup_recipe_catalog_origins(service_lower: str) -> Optional[list[str]]:
    catalog_path = os.environ.get("QNTM_RECIPE_CATALOG_PATH") or os.path.join(
        os.path.dirname(__file__), "recipes.json"
    )
    try:
        with open(catalog_path, "r", encoding="utf-8") as fh:
            catalog = json.load(fh)
    except (OSError, ValueError):
        return None
    profiles = catalog.get("profiles")
    if not isinstance(profiles, dict):
        return None
    for key, prof in profiles.items():
        if not isinstance(prof, dict):
            continue
        prof_service = str(prof.get("service", key)).lower()
        if key.lower() == service_lower or prof_service == service_lower:
            base_url = prof.get("base_url")
            if isinstance(base_url, str) and base_url:
                parsed = urlsplit(base_url)
                if parsed.scheme and parsed.netloc:
                    return [canonicalize_origin(f"{parsed.scheme}://{parsed.netloc}")]
    return None


def resolve_service_origins(
    service: str,
    explicit_origins: Optional[list[str]] = None,
) -> list[str]:
    """Resolve canonical allowed_origins (1..16) for a service and optional --origin overrides."""
    if not isinstance(service, str) or not service.strip():
        raise ValueError("Service name must be a non-empty string")
    s = service.strip()

    if explicit_origins:
        if not isinstance(explicit_origins, (list, tuple)) or len(explicit_origins) > 16:
            raise ValueError("allowed_origins must contain between 1 and 16 origins")
        resolved: list[str] = []
        for raw_origin in explicit_origins:
            canon = canonicalize_origin(raw_origin)
            if canon not in resolved:
                resolved.append(canon)
        if not (1 <= len(resolved) <= 16):
            raise ValueError("allowed_origins must contain between 1 and 16 origins")
        return resolved

    s_lower = s.lower()
    if s_lower.startswith(("https://", "http://")):
        return [canonicalize_origin(s)]

    catalog_origins = _lookup_recipe_catalog_origins(s_lower)
    if catalog_origins:
        return catalog_origins

    if s_lower in BUILTIN_SERVICE_ORIGINS:
        return list(BUILTIN_SERVICE_ORIGINS[s_lower])

    is_loopback = s_lower in ("localhost", "127.0.0.1", "[::1]") or s_lower.startswith(
        ("localhost:", "127.0.0.1:", "[::1]:")
    )
    if is_loopback:
        return [canonicalize_origin(f"http://{s}")]
    if "." in s:
        return [canonicalize_origin(f"https://{s}")]

    raise ValueError(
        f'Unknown service "{service}": specify an API hostname (e.g. api.example.com) or pass --origin'
    )


@dataclass
class ExpiredPayload:
    """Body of a gate.expired notification message.

    Sent when a credential's TTL has elapsed. The gateway can USE secrets
    but cannot CREATE or REFRESH them -- humans must re-provision.
    """

    secret_id: str
    service: str
    expired_at: str  # ISO 8601 / RFC3339 timestamp
    message: str  # Human-readable description


# ---------------------------------------------------------------------------
# GateConversationMessage (mirrors Go GateConversationMessage)
# ---------------------------------------------------------------------------

@dataclass
class GateConversationMessage:
    type: str
    conv_id: str
    request_id: str
    signer_kid: str
    signature: str
    # Request fields (only for gate.request)
    verb: Optional[str] = None
    target_endpoint: Optional[str] = None
    target_service: Optional[str] = None
    target_url: Optional[str] = None
    payload: Optional[Any] = None
    expires_at: Optional[str] = None
    executed_at: Optional[str] = None
    execution_status_code: Optional[int] = None
    eligible_signer_kids: Optional[list[str]] = None
    required_approvals: Optional[int] = None
    # Recipe fields (optional -- populated when request originates from a recipe)
    recipe_name: Optional[str] = None
    arguments: Optional[dict[str, str]] = None


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _gate_signable_map(
    conv_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
    eligible_signer_kids: list[str],
    required_approvals: int,
    gateway_kid: str | None = None,
) -> dict:
    """Build the canonical CBOR map for a gate request."""
    return {
        **({"gateway_kid": gateway_kid} if gateway_kid else {}),
        "conv_id": conv_id,
        "request_id": request_id,
        "verb": verb,
        "target_endpoint": target_endpoint,
        "target_service": target_service,
        "target_url": target_url,
        "expires_at_unix": expires_at_unix,
        "payload_hash": payload_hash,
        "eligible_signer_kids": eligible_signer_kids,
        "required_approvals": required_approvals,
    }


def _approval_signable_map(
    conv_id: str,
    request_id: str,
    request_hash: bytes,
) -> dict:
    """Build the canonical CBOR map for an approval."""
    return {
        "conv_id": conv_id,
        "request_id": request_id,
        "request_hash": request_hash,
    }


def compute_payload_hash(payload: Any) -> bytes:
    """SHA-256 of JSON-encoded payload, or empty bytes if None."""
    if payload is None:
        return hashlib.sha256(b"").digest()
    data = json.dumps(payload, separators=(",", ":")).encode()
    return hashlib.sha256(data).digest()


def sign_request(
    private_key: bytes,
    *,
    conv_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
    eligible_signer_kids: list[str],
    required_approvals: int,
    gateway_kid: str | None = None,
) -> bytes:
    """Sign a gate request. Returns 64-byte Ed25519 signature."""
    m = _gate_signable_map(
        conv_id, request_id, verb, target_endpoint,
        target_service, target_url, expires_at_unix, payload_hash,
        eligible_signer_kids, required_approvals, gateway_kid,
    )
    tbs = marshal_canonical(m)
    return _suite.sign(private_key, tbs)


def verify_request(
    public_key: bytes,
    signature: bytes,
    *,
    conv_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
    eligible_signer_kids: list[str],
    required_approvals: int,
    gateway_kid: str | None = None,
) -> bool:
    """Verify a gate request signature."""
    m = _gate_signable_map(
        conv_id, request_id, verb, target_endpoint,
        target_service, target_url, expires_at_unix, payload_hash,
        eligible_signer_kids, required_approvals, gateway_kid,
    )
    tbs = marshal_canonical(m)
    return _suite.verify(public_key, tbs, signature)


def hash_request(
    *,
    conv_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
    eligible_signer_kids: list[str],
    required_approvals: int,
    gateway_kid: str | None = None,
) -> bytes:
    """SHA-256 of the CBOR-encoded GateSignable."""
    m = _gate_signable_map(
        conv_id, request_id, verb, target_endpoint,
        target_service, target_url, expires_at_unix, payload_hash,
        eligible_signer_kids, required_approvals, gateway_kid,
    )
    tbs = marshal_canonical(m)
    return hashlib.sha256(tbs).digest()


def sign_approval(
    private_key: bytes,
    *,
    conv_id: str,
    request_id: str,
    request_hash: bytes,
) -> bytes:
    """Sign an approval. Returns 64-byte Ed25519 signature."""
    m = _approval_signable_map(conv_id, request_id, request_hash)
    tbs = marshal_canonical(m)
    return _suite.sign(private_key, tbs)


def verify_approval(
    public_key: bytes,
    signature: bytes,
    *,
    conv_id: str,
    request_id: str,
    request_hash: bytes,
) -> bool:
    """Verify an approval signature."""
    m = _approval_signable_map(conv_id, request_id, request_hash)
    tbs = marshal_canonical(m)
    return _suite.verify(public_key, tbs, signature)


# ---------------------------------------------------------------------------
# Threshold matching (mirrors Go LookupThreshold)
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\{([^}/]+)\}")


def _endpoint_matches(pattern: str, endpoint: str) -> tuple[bool, tuple[int, int]]:
    """Return (matched, specificity_tuple) where exact > template, then literal segment count."""
    if pattern == endpoint:
        return True, (1, len(endpoint.split("/")))
    if "{" not in pattern or "}" not in pattern:
        return False, (0, 0)
    pat_segs = pattern.split("/")
    end_segs = endpoint.split("/")
    if len(pat_segs) != len(end_segs):
        return False, (0, 0)
    literal_segs = 0
    for p_seg, e_seg in zip(pat_segs, end_segs):
        if e_seg in (".", ".."):
            return False, (0, 0)
        if p_seg == e_seg:
            literal_segs += 1
            continue
        if "{" not in p_seg or not e_seg:
            return False, (0, 0)
        parts = _PLACEHOLDER_RE.split(p_seg)
        # Odd indices are placeholder names; even indices are literal substrings.
        if len(parts) < 3:
            return False, (0, 0)
        regex_parts = ["^"]
        for idx, token in enumerate(parts):
            if idx % 2 == 0:
                regex_parts.append(re.escape(token))
            else:
                regex_parts.append("([^/?#]+)")
        regex_parts.append("$")
        m = re.match("".join(regex_parts), e_seg)
        if not m or any(val in ("", ".", "..") for val in m.groups()):
            return False, (0, 0)
    return True, (0, literal_segs)


def lookup_threshold(
    rules: list[ThresholdRule],
    service: str,
    endpoint: str,
    verb: str,
) -> Optional[ThresholdRule]:
    """Match all fields, then prefer service/endpoint/verb specificity; first tie wins."""
    best: Optional[ThresholdRule] = None
    best_key = (-1, (-1, -1))
    verb_upper = verb.upper()

    for rule in rules:
        score = 0
        endpoint_spec = (1, 0)
        if rule.service not in ("*", ""):
            if rule.service != service:
                continue
            score += 4
        if rule.endpoint not in ("*", ""):
            matched, endpoint_spec = _endpoint_matches(rule.endpoint, endpoint)
            if not matched:
                continue
            score += 2
        if rule.verb not in ("*", ""):
            if rule.verb.upper() != verb_upper:
                continue
            score += 1

        candidate_key = (score, endpoint_spec)
        if candidate_key > best_key:
            best_key = candidate_key
            best = rule

    return best


# ---------------------------------------------------------------------------
# Recipe resolution (mirrors Go ResolveRecipe)
# ---------------------------------------------------------------------------


def resolve_recipe(
    recipe: Recipe,
    args: Optional[dict[str, str]],
) -> tuple[str, str, Optional[bytes]]:
    """Resolve a recipe by substituting parameters.

    Returns (endpoint, target_url, body_bytes_or_None).
    Raises ValueError on missing or unsafe parameters.
    """
    if args is None:
        args = {}
    # Make a mutable copy so we can inject defaults
    args = dict(args)

    # Validate required path params
    for p in recipe.path_params:
        if p.required and p.name not in args:
            if p.default:
                args[p.name] = p.default
            else:
                raise ValueError(f"missing required path parameter {p.name!r}")

    # Validate required query params
    for p in recipe.query_params:
        if p.required and p.name not in args:
            if p.default:
                args[p.name] = p.default
            else:
                raise ValueError(f"missing required query parameter {p.name!r}")

    # Substitute {param} placeholders with strict URL segment encoding
    def _sub(s: str) -> str:
        def _repl(m: re.Match) -> str:
            key = m.group(1)
            if key not in args:
                return m.group(0)
            raw_val = str(args[key])
            if not raw_val or raw_val in (".", ".."):
                raise ValueError(f"invalid path parameter {key!r}: {raw_val!r}")
            encoded = quote(raw_val, safe="")
            if not encoded or encoded in (".", ".."):
                raise ValueError(f"invalid path parameter {key!r}: {raw_val!r}")
            return encoded
        return _PLACEHOLDER_RE.sub(_repl, s)

    endpoint = _sub(recipe.endpoint)
    if any(seg in (".", "..") for seg in endpoint.split("/")):
        raise ValueError(f"resolved endpoint contains dot segment: {endpoint!r}")
    target_url = _sub(recipe.target_url)

    # Append URL-encoded query params to target URL
    query_pairs: list[tuple[str, str]] = []
    for p in recipe.query_params:
        if p.name in args:
            query_pairs.append((p.name, str(args[p.name])))
        elif p.default:
            query_pairs.append((p.name, str(p.default)))
    if query_pairs:
        sep = "&" if "?" in target_url else "?"
        target_url = target_url + sep + urlencode(query_pairs, quote_via=quote)

    # Build body from body_schema + args for POST/PUT/PATCH
    body: Optional[bytes] = None
    verb = recipe.verb.upper()
    if verb in ("POST", "PUT", "PATCH") and recipe.body_schema:
        schema = json.loads(recipe.body_schema)

        # Discover field names from JSON Schema "properties"
        field_names: list[str] = []
        if "properties" in schema:
            field_names = list(schema["properties"].keys())

        # Fall back to flat schema keys
        if not field_names:
            field_names = [
                k for k in schema
                if k not in ("type", "properties", "required")
            ]

        # Build body object from args matching schema fields
        body_map: dict[str, Any] = {}
        for name in field_names:
            if name in args:
                body_map[name] = args[name]

        if body_map:
            body = json.dumps(body_map, separators=(",", ":")).encode()

        # Validate required body params
        if "required" in schema:
            for name in schema["required"]:
                if name not in args:
                    raise ValueError(f"missing required body parameter {name!r}")

    return endpoint, target_url, body


# ---------------------------------------------------------------------------
# NaCl box secret sealing (mirrors Go SealSecret / OpenSecret)
# ---------------------------------------------------------------------------

# NaCl box overhead: 16 bytes Poly1305 MAC
_NACL_BOX_NONCE_SIZE = 24
_NACL_BOX_MAC_SIZE = 16


def seal_secret(
    sender_private_key: bytes,
    gateway_public_key: bytes,
    plaintext: bytes,
) -> bytes:
    """Encrypt a secret to the gateway using NaCl box (X25519-XSalsa20-Poly1305).

    Ed25519 keys are converted to X25519 for the DH exchange.
    Returns nonce (24 bytes) || ciphertext.
    """
    sender_x25519 = ed25519_private_key_to_x25519(sender_private_key)
    gateway_x25519 = ed25519_public_key_to_x25519(gateway_public_key)

    nonce = os.urandom(_NACL_BOX_NONCE_SIZE)

    ciphertext = nacl.bindings.crypto_box(
        plaintext, nonce, gateway_x25519, sender_x25519
    )

    return nonce + ciphertext


def open_secret(
    gateway_private_key: bytes,
    sender_public_key: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypt a secret sealed by seal_secret.

    Raises ValueError if ciphertext is too short.
    Raises nacl.exceptions.CryptoError on authentication failure.
    """
    min_len = _NACL_BOX_NONCE_SIZE + _NACL_BOX_MAC_SIZE
    if len(ciphertext) < min_len:
        raise ValueError(
            f"ciphertext too short: {len(ciphertext)} bytes, need at least {min_len}"
        )

    gateway_x25519 = ed25519_private_key_to_x25519(gateway_private_key)
    sender_x25519 = ed25519_public_key_to_x25519(sender_public_key)

    nonce = ciphertext[:_NACL_BOX_NONCE_SIZE]
    encrypted = ciphertext[_NACL_BOX_NONCE_SIZE:]

    return nacl.bindings.crypto_box_open(
        encrypted, nonce, sender_x25519, gateway_x25519
    )


# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------

class GateError(Exception):
    """Error from the gate API."""

    def __init__(self, status: int, body: str):
        super().__init__(f"Gate API error {status}: {body}")
        self.status = status
        self.body = body


class GateClient:
    """HTTP client for the qntm-gate server."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=30)

    def _check(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise GateError(resp.status_code, resp.text)

    def _post(self, path: str, body: dict) -> dict:
        resp = self._client.post(f"{self.base_url}{path}", json=body)
        self._check(resp)
        return resp.json()

    def create_invitation(self, inviter_public_key: str, invitation_id: str) -> dict:
        return self._post("/v1/invitations", {"inviter_public_key": inviter_public_key, "invitation_id": invitation_id})

    def promote(self, request: dict) -> dict:
        """Deliver sealed access material. Activation requires verified gate.accept in chat."""
        return self._post("/v1/promote", request)

    def health(self) -> dict:
        resp = self._client.get(f"{self.base_url}/health")
        self._check(resp)
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
