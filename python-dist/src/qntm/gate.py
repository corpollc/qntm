"""Gate: multisig threshold authorization for external API execution.

Provides Ed25519 request/approval signing, threshold rule matching,
recipes, secret sealing, and an HTTP client for the qntm-gate server.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

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
    n: int = 0


@dataclass
class Credential:
    id: str
    service: str
    value: str
    header_name: str
    header_value: str
    description: str = ""


@dataclass
class Signer:
    kid: str
    public_key: str  # base64url
    label: str


@dataclass
class Org:
    id: str
    signers: list[Signer]
    rules: list[ThresholdRule]
    credentials: Optional[dict[str, Credential]] = None


@dataclass
class ScanResult:
    found: bool
    threshold_met: bool
    expired: bool
    signer_kids: list[str]
    threshold: int
    status: str  # pending | approved | executed | expired
    request: Optional[dict] = None


@dataclass
class ExecutionResult:
    status_code: int
    content_type: Optional[str] = None
    content_length: int = 0


@dataclass
class ExecuteResult:
    org_id: str
    request_id: str
    verb: str
    target_endpoint: str
    target_service: str
    status: str
    signature_count: int
    signer_kids: list[str]
    threshold: int
    expires_at: str
    execution_result: Optional[ExecutionResult] = None


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
# Gateway payload types (mirrors Go PromotePayload, ConfigPayload, SecretPayload)
# ---------------------------------------------------------------------------

@dataclass
class PromotePayload:
    org_id: str
    signers: list[Signer]
    rules: list[ThresholdRule]


@dataclass
class ConfigPayload:
    rules: list[ThresholdRule]


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
    org_id: str
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
    # Recipe fields (optional -- populated when request originates from a recipe)
    recipe_name: Optional[str] = None
    arguments: Optional[dict[str, str]] = None


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _gate_signable_map(
    org_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
) -> dict:
    """Build the canonical CBOR map for a gate request."""
    return {
        "org_id": org_id,
        "request_id": request_id,
        "verb": verb,
        "target_endpoint": target_endpoint,
        "target_service": target_service,
        "target_url": target_url,
        "expires_at_unix": expires_at_unix,
        "payload_hash": payload_hash,
    }


def _approval_signable_map(
    org_id: str,
    request_id: str,
    request_hash: bytes,
) -> dict:
    """Build the canonical CBOR map for an approval."""
    return {
        "org_id": org_id,
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
    org_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
) -> bytes:
    """Sign a gate request. Returns 64-byte Ed25519 signature."""
    m = _gate_signable_map(
        org_id, request_id, verb, target_endpoint,
        target_service, target_url, expires_at_unix, payload_hash,
    )
    tbs = marshal_canonical(m)
    return _suite.sign(private_key, tbs)


def verify_request(
    public_key: bytes,
    signature: bytes,
    *,
    org_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
) -> bool:
    """Verify a gate request signature."""
    m = _gate_signable_map(
        org_id, request_id, verb, target_endpoint,
        target_service, target_url, expires_at_unix, payload_hash,
    )
    tbs = marshal_canonical(m)
    return _suite.verify(public_key, tbs, signature)


def hash_request(
    *,
    org_id: str,
    request_id: str,
    verb: str,
    target_endpoint: str,
    target_service: str,
    target_url: str,
    expires_at_unix: int,
    payload_hash: bytes,
) -> bytes:
    """SHA-256 of the CBOR-encoded GateSignable."""
    m = _gate_signable_map(
        org_id, request_id, verb, target_endpoint,
        target_service, target_url, expires_at_unix, payload_hash,
    )
    tbs = marshal_canonical(m)
    return hashlib.sha256(tbs).digest()


def sign_approval(
    private_key: bytes,
    *,
    org_id: str,
    request_id: str,
    request_hash: bytes,
) -> bytes:
    """Sign an approval. Returns 64-byte Ed25519 signature."""
    m = _approval_signable_map(org_id, request_id, request_hash)
    tbs = marshal_canonical(m)
    return _suite.sign(private_key, tbs)


def verify_approval(
    public_key: bytes,
    signature: bytes,
    *,
    org_id: str,
    request_id: str,
    request_hash: bytes,
) -> bool:
    """Verify an approval signature."""
    m = _approval_signable_map(org_id, request_id, request_hash)
    tbs = marshal_canonical(m)
    return _suite.verify(public_key, tbs, signature)


# ---------------------------------------------------------------------------
# Threshold matching (mirrors Go LookupThreshold)
# ---------------------------------------------------------------------------

def lookup_threshold(
    rules: list[ThresholdRule],
    service: str,
    endpoint: str,
    verb: str,
) -> Optional[ThresholdRule]:
    """Find the best matching threshold rule by priority scoring."""
    best: Optional[ThresholdRule] = None
    best_score = -1

    for rule in rules:
        score = 0
        if rule.service != "*":
            if rule.service != service:
                continue
            score += 4
        if rule.endpoint != "*":
            if rule.endpoint != endpoint:
                continue
            score += 2
        if rule.verb != "*":
            if rule.verb != verb:
                continue
            score += 1

        if score > best_score:
            best_score = score
            best = rule

    return best


# ---------------------------------------------------------------------------
# Recipe resolution (mirrors Go ResolveRecipe)
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\{([^}]+)\}")


def resolve_recipe(
    recipe: Recipe,
    args: Optional[dict[str, str]],
) -> tuple[str, str, Optional[bytes]]:
    """Resolve a recipe by substituting parameters.

    Returns (endpoint, target_url, body_bytes_or_None).
    Raises ValueError on missing required parameters.
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

    # Substitute {param} placeholders
    def _sub(s: str) -> str:
        def _repl(m: re.Match) -> str:
            key = m.group(1)
            return args.get(key, m.group(0))
        return _PLACEHOLDER_RE.sub(_repl, s)

    endpoint = _sub(recipe.endpoint)
    target_url = _sub(recipe.target_url)

    # Append query params to target URL
    query_parts: list[str] = []
    for p in recipe.query_params:
        if p.name in args:
            query_parts.append(f"{p.name}={args[p.name]}")
        elif p.default:
            query_parts.append(f"{p.name}={p.default}")
    if query_parts:
        sep = "&" if "?" in target_url else "?"
        target_url = target_url + sep + "&".join(query_parts)

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

    def __init__(self, base_url: str, admin_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token
        self._client = httpx.Client(timeout=30)

    def _headers(self, with_auth: bool = False) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if with_auth and self.admin_token:
            h["Authorization"] = f"Bearer {self.admin_token}"
        return h

    def _check(self, resp: httpx.Response) -> None:
        if resp.status_code >= 400:
            raise GateError(resp.status_code, resp.text)

    def create_org(
        self,
        org_id: str,
        signers: list[dict],
        rules: list[dict],
    ) -> dict:
        resp = self._client.post(
            f"{self.base_url}/v1/orgs",
            headers=self._headers(with_auth=True),
            json={"id": org_id, "signers": signers, "rules": rules},
        )
        self._check(resp)
        return resp.json()

    def get_org(self, org_id: str) -> dict:
        resp = self._client.get(
            f"{self.base_url}/v1/orgs/{org_id}",
            headers=self._headers(with_auth=True),
        )
        self._check(resp)
        return resp.json()

    def add_credential(self, org_id: str, credential: dict) -> None:
        resp = self._client.post(
            f"{self.base_url}/v1/orgs/{org_id}/credentials",
            headers=self._headers(with_auth=True),
            json=credential,
        )
        self._check(resp)

    def submit_message(self, org_id: str, message: dict) -> dict:
        resp = self._client.post(
            f"{self.base_url}/v1/orgs/{org_id}/messages",
            headers=self._headers(),
            json=message,
        )
        self._check(resp)
        return resp.json()

    def scan_request(self, org_id: str, request_id: str) -> dict:
        resp = self._client.get(
            f"{self.base_url}/v1/orgs/{org_id}/scan/{request_id}",
            headers=self._headers(),
        )
        self._check(resp)
        return resp.json()

    def execute_request(self, org_id: str, request_id: str) -> dict:
        resp = self._client.post(
            f"{self.base_url}/v1/orgs/{org_id}/execute/{request_id}",
            headers=self._headers(with_auth=True),
        )
        self._check(resp)
        return resp.json()

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
