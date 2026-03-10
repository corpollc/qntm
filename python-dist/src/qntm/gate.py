"""Gate: multisig threshold authorization for external API execution.

Provides Ed25519 request/approval signing, threshold rule matching,
and an HTTP client for the qntm-gate server.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .cbor import marshal_canonical
from .crypto import QSP1Suite

_suite = QSP1Suite()


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
