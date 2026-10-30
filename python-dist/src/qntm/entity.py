"""Entity verification via Corpo API.

Verifies that an agent's cryptographic identity is bound to a legal entity.
Part of the Agent Identity Working Group interop surface.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from urllib.parse import quote
from ._identity_http import read_identity_json
from dataclasses import dataclass
from typing import Optional


CORPO_API_BASE = "https://api.corpo.llc/api/v1"


@dataclass
class EntityVerification:
    """Result of an entity verification check."""

    entity_id: str
    name: str
    status: str
    entity_type: str
    authority_ceiling: list[str]
    verified_at: str
    verified: bool

    @property
    def is_active(self) -> bool:
        return self.status == "active"


class EntityVerificationError(Exception):
    """Raised when entity verification fails."""

    pass


def verify_entity(
    entity_id: str,
    *,
    api_base: str = CORPO_API_BASE,
    timeout: float = 10.0,
) -> EntityVerification:
    """Verify a legal entity via the Corpo API.

    Args:
        entity_id: The entity identifier to verify.
        api_base: Base URL for the Corpo API (default: production).
        timeout: HTTP request timeout in seconds.

    Returns:
        EntityVerification with the entity's status and metadata.

    Raises:
        EntityVerificationError: If the entity is not found or the API fails.
    """
    url = f"{api_base.rstrip('/')}/entities/{quote(entity_id, safe='')}/verify"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        data = read_identity_json(req, timeout=timeout)
        if data.get("entity_id") != entity_id:
            raise ValueError("entity identifier mismatch")
        if not all(isinstance(data.get(key), str) for key in ("name", "status", "entity_type")):
            raise ValueError("invalid entity response")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise EntityVerificationError(
                f"Entity not found: {entity_id}"
            ) from e
        if e.code == 410:
            raise EntityVerificationError(
                f"Entity dissolved: {entity_id}"
            ) from e
        raise EntityVerificationError(
            f"API error {e.code}: {e.reason}"
        ) from e
    except urllib.error.URLError as e:
        raise EntityVerificationError(
            f"Cannot reach Corpo API: {e.reason}"
        ) from e
    except (ValueError, OSError) as e:
        raise EntityVerificationError(f"Invalid entity response: {e}") from e

    return EntityVerification(
        entity_id=data["entity_id"],
        name=data["name"],
        status=data["status"],
        entity_type=data["entity_type"],
        authority_ceiling=data.get("authority_ceiling", []),
        verified_at=data.get("verified_at", ""),
        verified=data["status"] == "active",
    )


def verify_sender_entity(
    sender_key_id: bytes,
    did: Optional[str],
    entity_id: str,
    *,
    resolve_did_fn=None,
    verify_binding_fn=None,
    api_base: str = CORPO_API_BASE,
) -> tuple[bool, Optional[EntityVerification]]:
    """Full verification chain: DID → key → sender match → entity.

    Args:
        sender_key_id: 16-byte sender key ID from the QSP-1 envelope.
        did: DID URI from the envelope (optional).
        entity_id: Entity ID to verify against.
        resolve_did_fn: Callable(did_uri) → bytes(32) Ed25519 public key.
            Required for sender verification.
        verify_binding_fn: Trusted local Callable(did, public_key, entity) → bool
            that verifies the DID/key is authorized by this entity. Neither a
            sender-supplied entity ID nor an active entity proves this binding.
            Missing binding verification fails closed. Use verify_entity for a
            standalone entity-status lookup.
        api_base: Base URL for the Corpo API.

    Returns:
        Tuple of (verified: bool, entity: EntityVerification or None).
    """
    from .identity import key_id_from_public_key

    if not did or not resolve_did_fn or not verify_binding_fn:
        return False, None
    try:
        resolved_key = resolve_did_fn(did)
        if len(resolved_key) != 32 or key_id_from_public_key(resolved_key) != sender_key_id:
            return False, None
    except Exception:
        return False, None

    # Step 2: Verify entity
    try:
        entity = verify_entity(entity_id, api_base=api_base)
        if not entity.is_active or verify_binding_fn(did, resolved_key, entity) is not True:
            return False, None
        entity.verified = True
        return True, entity
    except Exception:
        return False, None
