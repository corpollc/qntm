"""Entity verification via Corpo API.

Verifies that an agent's cryptographic identity is bound to a legal entity.
Part of the Agent Identity Working Group interop surface.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
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
    url = f"{api_base}/entities/{entity_id}/verify"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
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
    api_base: str = CORPO_API_BASE,
) -> tuple[bool, Optional[EntityVerification]]:
    """Full verification chain: DID → key → sender match → entity.

    Args:
        sender_key_id: 16-byte sender key ID from the QSP-1 envelope.
        did: DID URI from the envelope (optional).
        entity_id: Entity ID to verify against.
        resolve_did_fn: Callable(did_uri) → bytes(32) Ed25519 public key.
            If None, DID verification is skipped (entity-only check).
        api_base: Base URL for the Corpo API.

    Returns:
        Tuple of (verified: bool, entity: EntityVerification or None).
    """
    from .identity import key_id_from_public_key

    # Step 1: If DID provided and resolver available, verify key matches sender
    if did and resolve_did_fn:
        try:
            resolved_key = resolve_did_fn(did)
            computed_kid = key_id_from_public_key(resolved_key)
            if computed_kid != sender_key_id:
                return False, None
        except Exception:
            return False, None

    # Step 2: Verify entity
    try:
        entity = verify_entity(entity_id, api_base=api_base)
        return entity.is_active, entity
    except EntityVerificationError:
        return False, None
