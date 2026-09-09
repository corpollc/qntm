"""Governance message signing helpers for promoted gateway conversations."""

import time
import uuid as _uuid
from datetime import datetime
import cbor2

from .cbor import marshal_canonical
from .crypto import QSP1Suite
from .identity import base64url_encode, key_id_from_public_key

_suite = QSP1Suite()

GOV_MESSAGE_PROPOSE = "gov.propose"
GOV_MESSAGE_APPROVE = "gov.approve"
GOV_MESSAGE_DISAPPROVE = "gov.disapprove"
GOV_MESSAGE_APPLIED = "gov.applied"


def _proposal_signable_map(
    *,
    conv_id: str,
    proposal_id: str,
    proposal_type: str,
    proposed_floor: int | None,
    proposed_rules,
    proposed_members,
    removed_member_kids,
    eligible_signer_kids: list[str],
    required_approvals: int,
    expires_at_unix: int,
    gateway_kid: str | None = None,
) -> dict:
    return {
        **({"gateway_kid": gateway_kid} if gateway_kid else {}),
        "conv_id": conv_id,
        "proposal_id": proposal_id,
        "proposal_type": proposal_type,
        "proposed_floor": proposed_floor,
        "proposed_rules": proposed_rules,
        "proposed_members": proposed_members,
        "removed_member_kids": removed_member_kids,
        "eligible_signer_kids": eligible_signer_kids,
        "required_approvals": required_approvals,
        "expires_at_unix": expires_at_unix,
    }


def sign_proposal(
    private_key: bytes,
    *,
    conv_id: str,
    proposal_id: str,
    proposal_type: str,
    proposed_floor: int | None,
    proposed_rules,
    proposed_members,
    removed_member_kids,
    eligible_signer_kids: list[str],
    required_approvals: int,
    expires_at_unix: int,
    gateway_kid: str | None = None,
) -> bytes:
    signable = _proposal_signable_map(
        conv_id=conv_id,
        proposal_id=proposal_id,
        proposal_type=proposal_type,
        proposed_floor=proposed_floor,
        proposed_rules=proposed_rules,
        proposed_members=proposed_members,
        removed_member_kids=removed_member_kids,
        eligible_signer_kids=eligible_signer_kids,
        required_approvals=required_approvals,
        expires_at_unix=expires_at_unix,
        gateway_kid=gateway_kid,
    )
    return _suite.sign(private_key, marshal_canonical(signable))


def hash_proposal(
    *,
    conv_id: str,
    proposal_id: str,
    proposal_type: str,
    proposed_floor: int | None,
    proposed_rules,
    proposed_members,
    removed_member_kids,
    eligible_signer_kids: list[str],
    required_approvals: int,
    expires_at_unix: int,
    gateway_kid: str | None = None,
) -> bytes:
    signable = _proposal_signable_map(
        conv_id=conv_id,
        proposal_id=proposal_id,
        proposal_type=proposal_type,
        proposed_floor=proposed_floor,
        proposed_rules=proposed_rules,
        proposed_members=proposed_members,
        removed_member_kids=removed_member_kids,
        eligible_signer_kids=eligible_signer_kids,
        required_approvals=required_approvals,
        expires_at_unix=expires_at_unix,
        gateway_kid=gateway_kid,
    )
    return _suite.hash(marshal_canonical(signable))


def hash_proposal_body(body: dict) -> bytes:
    """Hash a received JSON proposal without changing absent fields into null.

    Existing TypeScript signables encode absent optional branches as CBOR
    undefined, while Python's emitted null branches encode as CBOR null.
    """
    return hash_proposal(
        gateway_kid=body.get("gateway_kid"),
        conv_id=body["conv_id"], proposal_id=body["proposal_id"], proposal_type=body["proposal_type"],
        proposed_floor=body.get("proposed_floor", cbor2.undefined),
        proposed_rules=body.get("proposed_rules", cbor2.undefined),
        proposed_members=body.get("proposed_members", cbor2.undefined),
        removed_member_kids=body.get("removed_member_kids", cbor2.undefined),
        eligible_signer_kids=body["eligible_signer_kids"], required_approvals=body["required_approvals"],
        expires_at_unix=int(datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00")).timestamp()),
    )


def sign_gov_approval(
    private_key: bytes,
    *,
    conv_id: str,
    proposal_id: str,
    proposal_hash: bytes,
) -> bytes:
    approval = {
        "conv_id": conv_id,
        "proposal_id": proposal_id,
        "proposal_hash": proposal_hash,
    }
    return _suite.sign(private_key, marshal_canonical(approval))


def create_proposal_body(
    identity: dict,
    *,
    conv_id: str,
    proposal_type: str,
    eligible_signer_kids: list[str],
    required_approvals: int,
    expires_in_seconds: int = 3600,
    proposed_floor: int | None = None,
    proposed_rules=None,
    proposed_members=None,
    removed_member_kids=None,
    gateway_kid: str | None = None,
) -> dict:
    proposal_id = str(_uuid.uuid4())
    expires_at_unix = int(time.time()) + expires_in_seconds
    signature = sign_proposal(
        identity["privateKey"],
        conv_id=conv_id,
        proposal_id=proposal_id,
        proposal_type=proposal_type,
        proposed_floor=proposed_floor,
        proposed_rules=proposed_rules,
        proposed_members=proposed_members,
        removed_member_kids=removed_member_kids,
        eligible_signer_kids=eligible_signer_kids,
        required_approvals=required_approvals,
        expires_at_unix=expires_at_unix,
        gateway_kid=gateway_kid,
    )
    return {
        "type": GOV_MESSAGE_PROPOSE,
        **({"gateway_kid": gateway_kid} if gateway_kid else {}),
        "conv_id": conv_id,
        "proposal_id": proposal_id,
        "proposal_type": proposal_type,
        "proposed_floor": proposed_floor,
        "proposed_rules": proposed_rules,
        "proposed_members": proposed_members,
        "removed_member_kids": removed_member_kids,
        "eligible_signer_kids": eligible_signer_kids,
        "required_approvals": required_approvals,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at_unix)),
        "signer_kid": base64url_encode(key_id_from_public_key(identity["publicKey"])),
        "signature": base64url_encode(signature),
    }
