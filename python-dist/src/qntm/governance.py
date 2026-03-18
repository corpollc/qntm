"""Governance message signing helpers for promoted gateway conversations."""

import time
import uuid as _uuid

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
) -> dict:
    return {
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
    )
    return _suite.hash(marshal_canonical(signable))


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
    )
    return {
        "type": GOV_MESSAGE_PROPOSE,
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
