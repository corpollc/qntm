"""Opt-in experimental Charter Registry v0.2. Separate from QSP messaging.

Signatures establish authorship and authority, not compliance. Registrar pins
must come from trusted configuration. Independent witnesses are not included.
"""

from .json import (CharterError, canonicalize_charter_json, charter_json_bytes,
                   parse_charter_json)
from .core import (CHARTER_DRAFT_VERSION, CHARTER_GENESIS_HASH, CharterAgentRight,
                   CharterGovernance, CharterKey, CharterRecord, CharterSignature,
                   CharterSignedBody, CharterStatement, CharterStatementType,
                   charter_agent_id, charter_governance_commitment, charter_key,
                   charter_statement_hash, create_charter, create_charter_statement,
                   parse_charter_statement, replay_charter_chain, sign_charter_statement)
from .proofs import (CharterTrust, audit_charter_snapshot, verify_charter_chain_response,
                     verify_charter_consistency, verify_charter_heads,
                     verify_charter_inclusion, verify_charter_receipt)
from .client import CharterChainResult, CharterRegistryClient, CharterRegistryError

__all__ = [
    "CHARTER_DRAFT_VERSION", "CHARTER_GENESIS_HASH", "CharterError", "CharterAgentRight",
    "CharterGovernance", "CharterKey", "CharterRecord", "CharterSignature", "CharterSignedBody",
    "CharterStatement", "CharterStatementType", "CharterTrust", "CharterChainResult",
    "CharterRegistryClient", "CharterRegistryError", "canonicalize_charter_json",
    "charter_json_bytes", "parse_charter_json", "charter_agent_id",
    "charter_governance_commitment", "charter_key", "charter_statement_hash", "create_charter",
    "create_charter_statement", "parse_charter_statement", "replay_charter_chain",
    "sign_charter_statement", "audit_charter_snapshot", "verify_charter_chain_response",
    "verify_charter_consistency", "verify_charter_heads", "verify_charter_inclusion", "verify_charter_receipt",
]
