"""qntm - secure messaging protocol client library and CLI."""

__version__ = "0.4.2"

from .constants import (
    DEFAULT_SUITE,
    DEFAULT_TTL_SECONDS,
    SPEC_VERSION,
    PROTOCOL_VERSION,
)
from .crypto import (
    QSP1Suite,
    ed25519_private_key_to_x25519,
    ed25519_public_key_to_x25519,
)
from .identity import (
    base64url_decode,
    base64url_encode,
    generate_conversation_id,
    generate_identity,
    generate_message_id,
    key_id_from_public_key,
    key_id_to_string,
    public_key_to_string,
    validate_identity,
    verify_key_id,
)
from .invite import (
    add_participant,
    create_conversation,
    create_invite,
    derive_conversation_keys,
    invite_from_url,
    invite_to_token,
    validate_invite,
)
from .message import (
    create_message,
    decrypt_message,
    default_handshake_ttl,
    default_ttl,
    deserialize_envelope,
    serialize_envelope,
    validate_envelope,
    verify_message_signature,
)
from .cbor import marshal_canonical, unmarshal
from .group import (
    GroupState,
    apply_rekey,
    create_group_add_body,
    create_group_genesis_body,
    create_group_rekey_body,
    create_group_remove_body,
    create_rekey,
    parse_group_add_body,
    parse_group_genesis_body,
    parse_group_rekey_body,
    parse_group_remove_body,
    process_group_message,
)
from .gate import (
    GateClient,
    GateError,
    compute_payload_hash,
    hash_request,
    lookup_threshold,
    sign_approval,
    sign_request,
    verify_approval,
    verify_request,
)
