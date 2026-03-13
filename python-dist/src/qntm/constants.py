"""QSP protocol constants."""

SPEC_VERSION = "QSP-v1.1"
PROTOCOL_VERSION = 1
DEFAULT_SUITE = "QSP-1"
MAX_GROUP_SIZE = 128
EPOCH_GRACE_PERIOD_SECONDS = 86400

PROTO_PREFIX = "qntm/qsp/v1"
INFO_ROOT = "qntm/qsp/v1/root"
INFO_AEAD = "qntm/qsp/v1/aead"
INFO_NONCE = "qntm/qsp/v1/nonce"
INFO_AEAD_V11 = "qntm/qsp/v1.1/aead"
INFO_NONCE_V11 = "qntm/qsp/v1.1/nonce"
INFO_WRAP_V11 = "qntm/qsp/v1.1/wrap"

DEFAULT_TTL_SECONDS = 30 * 86400  # 30 days
DEFAULT_HANDSHAKE_TTL_SECONDS = 7 * 86400  # 7 days
CLOCK_SKEW_SECONDS = 300  # 5 minutes
