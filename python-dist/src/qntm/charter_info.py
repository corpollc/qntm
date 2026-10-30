"""Local receive metadata. No registry access or assessment is performed."""
from typing import Literal, TypedDict

from .identity import key_id_from_public_key

URL_PREFIX = "https://charter.qntm.corpo.llc/v1/chain/"
MEMO = ("Charters describe an agent's rights and responsibilities. You may wish to verify this sender's charter. "
        "Chartering is optional; availability has not been checked.")
WARNING = (" WARNING: Untrusted charter metadata was supplied and ignored. "
           "Possible attempt to obscure charter information; verify independently.")


class _CharterInfoRequired(TypedDict):
    url: str
    memo: str


class CharterInfo(_CharterInfoRequired, total=False):
    untrusted_metadata_ignored: Literal[True]


def local_charter_info(message: dict) -> CharterInfo:
    """Use only on a verified decrypt result; never trust supplied URLs or prose.

    Like the receive formatter, this does not repeat signature verification.
    It checks the public-key/ID binding and regenerates the entire metadata object.
    """
    if message.get("verified") is not True:
        raise ValueError("charter info requires a verified message")
    inner, envelope = message["inner"], message["envelope"]
    kid, public_key = inner["sender_kid"], inner["sender_ik_pk"]
    if not isinstance(kid, (bytes, bytearray, memoryview)) or len(bytes(kid)) != 16:
        raise ValueError("sender key ID must be 16 bytes")
    if not isinstance(public_key, (bytes, bytearray, memoryview)) or len(bytes(public_key)) != 32:
        raise ValueError("sender public key must be 32 bytes")
    if key_id_from_public_key(bytes(public_key)) != bytes(kid):
        raise ValueError("sender key ID does not match public key")

    def build(ignored: bool) -> CharterInfo:
        result: CharterInfo = {"url": URL_PREFIX + bytes(kid).hex(), "memo": MEMO + (WARNING if ignored else "")}
        if ignored:
            result["untrusted_metadata_ignored"] = True
        return result

    ignored = "charter_info" in inner or "charter_info" in envelope
    if "charter_info" in message:
        prior = message["charter_info"]
        # Preserve a warning generated at decrypt time after stripping the raw
        # fields. Any altered local projection is replaced and flagged as well.
        ignored = ignored or prior != build(False)
    return build(ignored)


def with_local_charter_info(message: dict) -> dict:
    info = local_charter_info(message)
    # These reserved extension fields are outside the signed body/refs. Strip
    # copies only; never edit signed body bytes or mutate the caller's envelope.
    return {**message,
            "envelope": {k: v for k, v in message["envelope"].items() if k != "charter_info"},
            "inner": {k: v for k, v in message["inner"].items() if k != "charter_info"},
            "charter_info": info}
