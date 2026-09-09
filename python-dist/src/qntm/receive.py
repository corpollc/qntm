"""Portable receive-event contract, independent of CLI storage and scheduling."""

import base64
from typing import Literal, TypedDict


class _ReceivedMessageRequired(TypedDict):
    conversation_id: str
    message_id: str
    sender_kid: str
    created_ts: int
    body_type: str
    verified: Literal[True]
    sequence: int


class ReceivedMessage(_ReceivedMessageRequired, total=False):
    unsafe_body: str
    unsafe_body_b64: str


class ReceiveEvent(TypedDict):
    version: Literal[1]
    event_id: str
    conversation_id: str
    sequence: int
    message: ReceivedMessage


def _id(value):
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(bytes(value)) != 16:
        raise ValueError("receive event IDs must be 16 bytes")
    return bytes(value).hex()


def _positive_integer(value):
    if type(value) is not int or not 0 < value <= 9007199254740991:
        raise ValueError("receive event sequence and timestamp must be positive safe integers")
    return value


def create_receive_event(message: dict, sequence: int) -> ReceiveEvent:
    """Normalize a decrypt_message result for an adapter.

    Call only after cryptographic verification; this formatter doesn't verify
    signatures again or make received content trusted. Binary bodies (including
    CBOR group events) remain raw bytes encoded as base64 if not valid UTF-8.
    """
    if message.get("verified") is not True:
        raise ValueError("receive events require a verified message")
    envelope, inner = message["envelope"], message["inner"]
    sequence = _positive_integer(sequence)
    conversation_id, message_id = _id(envelope["conv_id"]), _id(envelope["msg_id"])
    body = inner["body"]
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise ValueError("receive event body must be bytes")
    if not isinstance(inner["body_type"], str) or not inner["body_type"]:
        raise ValueError("receive event body type must be nonempty")
    received: ReceivedMessage = {
        "conversation_id": conversation_id, "message_id": message_id,
        "sender_kid": _id(inner["sender_kid"]), "created_ts": _positive_integer(envelope["created_ts"]),
        "body_type": inner["body_type"], "verified": True, "sequence": sequence,
    }
    try:
        received["unsafe_body"] = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        received["unsafe_body_b64"] = base64.b64encode(body).decode("ascii")
    return {"version": 1, "event_id": f"qntm:{conversation_id}:{message_id}",
            "conversation_id": conversation_id, "sequence": sequence, "message": received}
