"""Tests for conversation ID normalization and lookup.

The conversation ID can be stored in multiple formats across clients:
  - hex string (Python CLI, TS client)
  - list of ints (legacy Go CLI)
  - raw bytes

_find_conversation must handle all of these.
"""

import pytest
from qntm.cli import _normalize_conv_id, _find_conversation


# ---- _normalize_conv_id ----


def test_normalize_hex_string():
    assert _normalize_conv_id("ED381FF8032012D0") == "ed381ff8032012d0"


def test_normalize_hex_string_lowercase():
    assert _normalize_conv_id("abcdef0123456789") == "abcdef0123456789"


def test_normalize_byte_list():
    """Legacy Go CLI stores conv IDs as JSON arrays of ints."""
    byte_list = [0xED, 0x38, 0x1F, 0xF8, 0x03, 0x20, 0x12, 0xD0]
    assert _normalize_conv_id(byte_list) == "ed381ff8032012d0"


def test_normalize_bytes():
    raw = bytes([0xED, 0x38, 0x1F, 0xF8, 0x03, 0x20, 0x12, 0xD0])
    assert _normalize_conv_id(raw) == "ed381ff8032012d0"


def test_normalize_empty_list():
    assert _normalize_conv_id([]) == ""


def test_normalize_empty_string():
    assert _normalize_conv_id("") == ""


# ---- _find_conversation ----


CONV_HEX = "ed381ff8032012d03065d45ca3e394b2"
CONV_BYTES = [
    0xED, 0x38, 0x1F, 0xF8, 0x03, 0x20, 0x12, 0xD0,
    0x30, 0x65, 0xD4, 0x5C, 0xA3, 0xE3, 0x94, 0xB2,
]


def _make_conv(id_value, name="test"):
    return {"id": id_value, "name": name, "type": "direct", "keys": {}, "participants": []}


def test_find_conversation_hex_string():
    convs = [_make_conv(CONV_HEX, "found")]
    result = _find_conversation(convs, CONV_HEX)
    assert result is not None
    assert result["name"] == "found"


def test_find_conversation_case_insensitive():
    convs = [_make_conv(CONV_HEX.upper(), "found")]
    result = _find_conversation(convs, CONV_HEX.lower())
    assert result is not None


def test_find_conversation_byte_list():
    """Must find conversations stored with legacy Go CLI byte-array format."""
    convs = [_make_conv(CONV_BYTES, "legacy")]
    result = _find_conversation(convs, CONV_HEX)
    assert result is not None
    assert result["name"] == "legacy"


def test_find_conversation_bytes():
    convs = [_make_conv(bytes(CONV_BYTES), "raw")]
    result = _find_conversation(convs, CONV_HEX)
    assert result is not None
    assert result["name"] == "raw"


def test_find_conversation_not_found():
    convs = [_make_conv("0000000000000000", "other")]
    result = _find_conversation(convs, CONV_HEX)
    assert result is None


def test_find_conversation_empty_list():
    result = _find_conversation([], CONV_HEX)
    assert result is None


def test_find_conversation_prefix_not_matched():
    """_find_conversation requires exact match, not prefix."""
    convs = [_make_conv(CONV_HEX, "full")]
    result = _find_conversation(convs, CONV_HEX[:8])
    assert result is None


def test_find_conversation_mixed_formats():
    """Multiple conversations in different formats should all be searchable."""
    convs = [
        _make_conv("aaaa0000bbbb0000cccc0000dddd0000", "hex-conv"),
        _make_conv(CONV_BYTES, "legacy-conv"),
        _make_conv("1111222233334444", "other"),
    ]
    result = _find_conversation(convs, CONV_HEX)
    assert result is not None
    assert result["name"] == "legacy-conv"
