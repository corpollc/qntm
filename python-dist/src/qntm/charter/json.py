"""Strict RFC 8785 JSON, sharing the TypeScript/Go binary64 wire domain."""

import json
import math
from typing import Any

import rfc8785

MAX_SAFE_INTEGER = 2**53 - 1


class CharterError(ValueError):
    """Malformed charter input, invalid evidence, or rejected authority."""


def _normalize(value: Any, depth: int, ancestors: set[int]) -> Any:
    if depth > 128:
        raise CharterError("JSON nesting exceeds 128 levels")
    kind = type(value)
    if value is None or kind is bool:
        return value
    if kind is str:
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise CharterError("JCS rejects lone surrogates") from exc
        return value
    if kind is int:
        if abs(value) <= MAX_SAFE_INTEGER:
            return value
        # Accept exact binary64 integers, but never silently round Python input.
        try:
            number = float(value)
        except OverflowError as exc:
            raise CharterError("JCS requires finite binary64 numbers") from exc
        if not math.isfinite(number) or number != value:
            raise CharterError("Integer is not exact in binary64; use a string")
        return number
    if kind is float:
        if not math.isfinite(value):
            raise CharterError("JCS requires finite numbers")
        return value
    if kind not in (dict, list):
        raise CharterError("JSON requires plain dictionaries, lists and scalar values")
    if id(value) in ancestors:
        raise CharterError("JSON must not contain cycles")
    ancestors.add(id(value))
    try:
        if kind is list:
            return [_normalize(child, depth + 1, ancestors) for child in value]
        result = {}
        for key, child in value.items():
            if type(key) is not str:
                raise CharterError("JSON object keys must be strings")
            _normalize(key, depth, ancestors)
            result[key] = _normalize(child, depth + 1, ancestors)
        return result
    finally:
        ancestors.remove(id(value))


def charter_json_bytes(value: Any) -> bytes:
    """Canonical UTF-8 bytes; no object coercions, duplicate keys or lone surrogates."""
    try:
        return rfc8785.dumps(_normalize(value, 0, set()))
    except rfc8785.CanonicalizationError as exc:
        raise CharterError("Invalid canonical JSON") from exc


def canonicalize_charter_json(value: Any) -> str:
    return charter_json_bytes(value).decode("utf-8")


def parse_charter_json(text: str) -> Any:
    """Parse JSON using binary64 numbers, as in the TypeScript and Go clients.

    Integer tokens beyond the safe range follow JSON.parse's binary64 rounding.
    Use JSON strings when the exact value of a large integer matters.
    """
    if type(text) is not str:
        raise CharterError("Expected JSON text")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise CharterError("Duplicate JSON key")
            result[key] = value
        return result

    def integer(token: str) -> int | float:
        # Avoid Python's arbitrary-size integer parsing for large wire numbers.
        if len(token.lstrip("-")) <= 16:
            number = int(token)
            if abs(number) <= MAX_SAFE_INTEGER:
                return number
        return float(token)

    def invalid_constant(_: str) -> Any:
        raise CharterError("Invalid JSON constant")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_constant=invalid_constant)
        _normalize(value, 0, set())
        return value
    except (ValueError, RecursionError, UnicodeError) as exc:
        if isinstance(exc, CharterError):
            raise
        raise CharterError("Invalid JSON") from exc


def clone(value: Any) -> Any:
    return parse_charter_json(canonicalize_charter_json(value))
