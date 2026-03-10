"""Canonical CBOR encoding/decoding for QSP.

RFC 8949 section 4.2.1: deterministic encoding with keys sorted
by encoded byte length first, then lexicographic.
"""

import cbor2


def _to_canonical(obj):
    """Recursively convert dicts to sorted maps for canonical CBOR."""
    if obj is None:
        return obj
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, memoryview):
        return bytes(obj)
    if isinstance(obj, list):
        return [_to_canonical(item) for item in obj]
    if isinstance(obj, dict):
        # RFC 8949 §4.2.1: sort by encoded key length first, then lexicographic
        keys = sorted(obj.keys(), key=lambda k: (len(k), k))
        return {k: _to_canonical(obj[k]) for k in keys}
    return obj


def marshal_canonical(value) -> bytes:
    """Encode value as canonical CBOR."""
    canonical = _to_canonical(value)
    return cbor2.dumps(canonical, canonical=True)


def unmarshal(data: bytes):
    """Decode CBOR bytes."""
    return cbor2.loads(data)
