"""Synchronous, explicitly pinned HTTP client for the reference Go registrar."""

import math
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .core import (CharterRecord, CharterStatement, charter_agent_id, check,
                   nonempty, size, valid_id, validate_shape, wire)
from .crypto import validate_charter_public_key
from .json import CharterError, charter_json_bytes, clone, parse_charter_json
from .proofs import (CharterTrust, verify_charter_chain_response, verify_charter_consistency,
                     verify_charter_heads, verify_charter_receipt)


class CharterRegistryError(CharterError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code


@dataclass
class CharterChainResult:
    record: CharterRecord | None
    evidence: dict


class CharterRegistryClient:
    """No discovery of trust, redirects, automatic POST retries, or implicit freshness.

    Retain authenticated heads and call consistency() to reject rollback/forks
    relative to them. A valid signature alone does not prove a head is recent.
    """

    def __init__(self, base_url: str, trust: CharterTrust, *, timeout: float = 30,
                 max_response_bytes: int = 32 * 1024 * 1024):
        check(type(base_url) is str and not any(ord(c) <= 32 or c == "\\" for c in base_url),
              "Invalid registry base URL")
        try:
            url = urlsplit(base_url)
            _ = url.port  # Reject malformed/out-of-range ports before any request.
        except ValueError as exc:
            raise CharterError("Invalid registry base URL") from exc
        check(url.hostname is not None and (url.scheme == "https" or
              (url.scheme == "http" and url.hostname in ("localhost", "127.0.0.1", "::1"))),
              "Registry requires HTTPS (HTTP is allowed on loopback for development)")
        check(url.username is None and url.password is None and "?" not in base_url and "#" not in base_url,
              "Invalid registry base URL")
        pinned = clone(trust)
        try:
            nonempty(pinned["registry"], "Registry pin")
            public_key = wire(pinned["registrar"]["pubkey"], 32)
            validate_charter_public_key(public_key)
            check(charter_agent_id(public_key) == pinned["registrar"]["kid"], "Invalid registrar pin")
        except (KeyError, TypeError) as exc:
            raise CharterError("Invalid registrar pin") from exc
        check(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0, "Invalid request timeout")
        check(type(max_response_bytes) is int and max_response_bytes > 0, "Invalid response limit")
        self._base = base_url.rstrip("/")
        self._trust = pinned
        self._max_response_bytes = max_response_bytes
        self._http = httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)

    def close(self) -> None:
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _request(self, path: str, method: str = "GET", body=None):
        options = {} if body is None else {"content": charter_json_bytes(body), "headers": {"Content-Type": "application/json"}}
        with self._http.stream(method, self._base + path, **options) as response:
            if response.is_redirect:
                raise CharterRegistryError(response.status_code, "redirect_rejected", "Registry redirect rejected")
            chunks = []
            length = 0
            for chunk in response.iter_bytes():
                length += len(chunk)
                check(length <= self._max_response_bytes, "Registry response exceeds byte limit")
                chunks.append(chunk)
            try:
                value = parse_charter_json(b"".join(chunks).decode("utf-8"))
            except (UnicodeError, CharterError) as exc:
                raise CharterRegistryError(response.status_code, "invalid_json", "Registry returned invalid JSON") from exc
            if not response.is_success:
                code = value.get("error") if type(value) is dict else None
                message = value.get("message") if type(value) is dict else None
                raise CharterRegistryError(response.status_code, code if type(code) is str else "http_error",
                                           message if type(message) is str else f"Registry HTTP {response.status_code}")
            check(type(value) is dict, "Registry response must be an object")
            return value

    @staticmethod
    def _query_size(snapshot_size: int | None) -> str:
        return "" if snapshot_size is None else f"?size={size(snapshot_size)}"

    def heads(self, snapshot_size: int | None = None) -> dict:
        result = self._request("/v1/heads" + self._query_size(snapshot_size))
        verify_charter_heads(result, self._trust)
        if snapshot_size is not None:
            check(result["log"]["signed"]["tree_size"] == snapshot_size, "Wrong snapshot size")
        return result

    def submit(self, statement: CharterStatement) -> dict:
        validate_shape(statement)
        check(statement["signed"]["registry"] == self._trust["registry"], "Registry audience mismatch")
        result = self._request("/v1/statements", "POST", statement)
        verify_charter_receipt(result, statement, self._trust)
        return result

    def chain(self, agent_id: str, snapshot_size: int | None = None) -> CharterChainResult:
        valid_id(agent_id)
        result = self._request(f"/v1/chain/{agent_id}" + self._query_size(snapshot_size))
        record = verify_charter_chain_response(result, self._trust, agent_id)
        if snapshot_size is not None:
            check(result["heads"]["log"]["signed"]["tree_size"] == snapshot_size, "Wrong snapshot size")
        return CharterChainResult(record, result)

    def consistency(self, older: dict, newer: dict) -> list[str]:
        verify_charter_heads(older, self._trust)
        verify_charter_heads(newer, self._trust)
        first, last = size(older["log"]["signed"]["tree_size"]), size(newer["log"]["signed"]["tree_size"])
        check(first <= last, "Invalid consistency head range")
        result = self._request(f"/v1/consistency?from={first}&to={last}")
        proof = result.get("proof")
        verify_charter_consistency(older["log"]["signed"], newer["log"]["signed"], proof)
        return proof

    def log(self, heads: dict) -> list[dict]:
        """Download a pinned-size log. Authenticate entries with audit_charter_snapshot."""
        verify_charter_heads(heads, self._trust)
        result = []
        count = size(heads["log"]["signed"]["tree_size"])
        while len(result) < count:
            page = self._request(f"/v1/log?size={count}&from={len(result)}&limit=1000")
            entries = page.get("entries")
            check(type(entries) is list and size(page.get("from")) == len(result) and
                  size(page.get("next")) == len(result) + len(entries) and
                  len(result) < page["next"] <= count, "Invalid log pagination")
            result.extend(entries)
        return result
