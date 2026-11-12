"""Tests for DID resolution module."""

import base64
import http.client
import json
import pytest
from unittest.mock import patch, MagicMock
from nacl.signing import SigningKey

from qntm.did import (
    resolve_did_web,
    resolve_did_key,
    resolve_did,
    resolve_did_to_ed25519,
    DIDDocument,
    DIDResolutionError,
    _base58_decode,
)

VALID_ED25519_PUBKEY = SigningKey(bytes(range(32))).verify_key.encode()


# --- did:web tests ---


class TestResolveDidWeb:
    """Tests for did:web resolution."""

    def _mock_urlopen(self, data: dict):
        """Create a mock for urllib.request.urlopen."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(data).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def test_root_domain(self):
        """did:web:example.com → https://example.com/.well-known/did.json"""
        doc_data = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
            "service": [
                {
                    "id": "did:web:example.com#inbox",
                    "type": "AgentInbox",
                    "serviceEndpoint": "https://example.com/inbox",
                }
            ],
        }

        with patch("qntm._identity_http._opener.open") as mock_open:
            mock_open.return_value = self._mock_urlopen(doc_data)
            doc = resolve_did_web("did:web:example.com")

        assert doc.id == "did:web:example.com"
        assert len(doc.services) == 1
        assert doc.services[0]["type"] == "AgentInbox"
        assert doc.service_endpoint("AgentInbox") == "https://example.com/inbox"

    def test_path_did(self):
        """did:web:example.com:path:to → https://example.com/path/to/did.json"""
        doc_data = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com:path:to",
        }

        with patch("qntm._identity_http._opener.open") as mock_open:
            mock_open.return_value = self._mock_urlopen(doc_data)
            doc = resolve_did_web("did:web:example.com:path:to")

            # Verify the URL was correct
            call_args = mock_open.call_args
            req = call_args[0][0]
            assert req.full_url == "https://example.com/path/to/did.json"

    def test_not_did_web(self):
        """Non did:web URIs should raise."""
        with pytest.raises(DIDResolutionError, match="Not a did:web"):
            resolve_did_web("did:key:z123")

    def test_ed25519_key_extraction_multibase(self):
        """Extract Ed25519 public key from publicKeyMultibase."""
        # Ed25519 multicodec prefix (0xed, 0x01) + 32 bytes
        raw_key = VALID_ED25519_PUBKEY
        multicodec = bytes([0xED, 0x01]) + raw_key
        # Encode as base58btc
        multibase = "z" + _base58_encode(multicodec)

        doc_data = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyMultibase": multibase,
                }
            ],
        }

        with patch("qntm._identity_http._opener.open") as mock_open:
            mock_open.return_value = self._mock_urlopen(doc_data)
            doc = resolve_did_web("did:web:example.com")

        key = doc.ed25519_public_key()
        assert key == raw_key

    def test_ed25519_key_extraction_jwk(self):
        """Extract Ed25519 public key from publicKeyJwk."""
        import base64

        raw_key = VALID_ED25519_PUBKEY
        x_value = base64.urlsafe_b64encode(raw_key).rstrip(b"=").decode()

        doc_data = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
            "verificationMethod": [
                {
                    "id": "did:web:example.com#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:web:example.com",
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": x_value,
                    },
                }
            ],
        }

        with patch("qntm._identity_http._opener.open") as mock_open:
            mock_open.return_value = self._mock_urlopen(doc_data)
            doc = resolve_did_web("did:web:example.com")

        key = doc.ed25519_public_key()
        assert key == raw_key

    def test_no_ed25519_key(self):
        """DID Document without Ed25519 key returns None."""
        doc_data = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
            "service": [],
        }

        with patch("qntm._identity_http._opener.open") as mock_open:
            mock_open.return_value = self._mock_urlopen(doc_data)
            doc = resolve_did_web("did:web:example.com")

        assert doc.ed25519_public_key() is None

    def test_service_endpoint_lookup(self):
        """Find service endpoint by type."""
        doc = DIDDocument(
            id="did:web:example.com",
            services=[
                {"type": "AgentInbox", "serviceEndpoint": "https://inbox.example.com"},
                {"type": "LinkedDomains", "serviceEndpoint": "https://example.com"},
            ],
        )

        assert doc.service_endpoint("AgentInbox") == "https://inbox.example.com"
        assert doc.service_endpoint("LinkedDomains") == "https://example.com"
        assert doc.service_endpoint("Nonexistent") is None


# --- did:key tests ---


class TestResolveDidKey:
    """Tests for did:key resolution."""

    def test_ed25519_key(self):
        """Resolve did:key with Ed25519 multicodec prefix."""
        raw_key = VALID_ED25519_PUBKEY
        multicodec = bytes([0xED, 0x01]) + raw_key
        multibase = _base58_encode(multicodec)
        did_uri = f"did:key:z{multibase}"

        doc = resolve_did_key(did_uri)

        assert doc.id == did_uri
        assert len(doc.verification_methods) == 1
        assert doc.verification_methods[0]["_raw_public_key"] == raw_key

    def test_not_did_key(self):
        """Non did:key URIs should raise."""
        with pytest.raises(DIDResolutionError, match="Not a did:key"):
            resolve_did_key("did:web:example.com")


# --- Universal resolver tests ---


class TestResolveDid:
    """Tests for the universal resolve_did function."""

    def test_routes_to_did_key(self):
        """did:key routes to resolve_did_key."""
        raw_key = VALID_ED25519_PUBKEY
        multicodec = bytes([0xED, 0x01]) + raw_key
        multibase = _base58_encode(multicodec)
        did_uri = f"did:key:z{multibase}"

        doc = resolve_did(did_uri)
        assert doc.id == did_uri

    def test_unsupported_method(self):
        """Unsupported DID methods raise."""
        with pytest.raises(DIDResolutionError, match="Unsupported DID method"):
            resolve_did("did:ion:abc123")


class TestResolveDidToEd25519:
    """Tests for the convenience resolve_did_to_ed25519 function."""

    def test_did_key_returns_raw_bytes(self):
        """did:key resolution returns 32-byte Ed25519 public key."""
        raw_key = VALID_ED25519_PUBKEY
        multicodec = bytes([0xED, 0x01]) + raw_key
        multibase = _base58_encode(multicodec)
        did_uri = f"did:key:z{multibase}"

        key = resolve_did_to_ed25519(did_uri)
        assert key == raw_key
        assert len(key) == 32

    def test_no_key_raises(self):
        """DID Document without Ed25519 key raises."""
        doc_data = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com",
        }

        with patch("qntm._identity_http._opener.open") as mock_open:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(doc_data).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = mock_resp

            with pytest.raises(DIDResolutionError, match="No Ed25519"):
                resolve_did_to_ed25519("did:web:example.com")


# --- Live integration test (skipped by default) ---


class TestLiveResolution:
    """Live DID resolution tests. Run with pytest -m live."""

    @pytest.mark.skip(reason="Requires network access — run manually")
    def test_archedark_ada_did(self):
        """Resolve archedark-ada's live DID."""
        doc = resolve_did_web("did:web:inbox.ada.archefire.com")
        assert doc.id == "did:web:inbox.ada.archefire.com"
        assert doc.service_endpoint("AgentInbox") == "https://inbox.ada.archefire.com"


# --- Helpers ---


_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode bytes to base58btc string."""
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r + 1])
    result.reverse()

    # Preserve leading zeros
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break

    return (b"1" * pad + b"".join(result)).decode()


@pytest.mark.parametrize("did", ["did:web:user@example.com", "did:web:example.com/evil", "did:web:example.com:..", "did:web:example.com:%2Fprivate"])
def test_invalid_web_authorities_and_paths(did):
    with pytest.raises(DIDResolutionError):
        resolve_did_web(did)


def test_identity_http_bounds_and_no_redirects():
    from qntm._identity_http import MAX_IDENTITY_DOCUMENT_BYTES, _NoRedirect, read_identity_json
    assert _NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid") is None
    with patch("qntm._identity_http._opener.open") as op:
        response = op.return_value.__enter__.return_value
        response.read.return_value = b"x" * (MAX_IDENTITY_DOCUMENT_BYTES + 1)
        with pytest.raises(ValueError, match="size limit"):
            read_identity_json("https://example.com", timeout=1)
        response.read.assert_called_once_with(MAX_IDENTITY_DOCUMENT_BYTES + 1)


def test_did_web_document_id_must_match():
    with patch("qntm.did.read_identity_json", return_value={"id": "did:web:elsewhere.example"}):
        with pytest.raises(DIDResolutionError, match="identifier mismatch"):
            resolve_did_web("did:web:example.com")


@pytest.mark.parametrize(
    "bad_key",
    [
        b"\x01" + b"\x00" * 31,  # Ed25519 identity / small-order point
        bytes(range(32)),        # off-curve bytes
        VALID_ED25519_PUBKEY[:31],
        VALID_ED25519_PUBKEY + b"\x00",
    ],
)
def test_ed25519_curve_and_length_validation_across_all_encodings(bad_key):
    multicodec = bytes([0xED, 0x01]) + bad_key
    did_key_uri = f"did:key:z{_base58_encode(multicodec)}"
    with pytest.raises(DIDResolutionError):
        resolve_did_key(did_key_uri)
    with pytest.raises(DIDResolutionError):
        resolve_did_to_ed25519(did_key_uri)

    doc = DIDDocument(
        id="did:web:example.com",
        verification_methods=[
            {
                "id": "did:web:example.com#mb",
                "type": "Ed25519VerificationKey2020",
                "publicKeyMultibase": "z" + _base58_encode(multicodec),
            },
            {
                "id": "did:web:example.com#b58",
                "type": "Ed25519VerificationKey2018",
                "publicKeyBase58": _base58_encode(bad_key),
            },
            {
                "id": "did:web:example.com#jwk",
                "type": "Ed25519VerificationKey2020",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": base64.urlsafe_b64encode(bad_key).rstrip(b"=").decode(),
                },
            },
        ],
    )
    assert doc.ed25519_public_key() is None


def test_base58_length_cap_blocks_oversized_inputs():
    with pytest.raises(ValueError, match="length"):
        _base58_decode("2" * 65)
    with pytest.raises(DIDResolutionError):
        resolve_did_key("did:key:z" + ("2" * 5000))


@pytest.mark.parametrize(
    "did",
    [
        "did:web:%5B%3A%3A1%5D",
        "did:web:%5b::1%5d",
        "did:web:127.0.0.1",
        "did:web:10.0.0.1",
        "did:web:169.254.169.254",
        "did:web:localhost",
        "did:web:api.localhost",
        "did:web:printer.local",
        "did:web:2130706433",
        "did:web:localhost%3A8443",
        "did:web:127.0.0.1%3A8080",
        "did:web:example.com%3A0",
        "did:web:example.com%3A99999",
    ],
)
def test_did_web_percent_decoded_loopback_and_private_hosts_rejected(did):
    with patch("qntm._identity_http._opener.open") as mock_open:
        with pytest.raises(DIDResolutionError):
            resolve_did_web(did)
        mock_open.assert_not_called()


def test_malformed_did_documents_and_invalid_urls_normalize_cleanly():
    doc_with_string_vm = {
        "id": "did:web:example.com",
        "verificationMethod": [
            "did:web:example.com#string-ref",
            {
                "id": "did:web:example.com#bad-jwk",
                "type": "Ed25519VerificationKey2020",
                "publicKeyJwk": "not-a-dict",
            },
            {
                "id": "did:web:example.com#good",
                "type": "Ed25519VerificationKey2020",
                "publicKeyBase58": _base58_encode(VALID_ED25519_PUBKEY),
            },
        ],
        "service": ["not-a-dict", {"type": "AgentInbox", "serviceEndpoint": "https://example.com/inbox"}],
    }
    with patch("qntm.did.read_identity_json", return_value=doc_with_string_vm):
        assert resolve_did_to_ed25519("did:web:example.com") == VALID_ED25519_PUBKEY

    with patch("qntm.did.read_identity_json", side_effect=http.client.InvalidURL("bad url")):
        with pytest.raises(DIDResolutionError):
            resolve_did_web("did:web:example.com")
