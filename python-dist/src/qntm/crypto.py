"""QSP-1 cryptographic suite implementation.

Wraps established libraries (PyNaCl, cryptography, hashlib) to implement
the QSP-1 crypto primitives. No custom crypto.
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
# XChaCha20-Poly1305 via PyNaCl (libsodium)
import nacl.bindings

from .constants import (
    INFO_AEAD,
    INFO_AEAD_V11,
    INFO_NONCE,
    INFO_NONCE_V11,
    INFO_ROOT,
    INFO_WRAP_V11,
)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract (RFC 5869) using HMAC-SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869) using HMAC-SHA-256."""
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Full HKDF (extract + expand)."""
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


class QSP1Suite:
    """QSP-1 cryptographic suite."""

    def name(self) -> str:
        return "QSP-1"

    def generate_identity_key(self) -> tuple[bytes, bytes]:
        """Generate Ed25519 keypair. Returns (private_key_64, public_key_32)."""
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        # Ed25519 seed (32 bytes)
        seed = sk.private_bytes_raw()
        pub = pk.public_bytes_raw()
        # Go-compatible 64-byte private key: seed || public_key
        private_key = seed + pub
        return private_key, pub

    def compute_key_id(self, public_key: bytes) -> bytes:
        """Trunc16(SHA-256(public_key))."""
        return hashlib.sha256(public_key).digest()[:16]

    def generate_group_key(self) -> bytes:
        return os.urandom(32)

    def derive_root_key(
        self, invite_secret: bytes, invite_salt: bytes, conv_id: bytes
    ) -> bytes:
        info = INFO_ROOT.encode() + conv_id
        return _hkdf(invite_secret, invite_salt, info, 32)

    def derive_conversation_keys(
        self, root_key: bytes, conv_id: bytes
    ) -> tuple[bytes, bytes]:
        """Returns (aead_key, nonce_key) via HKDF-Expand only."""
        aead_info = INFO_AEAD.encode() + conv_id
        nonce_info = INFO_NONCE.encode() + conv_id
        aead_key = _hkdf_expand(root_key, aead_info, 32)
        nonce_key = _hkdf_expand(root_key, nonce_info, 32)
        return aead_key, nonce_key

    def derive_epoch_keys(
        self, group_key: bytes, conv_id: bytes, epoch: int
    ) -> tuple[bytes, bytes]:
        """Returns (aead_key, nonce_key) for a given epoch."""
        if epoch == 0:
            return self.derive_conversation_keys(group_key, conv_id)

        epoch_bytes = struct.pack(">I", epoch)
        aead_info = INFO_AEAD_V11.encode() + conv_id + epoch_bytes
        nonce_info = INFO_NONCE_V11.encode() + conv_id + epoch_bytes
        aead_key = _hkdf_expand(group_key, aead_info, 32)
        nonce_key = _hkdf_expand(group_key, nonce_info, 32)
        return aead_key, nonce_key

    def derive_nonce(self, nonce_key: bytes, msg_id: bytes) -> bytes:
        """Trunc24(HMAC-SHA-256(nonce_key, msg_id))."""
        return hmac.new(nonce_key, msg_id, hashlib.sha256).digest()[:24]

    def encrypt(
        self, aead_key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
    ) -> bytes:
        """XChaCha20-Poly1305 encrypt."""
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, aead_key
        )

    def decrypt(
        self, aead_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
    ) -> bytes:
        """XChaCha20-Poly1305 decrypt."""
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, aead_key
        )

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Ed25519 sign. private_key is 64-byte (seed + pub)."""
        seed = private_key[:32]
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        return sk.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Ed25519 verify."""
        try:
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except Exception:
            return False

    def hash(self, data: bytes) -> bytes:
        """SHA-256."""
        return hashlib.sha256(data).digest()

    def wrap_key_for_recipient(
        self,
        new_group_key: bytes,
        recipient_ed25519_pk: bytes,
        recipient_kid: bytes,
        conv_id: bytes,
    ) -> bytes:
        """Wrap a group key for a recipient using X25519 + XChaCha20-Poly1305."""
        from .cbor import marshal_canonical

        recipient_x25519_pk = ed25519_public_key_to_x25519(recipient_ed25519_pk)
        ek_sk = X25519PrivateKey.generate()
        ek_pk = ek_sk.public_key().public_bytes_raw()

        shared = ek_sk.exchange(
            X25519PublicKey.from_public_bytes(recipient_x25519_pk)
        )

        prk = _hkdf_extract(conv_id, shared)
        info = INFO_WRAP_V11.encode() + recipient_kid
        wrap_key = _hkdf_expand(prk, info, 32)

        nonce = os.urandom(24)
        ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            new_group_key, None, nonce, wrap_key
        )

        return marshal_canonical({"ct": ct, "ek_pk": ek_pk, "nonce": nonce})

    def unwrap_key_for_recipient(
        self,
        wrapped_data: bytes,
        recipient_ed25519_sk: bytes,
        recipient_kid: bytes,
        conv_id: bytes,
    ) -> bytes:
        """Unwrap a group key using recipient's private key."""
        from .cbor import unmarshal

        obj = unmarshal(wrapped_data)
        ek_pk = bytes(obj["ek_pk"])
        nonce = bytes(obj["nonce"])
        ct = bytes(obj["ct"])

        recipient_x25519_sk = ed25519_private_key_to_x25519(recipient_ed25519_sk)
        x_sk = X25519PrivateKey.from_private_bytes(recipient_x25519_sk)
        shared = x_sk.exchange(X25519PublicKey.from_public_bytes(ek_pk))

        prk = _hkdf_extract(conv_id, shared)
        info = INFO_WRAP_V11.encode() + recipient_kid
        wrap_key = _hkdf_expand(prk, info, 32)

        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct, None, nonce, wrap_key
        )


def ed25519_public_key_to_x25519(ed_pk: bytes) -> bytes:
    """Convert Ed25519 public key to X25519 using libsodium."""
    return nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(ed_pk)


def ed25519_private_key_to_x25519(ed_sk: bytes) -> bytes:
    """Convert Ed25519 private key (64-byte seed+pub) to X25519 via SHA-512 + clamp."""
    import hashlib as _hl

    h = _hl.sha512(ed_sk[:32]).digest()
    h_list = list(h[:32])
    h_list[0] &= 248
    h_list[31] &= 127
    h_list[31] |= 64
    return bytes(h_list)
