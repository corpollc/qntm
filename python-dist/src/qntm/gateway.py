"""Gateway: headless qntm conversation participant for gate.* message processing.

The gateway polls its dropbox for encrypted messages, processes gate.*
protocol messages (promote, config, secret, request, approval), and
executes authorized API requests when M-of-N signature thresholds are met.
"""

import base64
import binascii
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from .gate import (
    GATE_MESSAGE_APPROVAL,
    GATE_MESSAGE_CONFIG,
    GATE_MESSAGE_EXECUTED,
    GATE_MESSAGE_PROMOTE,
    GATE_MESSAGE_REQUEST,
    GATE_MESSAGE_SECRET,
    ThresholdRule,
    lookup_threshold,
    open_secret,
    verify_approval,
    verify_request,
)
from .identity import (
    base64url_decode,
    base64url_encode,
    generate_identity,
    validate_identity,
)

logger = logging.getLogger("qntm.gateway")


# ---------------------------------------------------------------------------
# Per-conversation gate state
# ---------------------------------------------------------------------------


@dataclass
class ConversationGateState:
    """Per-conversation gate state: org, rules, credentials, participants."""
    conv_id: bytes
    org_id: str
    rules: list[ThresholdRule] = field(default_factory=list)
    credentials: dict[str, dict] = field(default_factory=dict)
    participants: dict[str, bytes] = field(default_factory=dict)  # kid_hex -> public_key bytes


# ---------------------------------------------------------------------------
# File I/O helpers (mirror cli.py patterns)
# ---------------------------------------------------------------------------


def _load_json(path, default=None):
    if not os.path.isfile(path):
        return default
    with open(path) as f:
        return json.load(f)


def _save_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _decode_public_key(value: str) -> bytes:
    """Decode a signer public key from canonical base64url."""
    text = (value or "").strip()
    if not text:
        return b""

    try:
        decoded = base64url_decode(text)
    except Exception as exc:
        raise ValueError("invalid signer public key encoding") from exc

    if len(decoded) != 32:
        raise ValueError(f"invalid signer public key length: {len(decoded)}")
    if base64url_encode(decoded) != text:
        raise ValueError("signer public key must use canonical base64url encoding")
    return decoded


def _decode_encrypted_blob(value: str) -> bytes:
    """Decode encrypted_blob from canonical standard base64."""
    text = (value or "").strip()
    if not text:
        raise ValueError("encrypted_blob is required")

    # Reject ambiguous legacy hex payloads before base64 decoding.
    if len(text) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in text):
        raise ValueError("encrypted_blob must use standard base64 encoding, not hex")

    try:
        decoded = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise ValueError("invalid encrypted_blob encoding") from exc

    if base64.b64encode(decoded).decode("ascii") != text:
        raise ValueError("encrypted_blob must use canonical base64 encoding")
    return decoded


# ---------------------------------------------------------------------------
# Gateway init
# ---------------------------------------------------------------------------


def init_gateway(config_dir: str, force: bool = False) -> dict:
    """Generate a gateway identity and initialize the config directory.

    Creates:
      - config_dir/identity.json  (Ed25519 keypair, mode 0600)
      - config_dir/conversations.json  (empty array)
      - config_dir/vault/  (directory for credential encryption at rest)

    Returns dict with key_id, public_key, config_dir, vault_dir, identity_path.

    Raises FileExistsError if identity already exists and force is False.
    """
    os.makedirs(config_dir, mode=0o700, exist_ok=True)

    identity_path = os.path.join(config_dir, "identity.json")

    if os.path.isfile(identity_path) and not force:
        raise FileExistsError(
            f"identity already exists at {identity_path} (use --force to overwrite)"
        )

    # Generate new Ed25519 identity
    identity = generate_identity()
    validate_identity(identity)

    # Save identity (mode 0600)
    identity_data = {
        "private_key": identity["privateKey"].hex(),
        "public_key": identity["publicKey"].hex(),
        "key_id": identity["keyID"].hex(),
    }
    _save_json(identity_path, identity_data)
    os.chmod(identity_path, 0o600)

    # Create vault directory
    vault_dir = os.path.join(config_dir, "vault")
    os.makedirs(vault_dir, mode=0o700, exist_ok=True)

    # Create conversations file (empty array) if it does not exist
    convs_path = os.path.join(config_dir, "conversations.json")
    if not os.path.isfile(convs_path):
        _save_json(convs_path, [])

    return {
        "key_id": identity["keyID"].hex(),
        "public_key": base64url_encode(identity["publicKey"]),
        "config_dir": config_dir,
        "vault_dir": vault_dir,
        "identity_path": identity_path,
    }


# ---------------------------------------------------------------------------
# Gateway
# ---------------------------------------------------------------------------


class Gateway:
    """Headless qntm conversation participant that processes gate.* messages."""

    def __init__(self, config_dir: str):
        self.config_dir = config_dir
        self.identity: Optional[dict] = None
        # conv_id bytes -> ConversationGateState
        self.conversations: dict[bytes, ConversationGateState] = {}
        # conv_id bytes -> list of gate message dicts
        self.gate_messages: dict[bytes, list[dict]] = {}
        # conv_id bytes -> sequence cursor
        self.sequence_cursors: dict[bytes, int] = {}

    # --- Identity ---

    def load_identity(self) -> dict:
        """Load the gateway identity from the config directory."""
        path = os.path.join(self.config_dir, "identity.json")
        if not os.path.isfile(path):
            raise FileNotFoundError(
                f"no identity found at {path}; run 'qntm gateway init' first"
            )
        raw = _load_json(path)
        self.identity = {
            "privateKey": bytes.fromhex(raw["private_key"]),
            "publicKey": bytes.fromhex(raw["public_key"]),
            "keyID": bytes.fromhex(raw["key_id"]),
        }
        return self.identity

    # --- Conversation state ---

    def get_conversation_state(self, conv_id: bytes) -> Optional[ConversationGateState]:
        return self.conversations.get(conv_id)

    def get_gate_messages(self, conv_id: bytes) -> list[dict]:
        return self.gate_messages.get(conv_id, [])

    # --- Message handlers ---

    def handle_promote(self, conv_id: bytes, payload: dict) -> None:
        """Process a gate.promote payload: register conversation as gate-enabled."""
        org_id = payload.get("org_id", "")
        if not org_id:
            raise ValueError("promote message missing org_id")

        participants: dict[str, bytes] = {}
        for s in payload.get("signers", []):
            kid = s.get("kid", "")
            pub_key_str = s.get("public_key", "")
            if pub_key_str:
                pub_key = _decode_public_key(pub_key_str)
            else:
                pub_key = b""
            if not kid and pub_key:
                from .identity import key_id_from_public_key
                kid = key_id_from_public_key(pub_key).hex()
            participants[kid] = pub_key

        rules = [
            ThresholdRule(
                service=r.get("service", "*"),
                endpoint=r.get("endpoint", "*"),
                verb=r.get("verb", "*"),
                m=r.get("m", 1),
                n=r.get("n", 0),
            )
            for r in payload.get("rules", [])
        ]

        state = ConversationGateState(
            conv_id=conv_id,
            org_id=org_id,
            rules=rules,
            participants=participants,
        )
        self.conversations[conv_id] = state
        logger.info(
            "PROMOTE conv=%s org=%s signers=%d rules=%d",
            conv_id[:4].hex(), org_id, len(participants), len(rules),
        )

    def handle_config(self, conv_id: bytes, payload: dict) -> None:
        """Process a gate.config payload: update threshold rules."""
        state = self.conversations.get(conv_id)
        if state is None:
            raise ValueError("gate.config received for non-promoted conversation")

        rules = [
            ThresholdRule(
                service=r.get("service", "*"),
                endpoint=r.get("endpoint", "*"),
                verb=r.get("verb", "*"),
                m=r.get("m", 1),
                n=r.get("n", 0),
            )
            for r in payload.get("rules", [])
        ]
        state.rules = rules
        logger.info(
            "CONFIG updated conv=%s org=%s rules=%d",
            conv_id[:4].hex(), state.org_id, len(rules),
        )

    def handle_secret(self, conv_id: bytes, payload: dict) -> None:
        """Process a gate.secret payload: decrypt and store credential."""
        state = self.conversations.get(conv_id)
        if state is None:
            raise ValueError("gate.secret received for non-promoted conversation")

        sender_kid = payload.get("sender_kid", "")
        sender_pub_key = state.participants.get(sender_kid)
        if sender_pub_key is None:
            raise ValueError(f"unknown sender kid {sender_kid!r} in gate.secret")

        encrypted_blob = _decode_encrypted_blob(payload["encrypted_blob"])
        decrypted = open_secret(
            self.identity["privateKey"],
            sender_pub_key,
            encrypted_blob,
        )

        service = payload.get("service", "")
        state.credentials[service] = {
            "id": payload.get("secret_id", ""),
            "service": service,
            "header_name": payload.get("header_name", ""),
            "header_template": payload.get("header_template", ""),
            "value": decrypted.decode("utf-8"),
        }
        logger.info(
            "SECRET stored conv=%s org=%s service=%s",
            conv_id[:4].hex(), state.org_id, service,
        )

    def handle_request(self, conv_id: bytes, payload: dict) -> None:
        """Process a gate.request payload: store for threshold scanning."""
        state = self.conversations.get(conv_id)
        if state is None:
            raise ValueError("gate.request received for non-promoted conversation")

        messages = self.gate_messages.setdefault(conv_id, [])
        messages.append(payload)

        logger.info(
            "REQUEST conv=%s org=%s req=%s verb=%s service=%s by=%s",
            conv_id[:4].hex(), state.org_id,
            payload.get("request_id"), payload.get("verb"),
            payload.get("target_service"), payload.get("signer_kid"),
        )

    def handle_approval(self, conv_id: bytes, payload: dict) -> None:
        """Process a gate.approval payload: store for threshold scanning."""
        state = self.conversations.get(conv_id)
        if state is None:
            raise ValueError("gate.approval received for non-promoted conversation")

        messages = self.gate_messages.setdefault(conv_id, [])
        messages.append(payload)

        logger.info(
            "APPROVAL conv=%s org=%s req=%s by=%s",
            conv_id[:4].hex(), state.org_id,
            payload.get("request_id"), payload.get("signer_kid"),
        )

    # --- Message routing ---

    def process_message(self, conv_id: bytes, body_type: str, body: bytes) -> None:
        """Route a decrypted message to the appropriate handler by body_type."""
        if body_type == GATE_MESSAGE_PROMOTE:
            payload = json.loads(body)
            self.handle_promote(conv_id, payload)
        elif body_type == GATE_MESSAGE_CONFIG:
            payload = json.loads(body)
            self.handle_config(conv_id, payload)
        elif body_type == GATE_MESSAGE_SECRET:
            payload = json.loads(body)
            self.handle_secret(conv_id, payload)
        elif body_type == GATE_MESSAGE_REQUEST:
            payload = json.loads(body)
            self.handle_request(conv_id, payload)
        elif body_type == GATE_MESSAGE_APPROVAL:
            payload = json.loads(body)
            self.handle_approval(conv_id, payload)
        else:
            # Ignore non-gate messages silently
            pass

    # --- Polling loop ---

    def load_conversations(self) -> list[dict]:
        """Load conversation records from the config directory."""
        path = os.path.join(self.config_dir, "conversations.json")
        return _load_json(path, [])

    def run(
        self,
        dropbox_url: str,
        poll_interval: int = 5,
        conversations: Optional[list[dict]] = None,
    ) -> None:
        """Start the gateway polling loop. Blocks until SIGINT/SIGTERM.

        Args:
            dropbox_url: HTTP dropbox endpoint URL.
            poll_interval: Seconds between polls.
            conversations: Conversation records to poll. If None, loads from config.
        """
        if self.identity is None:
            self.load_identity()

        if conversations is None:
            conversations = self.load_conversations()

        if not conversations:
            raise ValueError(
                f"no conversations found in {self.config_dir}\n"
                f"The gateway needs at least one conversation to poll.\n"
                f"Join one with: qntm --config-dir {self.config_dir} convo join <token>"
            )

        # Import HTTP helpers from cli module
        from .cli import (
            _http_poll,
            _conv_to_crypto,
        )
        from .message import decrypt_message, deserialize_envelope

        kid_hex = self.identity["keyID"].hex()
        logger.info(
            "starting gateway kid=%s conversations=%d poll=%ds",
            kid_hex[:8], len(conversations), poll_interval,
        )

        # Register conversations
        conv_cryptos = {}
        for conv_record in conversations:
            conv_id_hex = conv_record["id"]
            conv_crypto = _conv_to_crypto(conv_record)
            conv_cryptos[conv_id_hex] = conv_crypto
            logger.info("  registered conversation %s", conv_id_hex[:8])

        # Load sequence cursors
        cursors_path = os.path.join(self.config_dir, "sequence_cursors.json")
        cursors = _load_json(cursors_path, {})

        # Graceful shutdown
        running = True

        def _signal_handler(signum, frame):
            nonlocal running
            sig_name = signal.Signals(signum).name
            logger.info("received %s, shutting down gateway...", sig_name)
            running = False

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        logger.info("gateway running, press Ctrl+C to stop")

        while running:
            for conv_record in conversations:
                if not running:
                    break

                conv_id_hex = conv_record["id"]
                conv_crypto = conv_cryptos[conv_id_hex]
                from_seq = cursors.get(conv_id_hex, 0)

                try:
                    raw_messages, up_to_seq = _http_poll(
                        dropbox_url, conv_id_hex, from_seq
                    )
                except Exception as e:
                    logger.error("poll error conv=%s: %s", conv_id_hex[:8], e)
                    continue

                if up_to_seq > from_seq:
                    cursors[conv_id_hex] = up_to_seq
                    _save_json(cursors_path, cursors)

                for raw_msg in raw_messages:
                    try:
                        envelope_bytes = base64.b64decode(raw_msg["envelope_b64"])
                        envelope = deserialize_envelope(envelope_bytes)
                        msg = decrypt_message(envelope, conv_crypto)
                    except Exception as e:
                        logger.debug("decrypt error: %s", e)
                        continue

                    inner = msg["inner"]
                    body_type = inner["body_type"]
                    body_bytes = bytes(inner["body"])
                    conv_id = bytes(conv_crypto["id"])

                    try:
                        self.process_message(conv_id, body_type, body_bytes)
                    except Exception as e:
                        logger.error(
                            "process error conv=%s body_type=%s: %s",
                            conv_id_hex[:8], body_type, e,
                        )

            # Sleep between poll cycles
            if running:
                time.sleep(poll_interval)

        logger.info("gateway stopped")
