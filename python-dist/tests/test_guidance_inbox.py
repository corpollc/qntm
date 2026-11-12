"""Recipient separation, reviewed built-in destinations and private reply routing."""
import json
from unittest.mock import Mock

import pytest
from qntm import cli
from qntm.identity import generate_identity, base64url_decode
from qntm.invite import create_invite, invite_to_token
from qntm.message import decrypt_message, deserialize_envelope
from qntm.gate import open_secret
from qntm.guidance import prepare_request, send_request, list_contacts
from qntm.guidance_inbox import create_intake, open_intake, intake_conversation, providers


@pytest.fixture
def inbox():
    recipient = generate_identity()
    invite = create_invite(recipient)
    provider = {**providers()[0], "recipient_public_key": recipient["publicKey"].hex(),
                "recipient_key_id": recipient["keyID"].hex(), "conversation_id": invite["conv_id"].hex(),
                "intake_invite": invite_to_token(invite)}
    return recipient, provider


def test_only_recipient_can_read_public_intake(inbox):
    recipient, provider = inbox
    sender, outsider = generate_identity(), generate_identity()
    request = create_intake(sender, provider, "A private question", "Private context")
    public = decrypt_message(request["envelope"], intake_conversation(provider))
    assert b"private" not in public["inner"]["body"].lower()
    with pytest.raises(Exception):
        open_secret(outsider["privateKey"], sender["publicKey"], base64url_decode(public["inner"]["body"].decode()))
    opened = open_intake(recipient, provider, request["envelope"])
    assert opened["question"] == "A private question"
    assert opened["context"] == "Private context"
    assert opened["sender_key_id"] == sender["keyID"].hex()
    assert opened["reply_invite"]["inviter_ik_pk"] == sender["publicKey"]
    assert opened["reply_invite"]["conv_id"].hex() == request["request_id"]
    assert request["reply_conversation"]["participants"] == [sender["keyID"], recipient["keyID"]]


def test_destination_mismatch_and_tamper_fail(inbox):
    recipient, provider = inbox
    sender = generate_identity()
    for changed in ({"recipient_key_id": "f" * 32}, {"conversation_id": "f" * 32}, {"recipient_public_key": sender["publicKey"].hex()}):
        with pytest.raises(ValueError):
            create_intake(sender, {**provider, **changed}, "Question")
    request = create_intake(sender, provider, "Question")
    request["envelope"]["ciphertext"] = request["envelope"]["ciphertext"][:-1] + bytes([request["envelope"]["ciphertext"][-1] ^ 1])
    with pytest.raises(Exception): open_intake(recipient, provider, request["envelope"])


def test_builtin_review_send_and_key_retention(inbox, tmp_path, monkeypatch):
    recipient, provider = inbox
    monkeypatch.setattr('qntm.guidance_inbox.providers', lambda category=None: [provider] if category in (None, provider['category']) else [])
    path = str(tmp_path)
    cli._save_identity(path, generate_identity())
    send = Mock(return_value={"seq": 1})
    monkeypatch.setattr(cli, '_http_send', send)
    draft = prepare_request(path, provider['relay_url'], provider['id'], 'Question', 'Context')
    send.assert_not_called()
    assert cli._load_conversations(path) == []
    assert 'Grok' in draft['notice']
    assert list_contacts(path, include_builtin=True) == [provider]
    with pytest.raises(ValueError):
        send_request(path, provider['relay_url'], provider['id'], 'Changed', 'Context', draft['review_token'])
    send.assert_not_called()
    result = send_request(path, provider['relay_url'], provider['id'], 'Question', 'Context', draft['review_token'])
    assert send.call_args.args[:2] == (provider['relay_url'], provider['conversation_id'])
    opened = open_intake(recipient, provider, deserialize_envelope(send.call_args.args[2]))
    assert opened['question'] == 'Question'
    assert opened['request_id'] == result['conversation_id']
    conv = cli._load_conversations(path)[0]
    assert conv['id'] == result['conversation_id']
    assert len(cli._load_participant_public_keys(path, conv['id'])) == 2
    send.side_effect = OSError('unknown delivery')
    with pytest.raises(OSError): send_request(path, provider['relay_url'], provider['id'], 'Question', 'Context', draft['review_token'])
    assert len(cli._load_conversations(path)) == 2  # even an uncertain submission retains its reply keys


def test_published_providers_are_distinct_and_valid():
    records = providers()
    assert {p['category'] for p in records} == {'legal', 'ethical', 'law_enforcement'}
    assert len({p['recipient_key_id'] for p in records}) == 3
    for provider in records:
        intake_conversation(provider)
        assert 'private' not in json.dumps(provider)


def test_open_intake_normalizes_crypto_cbor_and_surrogate_errors_to_value_error(inbox):
    from qntm.gate import seal_secret
    from qntm.guidance_inbox import DOMAIN, INTAKE_TYPE
    from qntm.identity import base64url_encode
    from qntm.message import create_message

    recipient, provider = inbox
    sender = generate_identity()
    intake = intake_conversation(provider)

    # Corrupt inner sealed secret (CryptoError inside open_secret -> ValueError)
    bad_sealed_env = create_message(sender, intake, INTAKE_TYPE, base64url_encode(b"x" * 64).encode())
    with pytest.raises(ValueError):
        open_intake(recipient, provider, bad_sealed_env)

    # Tampered outer envelope msg_id int (ValueError)
    with pytest.raises(ValueError):
        open_intake(recipient, provider, {**bad_sealed_env, "msg_id": 10_000_000_000})

    # Escaped lone UTF-16 surrogate inside sealed JSON payload -> rejected as ValueError
    reply_inv = create_invite(sender)
    surrogate_json = (
        '{"domain":"' + DOMAIN + '",'
        '"category":"' + provider["category"] + '",'
        '"recipient_key_id":"' + provider["recipient_key_id"] + '",'
        '"request_id":"' + reply_inv["conv_id"].hex() + '",'
        '"reply_invite":"' + invite_to_token(reply_inv) + '",'
        '"question":"hello \\ud800 world",'
        '"context":""}'
    ).encode("utf-8")
    sealed_surrogate = seal_secret(sender["privateKey"], recipient["publicKey"], surrogate_json)
    surrogate_env = create_message(sender, intake, INTAKE_TYPE, base64url_encode(sealed_surrogate).encode())
    with pytest.raises(ValueError):
        open_intake(recipient, provider, surrogate_env)
