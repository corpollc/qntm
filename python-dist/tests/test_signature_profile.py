import json
from pathlib import Path

import pytest

from qntm.crypto import QSP1Suite
from qntm.charter.crypto import validate_charter_public_key, verify_charter_signature
from qntm import (is_valid_ed25519_public_key, verify_ed25519_signature, generate_identity,
                  create_invite, validate_invite, base64url_encode, key_id_from_public_key,
                  create_conversation, derive_conversation_keys, create_message, decrypt_message,
                  marshal_canonical, create_group_add_body, parse_group_add_body, GroupState)
from qntm.cbor import unmarshal
from qntm.gateway_handshake import valid_gateway

VECTORS = json.loads((Path(__file__).resolve().parents[2] / 'specs/test-vectors/ed25519-verification.json').read_text())['cases']


@pytest.mark.parametrize('vector', VECTORS, ids=lambda v: v['name'])
def test_shared_signature_profile(vector):
    key, message, signature = (bytes.fromhex(vector[k]) for k in ('public_key_hex', 'message_hex', 'signature_hex'))
    assert QSP1Suite().verify(key, message, signature) is vector['valid']
    assert is_valid_ed25519_public_key(key) is vector['key_valid']
    assert verify_ed25519_signature(key, message, signature) is vector['valid']
    if vector['key_valid']:
        validate_charter_public_key(key)
        assert verify_charter_signature(key, message, signature) is vector['valid']
    else:
        with pytest.raises(ValueError):
            validate_charter_public_key(key)


@pytest.mark.parametrize('vector', [v for v in VECTORS if not v['key_valid']], ids=lambda v: v['name'])
def test_reject_weak_keys_at_invite_and_gateway_admission(vector):
    key = bytes.fromhex(vector['public_key_hex'])
    invite = create_invite(generate_identity(), 'group')
    with pytest.raises(ValueError):
        validate_invite({**invite, 'inviter_ik_pk': key})
    assert not valid_gateway(base64url_encode(key), base64url_encode(key_id_from_public_key(key)))


def test_authenticated_ciphertext_does_not_validate_identity_key_forgery():
    issuer = generate_identity()
    invite = create_invite(issuer, 'group')
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    suite = QSP1Suite()
    envelope = create_message(issuer, conversation, 'text', b'forged sender')
    aad = marshal_canonical({key: value for key, value in envelope.items() if key not in ('ciphertext', 'aad_hash')})
    nonce = suite.derive_nonce(conversation['keys']['nonceKey'], envelope['msg_id'])
    inner = unmarshal(suite.decrypt(conversation['keys']['aeadKey'], nonce, envelope['ciphertext'], aad))
    identity = b'\x01' + bytes(31)
    inner.update(sender_ik_pk=identity, sender_kid=key_id_from_public_key(identity), signature=identity + bytes(32))
    envelope['ciphertext'] = suite.encrypt(conversation['keys']['aeadKey'], nonce, marshal_canonical(inner), aad)
    with pytest.raises(ValueError, match='signature'):
        decrypt_message(envelope, conversation)


def test_group_roster_rejects_invalid_key_before_partial_application():
    issuer, member = generate_identity(), generate_identity()
    identity = b'\x01' + bytes(31)
    with pytest.raises(ValueError, match='public key'):
        create_group_add_body(issuer, [member['publicKey'], identity])
    body = parse_group_add_body(create_group_add_body(issuer, [member['publicKey'], issuer['publicKey']]))
    body['new_members'][1].update(public_key=identity, key_id=key_id_from_public_key(identity))
    with pytest.raises(ValueError, match='public key'):
        parse_group_add_body(marshal_canonical(body))
    state = GroupState()
    with pytest.raises(ValueError, match='public key'):
        state.apply_add(body)
    assert state.members == {}
