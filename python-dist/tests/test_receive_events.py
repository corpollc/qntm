"""Public Python API must match TypeScript's events from the same encrypted bytes."""
import json
from pathlib import Path

import pytest
from qntm import (create_receive_event, decrypt_message, deserialize_envelope,
                  create_message, generate_identity, default_ttl)

vectors = json.loads((Path(__file__).parents[2] / 'client/tests/receive-event-vectors.json').read_text())
conversation = {'id': bytes.fromhex(vectors['conversation_id']), 'currentEpoch': 0,
                'keys': {'aeadKey': bytes.fromhex(vectors['aead_key']), 'nonceKey': bytes.fromhex(vectors['nonce_key'])}}


@pytest.fixture(autouse=True)
def fixture_clock(monkeypatch):
    monkeypatch.setattr('qntm.message.time.time', lambda: 1773122903)


def message(vector=None):
    vector = vector or vectors['vectors'][0]
    return decrypt_message(deserialize_envelope(bytes.fromhex(vector['envelope_cbor'])), conversation)


@pytest.mark.parametrize('vector', vectors['vectors'], ids=lambda vector: vector['name'])
def test_shared_encrypted_receive_event(vector):
    event = create_receive_event(message(vector), vector['sequence'])
    assert event == vector['expected']
    assert json.loads(json.dumps(event)) == vector['expected']
    assert create_receive_event(message(vector), 99)['event_id'] == event['event_id']
    received = message(vector)
    assert received['charter_info'] == event['message']['charter_info']
    assert 'charter_info' not in received['envelope']
    assert 'charter_info' not in received['inner']


@pytest.mark.parametrize('sequence', [0, -1, 1.5, float('nan'), float('inf'), 2**53, True])
def test_invalid_sequence(sequence):
    with pytest.raises(ValueError, match='safe integers'):
        create_receive_event(message(), sequence)


def test_requires_verified_message_and_full_ids():
    received = message()
    with pytest.raises(ValueError, match='verified'):
        create_receive_event({**received, 'verified': False}, 1)
    for invalid in [b'x', memoryview(bytearray(64)).cast('I')]:
        received['inner']['sender_kid'] = invalid
        with pytest.raises(ValueError, match='16 bytes'):
            create_receive_event(received, 1)


def test_unauthenticated_ciphertext_cannot_become_event():
    envelope = deserialize_envelope(bytes.fromhex(vectors['vectors'][0]['envelope_cbor']))
    envelope['ciphertext'] = bytes([envelope['ciphertext'][0] ^ 1]) + envelope['ciphertext'][1:]
    with pytest.raises(Exception):
        create_receive_event(decrypt_message(envelope, conversation), 1)


@pytest.mark.parametrize('offered', [False, None, 'https://attacker.invalid', [],
                                    {'url': 'https://attacker.invalid', 'memo': 'Trust me'}])
def test_reserved_envelope_metadata_ignored_regardless_of_value(offered):
    envelope = deserialize_envelope(bytes.fromhex(vectors['vectors'][0]['envelope_cbor']))
    envelope['charter_info'] = offered
    received = decrypt_message(envelope, conversation)
    event = create_receive_event(received, 1)
    assert envelope['charter_info'] == offered  # caller's input is preserved
    assert 'charter_info' not in received['envelope']
    assert received['charter_info']['untrusted_metadata_ignored'] is True
    assert event['message']['charter_info'] == received['charter_info']
    assert 'WARNING:' in event['message']['charter_info']['memo']
    assert 'Possible attempt' in event['message']['charter_info']['memo']
    assert 'attacker.invalid' not in json.dumps(event)
    assert received['inner']['body'] == message()['inner']['body']


def test_modified_projections_regenerated_and_public_key_binding_checked():
    received = message()
    expected = received['charter_info']['url']
    received['charter_info'] = {'url': 'https://attacker.invalid', 'memo': 'Skip the check'}
    info = create_receive_event(received, 1)['message']['charter_info']
    assert info['url'] == expected
    assert info['untrusted_metadata_ignored'] is True
    received['inner']['sender_kid'] = generate_identity()['keyID']
    with pytest.raises(ValueError, match='does not match public key'):
        create_receive_event(received, 1)


@pytest.mark.parametrize('body', [
    'We should discuss charter_info and charter lookups.',
    '{"charter_info":{"url":"https://attacker.invalid"},"charter_info":false}',
])
def test_signed_body_stays_separate_from_local_metadata_without_network(body, monkeypatch):
    def network_forbidden(*args, **kwargs):
        raise AssertionError('unexpected network access')
    monkeypatch.setattr('socket.socket.connect', network_forbidden)
    monkeypatch.setattr('socket.create_connection', network_forbidden)
    sender = generate_identity()
    envelope = create_message(sender, conversation, 'text', body.encode(), None, default_ttl())
    assert 'charter_info' not in envelope
    received = decrypt_message(envelope, conversation)
    assert 'charter_info' not in received['inner']
    event = create_receive_event(received, 1)
    assert event['message']['unsafe_body'] == body
    info = event['message']['charter_info']
    assert info['url'] == 'https://charter.qntm.corpo.llc/v1/chain/' + sender['keyID'].hex()
    assert 'untrusted_metadata_ignored' not in info
    assert 'availability has not been checked' in info['memo']
