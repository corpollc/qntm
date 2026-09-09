"""Public Python API must match TypeScript's events from the same encrypted bytes."""
import json
from pathlib import Path

import pytest
from qntm import create_receive_event, decrypt_message, deserialize_envelope

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
