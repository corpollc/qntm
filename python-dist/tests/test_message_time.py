"""Same signed envelope and expiry boundaries as the TypeScript suite."""
import json
from pathlib import Path

import pytest
from qntm import check_expiry, decrypt_message, unmarshal, validate_envelope

fixtures = Path(__file__).parents[2] / 'client/tests'
fixture = json.loads((fixtures / 'receive-event-vectors.json').read_text())
times = json.loads((fixtures / 'message-time-vectors.json').read_text())
conversation = {
    'id': bytes.fromhex(fixture['conversation_id']), 'currentEpoch': 0,
    'keys': {'aeadKey': bytes.fromhex(fixture['aead_key']), 'nonceKey': bytes.fromhex(fixture['nonce_key'])},
}


def envelope():
    return unmarshal(bytes.fromhex(fixture['vectors'][0]['envelope_cbor']))


@pytest.mark.parametrize('case', times, ids=lambda case: case['name'])
def test_shared_time_policy(case, monkeypatch):
    env = envelope()
    monkeypatch.setattr('qntm.message.time.time', lambda: env[case['relative_to']] + case['offset'])
    assert check_expiry(env) is case['expired']
    for allow_expired, accepted in [(False, case['live']), (True, case['history'])]:
        if accepted:
            assert decrypt_message(env, conversation, allow_expired=allow_expired)['verified']
        else:
            with pytest.raises(ValueError, match='expired|future'):
                decrypt_message(env, conversation, allow_expired=allow_expired)


def test_history_still_authenticates_ciphertext_and_metadata(monkeypatch):
    env = envelope()
    monkeypatch.setattr('qntm.message.time.time', lambda: env['expiry_ts'] + 1)
    tampered = dict(env, ciphertext=bytes([env['ciphertext'][0] ^ 1]) + env['ciphertext'][1:])
    with pytest.raises(Exception):
        decrypt_message(tampered, conversation, allow_expired=True)
    with pytest.raises(ValueError, match='AAD'):
        decrypt_message(dict(env, expiry_ts=env['expiry_ts'] + 1), conversation, allow_expired=True)
    with pytest.raises(ValueError, match='conversation'):
        decrypt_message(env, dict(conversation, id=bytes(16)), allow_expired=True)


@pytest.mark.parametrize('field', ['created_ts', 'expiry_ts'])
@pytest.mark.parametrize('value', [float('nan'), float('inf'), 1.5, 2**53, '1780000000', True, None])
def test_rejects_noninteger_timestamp(field, value):
    with pytest.raises(ValueError, match='timestamp'):
        validate_envelope(dict(envelope(), **{field: value}))
