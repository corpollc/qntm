"""Stop a real contact addition after selected controls, before welcome delivery.

The fixture only chooses the crash window and a short delivery lifetime. It uses
the production journal, encrypted envelopes, relay transport and replay reducer.
"""
import base64
import json
import sys
import time

from qntm import cli
from qntm.group_client import GroupClient
from qntm.group_session import (
    assert_group_addition_accepted,
    prepare_group_session_addition,
    receive_group_event,
)
from qntm.identity import key_id_from_public_key
from qntm.message import serialize_envelope


config_dir, relay_url, conversation_id, recipient_hex, challenge_hex, *options = sys.argv[1:]
if options not in ([], ['add-only']):
    raise ValueError('Expected optional add-only crash window')
add_only = options == ['add-only']
identity = cli._load_identity(config_dir)
recipient = bytes.fromhex(recipient_hex)
challenge = bytes.fromhex(challenge_hex) if challenge_hex else None
client = GroupClient(config_dir, identity, relay_url)
with client._operation_lock(conversation_id):
    record = client.sync(conversation_id)
    operation = prepare_group_session_addition(
        identity, record['group_session'], [recipient], ttl=8,
        recovery_challenge=challenge, replay_from_sequence=record['group_cursor'],
    )
    expected = record['group_session']
    controls = [operation['addition'], operation['rekey']]
    for envelope in controls:
        expected = receive_group_event(identity, envelope, expected)['state']
    encode = lambda envelope: base64.b64encode(serialize_envelope(envelope)).decode()
    client._save_operation(conversation_id, {
        'kind': 'add', 'controls': [encode(envelope) for envelope in controls],
        'welcomes': [encode(envelope) for envelope in operation['welcomes']],
        'welcomes_sent': 0, 'expected': expected,
        'member': key_id_from_public_key(recipient).hex(),
        **({'recovery_challenge': challenge_hex} if challenge else {}),
    })
    for envelope in controls[:1] if add_only else controls:
        cli._http_send(relay_url, conversation_id, serialize_envelope(envelope))
    accepted = client.sync(conversation_id)
    if add_only:
        assert accepted['group_session']['needsRekey'] is True
        assert accepted['group_session']['admissions'][key_id_from_public_key(recipient).hex()]['completion'] is None
    else:
        assert_group_addition_accepted(identity, accepted['group_session'], operation)
    expiry = operation['welcomes'][0]['expiry_ts']
    assert int(time.time()) < expiry, 'Fixture controls were not accepted before welcome expiry'
    assert accepted['group_operation']['welcomes_sent'] == 0
    print(json.dumps({
        'expires_at': expiry, 'cursor': accepted['group_cursor'],
        'controls': [envelope['msg_id'].hex() for envelope in controls],
        'welcome_id': operation['welcomes'][0]['msg_id'].hex(),
        'rekey_expires_at': operation['rekey']['expiry_ts'],
        'admission': accepted['group_session']['admissions'][key_id_from_public_key(recipient).hex()],
    }))
