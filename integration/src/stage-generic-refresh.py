"""Save a real founder refresh at the crash window before its first POST.

Only the short signed lifetime and optional older journal shape are fixtures.
The checkpoint, recipient box, signature, and durable journal use production code.
"""
import base64
import json
import sys

from qntm import cli
from qntm.group_client import GroupClient
from qntm.group_session import create_group_session, prepare_group_welcome_refresh
from qntm.identity import key_id_from_public_key
from qntm.message import serialize_envelope


config_dir, relay_url, conversation_id, recipient_hex, challenge_hex, shape = sys.argv[1:]
if shape not in ('current', 'legacy'):
    raise ValueError('Expected current or legacy journal shape')
identity = cli._load_identity(config_dir)
recipient = bytes.fromhex(recipient_hex)
challenge = bytes.fromhex(challenge_hex)
client = GroupClient(config_dir, identity, relay_url)
with client._operation_lock(conversation_id):
    record = client.sync(conversation_id)
    state = record['group_session']
    # The recipient really is the founder; no admission provenance is removed
    # to force generic behavior. The issuing Python member was added normally.
    assert key_id_from_public_key(recipient).hex() not in state['admissions']
    assert identity['keyID'].hex() in state['admissions']
    operation = prepare_group_welcome_refresh(
        identity, state, [recipient], ttl=8,
        recovery_challenge=challenge, replay_from_sequence=record['group_cursor'],
    )
    expected = create_group_session(identity, operation['conversation'], operation['state'],
                                    signed_epoch=state['signedEpoch'], admissions=state['admissions'])
    client._save_operation(conversation_id, {
        'kind': 'refresh', 'controls': [],
        'welcomes': [base64.b64encode(serialize_envelope(w)).decode() for w in operation['welcomes']],
        'welcomes_sent': 0, 'expected': expected,
        **({'recipient': recipient_hex, 'recovery_challenge': challenge_hex} if shape == 'current' else {}),
    })
    print(json.dumps({'expires_at': operation['welcomes'][0]['expiry_ts'],
                      'cursor': record['group_cursor'], 'epoch': state['epoch']}))
