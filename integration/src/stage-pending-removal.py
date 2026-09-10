"""Stop a real contact removal after its accepted removal control, before its rekey.

The fixture only chooses the crash window and a short rotation lifetime. The
journal, target pin, encrypted controls, relay transport and replay reducer are
production code; the removal is accepted through authenticated receive.
"""
import base64
import json
import sys

from qntm import cli
from qntm.group_client import GroupClient, _control_accepted
from qntm.message import deserialize_envelope


config_dir, relay_url, conversation_id, target_hex = sys.argv[1:]
identity = cli._load_identity(config_dir)
client = GroupClient(config_dir, identity, relay_url)
with client._operation_lock(conversation_id):
    record = client.sync(conversation_id)
    operation = client.prepare_change(record, target_hex, 'fixture removal', ttl=8)
    assert operation['kind'] == 'remove' and operation['target']['key_id'] == target_hex
    client._save_operation(conversation_id, operation)
    removal, rekey = (base64.b64decode(encoded) for encoded in operation['controls'])
    cli._http_send(relay_url, conversation_id, removal)
    accepted = client.sync(conversation_id)
    assert accepted['group_session']['needsRekey'] is True
    assert target_hex not in accepted['participants']
    assert _control_accepted(accepted, removal) and not _control_accepted(accepted, rekey)
    print(json.dumps({
        'cursor': accepted['group_cursor'], 'epoch': accepted['group_session']['epoch'],
        'removal_id': deserialize_envelope(removal)['msg_id'].hex(),
        'rekey_id': deserialize_envelope(rekey)['msg_id'].hex(),
        'rekey_expires_at': deserialize_envelope(rekey)['expiry_ts'],
        'target': operation['target'],
    }))
