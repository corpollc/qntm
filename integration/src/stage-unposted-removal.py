"""Save a real contact removal at the crash window before any control POST.

The fixture only chooses the crash window and short control lifetimes. The
journal, target pin and encrypted controls are production code; nothing is
posted, so acceptance can never be proven for this journal.
"""
import base64
import json
import sys

from qntm import cli
from qntm.group_client import GroupClient
from qntm.message import deserialize_envelope


config_dir, relay_url, conversation_id, target_hex, ttl = sys.argv[1:]
identity = cli._load_identity(config_dir)
client = GroupClient(config_dir, identity, relay_url)
with client._operation_lock(conversation_id):
    record = client.sync(conversation_id)
    operation = client.prepare_change(record, target_hex, 'fixture removal', ttl=int(ttl), removal_ttl=int(ttl))
    assert operation['kind'] == 'remove' and operation['target']['key_id'] == target_hex
    client._save_operation(conversation_id, operation)
    removal, rekey = (deserialize_envelope(base64.b64decode(encoded)) for encoded in operation['controls'])
    print(json.dumps({
        'cursor': record['group_cursor'], 'epoch': record['group_session']['epoch'],
        'removal_id': removal['msg_id'].hex(), 'rekey_id': rekey['msg_id'].hex(),
        'removal_expires_at': removal['expiry_ts'], 'target': operation['target'],
    }))
