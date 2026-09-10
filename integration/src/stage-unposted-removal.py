"""Save a real contact removal at the crash window before any control POST.

The fixture only chooses the crash window and short control lifetimes. The
controls, reducer trial, target pin and journal shape come from the same
production factories the client's own remove action uses; nothing is posted, so
acceptance can never be proven for this journal.
"""
import base64
import json
import sys

from qntm import cli
from qntm.group import create_rekey, create_group_remove_body
from qntm.group_client import GroupClient, _group, _removal_target
from qntm.group_session import create_group_control_message, group_session_conversation, receive_group_event
from qntm.message import serialize_envelope


config_dir, relay_url, conversation_id, target_hex, ttl = sys.argv[1:]
identity = cli._load_identity(config_dir)
client = GroupClient(config_dir, identity, relay_url)
with client._operation_lock(conversation_id):
    record = client.sync(conversation_id)
    state, kid = record['group_session'], bytes.fromhex(target_hex)
    assert _group(state).is_member(kid)
    conversation = group_session_conversation(state)
    removal = create_group_control_message(identity, conversation, 'group_remove', create_group_remove_body([kid], 'fixture removal'), int(ttl))
    applied = receive_group_event(identity, removal, state)
    body, _ = create_rekey(identity, conversation, applied['group'], conversation['id'])
    rekey = create_group_control_message(identity, conversation, 'group_rekey', body, int(ttl))
    trial = state
    for envelope in (removal, rekey):
        trial = receive_group_event(identity, envelope, trial)['state']
    operation = {'kind': 'remove', 'controls': [base64.b64encode(serialize_envelope(e)).decode() for e in (removal, rekey)],
                 'welcomes': [], 'welcomes_sent': 0, 'expected': trial, 'target': _removal_target(state, kid)}
    assert operation['target']['key_id'] == target_hex
    client._save_operation(conversation_id, operation)
    print(json.dumps({
        'cursor': record['group_cursor'], 'epoch': state['epoch'],
        'removal_id': removal['msg_id'].hex(), 'rekey_id': rekey['msg_id'].hex(),
        'removal_expires_at': removal['expiry_ts'], 'target': operation['target'],
    }))
