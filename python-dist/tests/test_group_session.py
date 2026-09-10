"""Real signed group state: ordering, restart, authority, late join and retries."""
import base64
from copy import deepcopy
from types import SimpleNamespace
import pytest
from qntm import cli
from qntm.group_session import crypto,save_crypto,save_state,state_for_record,import_current_invite
from qntm.group_bootstrap import create_current_epoch_invite
from qntm.group import GroupState,create_group_genesis_body,parse_group_genesis_body,create_rekey,apply_rekey,create_group_add_body,create_group_remove_body
from qntm.identity import generate_identity
from qntm.invite import create_invite,create_conversation,derive_conversation_keys
from qntm.message import create_message,serialize_envelope,deserialize_envelope,decrypt_message


def setup(tmp_path):
    owner,member,late=(generate_identity() for _ in range(3))
    invite=create_invite(owner,'group');conv=create_conversation(invite,derive_conversation_keys(invite))
    state=GroupState();state.apply_genesis(parse_group_genesis_body(create_group_genesis_body('Company','',owner,[member['publicKey']])))
    record={'id':conv['id'].hex(),'type':'group','name':'Company','inviter_key_id':owner['keyID'].hex()}
    save_crypto(record,conv);save_state(record,state)
    cli._save_identity(str(tmp_path),member);cli._save_conversations(str(tmp_path),[record])
    return owner,member,late,record,state

def wire(sender,record,kind,body):
    env=create_message(sender,crypto(record),kind,body)
    return {'envelope_b64':base64.b64encode(serialize_envelope(env)).decode(),'seq':1}

def rekey(sender,record,state):
    conv=crypto(record);body,root=create_rekey(sender,conv,state,conv['id'])
    event=wire(sender,record,'group_rekey',body)
    apply_rekey(conv,root,conv['currentEpoch']+1)
    updated=deepcopy(record);save_crypto(updated,conv)
    return event,updated

def mid(event):return deserialize_envelope(base64.b64decode(event['envelope_b64']))['msg_id']
def receive(path,identity,record,events,seq):
    return cli._process_received_messages(str(path),identity,[record],record,[{**event,'seq':seq-len(events)+index+1} for index,event in enumerate(events)],seq)


def test_delayed_lower_winner_rewinds_descendants_then_replays_winning_branch(tmp_path):
    owner,member,_,original,state=setup(tmp_path)
    candidates=sorted([rekey(owner,original,state),rekey(member,original,state)],key=lambda x:mid(x[0]))
    (low,winning),(high,losing)=candidates
    loser_next,losing2=rekey(owner,losing,state)
    winner_next,winning2=rekey(owner,winning,state)
    assert len(receive(tmp_path,member,original,[high,loser_next],2))==2
    # Winning-branch traffic precedes delayed evidence; it remains encrypted locally.
    text=wire(owner,winning2,'text',b'canonical after restart')
    receive(tmp_path,member,original,[winner_next,text],4)
    assert len(cli._load_conversations(str(tmp_path))[0]['waiting_envelopes'])==2
    out=receive(tmp_path,member,original,[low],5)
    fresh=cli._load_conversations(str(tmp_path))[0]
    assert fresh['keys']==winning2['keys'] and fresh['current_epoch']==2
    assert any(row.get('unsafe_body')=='canonical after restart' for row in out)
    assert not fresh['waiting_envelopes']
    from qntm.watch import delivery_events
    deliveries=delivery_events(str(tmp_path),original['id'])
    recovered=next((order,event) for order,event in deliveries if event['data']['message'].get('unsafe_body')=='canonical after restart')
    assert recovered[1]['data']['sequence']==4 and recovered[0]>5
    assert sorted(order for order,_ in deliveries)==[order for order,_ in deliveries]
    assert len(cli._load_history(str(tmp_path),original['id']))==5
    # Losing history is retained but a new old-epoch text cannot become live again.
    assert receive(tmp_path,member,original,[wire(owner,losing,'text',b'old branch')],6)==[]
    assert len(receive(tmp_path,member,original,[wire(owner,winning2,'text',b'continued')],7))==1


def test_membership_requires_admin_and_signed_epoch(tmp_path):
    owner,member,late,record,state=setup(tmp_path)
    unauthorized=wire(member,record,'group_add',create_group_add_body(member,[late['publicKey']]))
    assert receive(tmp_path,member,record,[unauthorized],1)==[]
    assert late['keyID'].hex() not in cli._load_conversations(str(tmp_path))[0]['participants']
    impossible=wire(owner,record,'group_remove',create_group_remove_body([owner['keyID']]))
    assert receive(tmp_path,member,record,[impossible],2)==[]


def test_late_join_has_current_keys_only_and_continues_after_removal(tmp_path):
    owner,member,late,record,state=setup(tmp_path)
    old=wire(owner,record,'text',b'earlier private history')
    state.apply_add(__import__('qntm.cbor',fromlist=['unmarshal']).unmarshal(create_group_add_body(owner,[late['publicKey']])))
    event,current=rekey(owner,record,state)
    token=create_current_epoch_invite(owner,crypto(current),state,late['publicKey'],mid(event))
    joined=import_current_invite(None,late,token,conversation_id=bytes.fromhex(record['id']),creator_public_key=owner['publicKey'])
    assert joined['current_epoch']==1 and not joined.get('epoch_archive') and not joined.get('invite_token')
    cli._save_conversations(str(tmp_path),[joined]);cli._save_identity(str(tmp_path),late)
    assert receive(tmp_path,late,joined,[old],1)==[]
    remove=wire(owner,current,'group_remove',create_group_remove_body([member['keyID']]))
    state.apply_remove({'removed_members':[member['keyID']]})
    rotation,updated=rekey(owner,current,state)
    out=receive(tmp_path,late,joined,[remove,rotation,wire(owner,updated,'text',b'new work')],4)
    assert out[-1]['unsafe_body']=='new work'
    assert member['keyID'].hex() not in cli._load_conversations(str(tmp_path))[0]['participants']
    assert len(cli._load_conversations(str(tmp_path))[0]['epoch_archive'])==1


def test_cli_control_retry_keeps_identical_wire_and_rotates_after_admission(tmp_path,monkeypatch):
    owner,member,late,record,state=setup(tmp_path)
    cli._save_identity(str(tmp_path),owner)
    attempted=[]
    def fail(url,cid,raw):attempted.append(raw);raise OSError('offline')
    monkeypatch.setattr(cli,'_http_send',fail)
    with pytest.raises(OSError):cli._publish_group_control(str(tmp_path),'http://relay',owner,record['id'],'group_add',create_group_add_body(owner,[late['publicKey']]))
    fresh=cli._load_conversations(str(tmp_path))[0]
    assert fresh['needs_rekey'] and fresh['pending_control']
    monkeypatch.setattr(cli,'_http_send',lambda url,cid,raw:attempted.append(raw) or {'seq':1})
    cli._retry_group_control(str(tmp_path),'http://relay',record['id'])
    assert attempted[0]==attempted[1]
    cli._rotate_group(str(tmp_path),'http://relay',owner,record['id'])
    fresh=cli._load_conversations(str(tmp_path))[0]
    assert fresh['current_epoch']==1 and not fresh['needs_rekey'] and not fresh.get('pending_control')
    assert late['keyID'].hex() in fresh['participants']


def test_rotated_cli_invitation_stays_recipient_bound_without_a_legacy_link(tmp_path, monkeypatch):
    # Reconciliation with upstream fragment URLs must not advertise a legacy
    # hosted-client URL for a sealed current-epoch token.
    from qntm.group_bootstrap import inspect_current_epoch_invite, open_current_epoch_invite
    owner, member, _, record, state = setup(tmp_path)
    event, current = rekey(owner, record, state)
    current['group_checkpoint'] = {'rekey_id': mid(event).hex()}
    cli._save_identity(str(tmp_path), owner)
    cli._save_conversations(str(tmp_path), [current])
    observed = []
    monkeypatch.setattr(cli, '_output', lambda kind, value: observed.append((kind, value)))
    cli.cmd_convo_invite(SimpleNamespace(config_dir=str(tmp_path), conv=record['id'], recipient=member['publicKey'].hex()))
    kind, result = observed[0]
    assert kind == 'convo.invite' and result['invite_link'] is None
    token = result['invite_token']
    assert inspect_current_epoch_invite(token)['recipient_public_key'] == member['publicKey']
    opened = open_current_epoch_invite(member, token, conversation_id=bytes.fromhex(record['id']), creator_public_key=owner['publicKey'])
    assert opened['conversation']['currentEpoch'] == 1


def test_legacy_bearer_hello_does_not_grant_control_or_post_rotation_membership(tmp_path):
    owner, member, outsider, record, state = setup(tmp_path)
    out = receive(tmp_path, member, record, [wire(outsider, record, 'text', b'legacy invitation hello')], 1)
    assert out[0]['unsafe_body'] == 'legacy invitation hello'
    learned = cli._load_conversations(str(tmp_path))[0]
    assert outsider['keyID'].hex() in learned['participants']
    assert not state_for_record(learned).is_member(outsider['keyID'])
    assert state_for_record(learned).creator == owner['keyID']
    invalid_control = wire(outsider, record, 'group_add', create_group_add_body(outsider, [generate_identity()['publicKey']]))
    assert receive(tmp_path, member, learned, [invalid_control], 2) == []
    rotation, current = rekey(owner, learned, state)
    receive(tmp_path, member, learned, [rotation], 3)
    # Even possession of current keys does not authorize an unrostered sender
    # after rotation. An old bearer invitation cannot bypass that boundary.
    assert receive(tmp_path, member, current, [wire(outsider, current, 'text', b'not admitted')], 4) == []
    assert receive(tmp_path, member, current, [wire(outsider, record, 'text', b'old keys')], 5) == []


def test_typescript_legacy_bearer_hello_and_control_boundary(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from qntm.invite import invite_from_url
    fixture = json.loads((Path(__file__).parents[2] / 'client/tests/legacy-bearer-typescript.json').read_text())
    monkeypatch.setattr('time.time', lambda: fixture['at'] + 1)
    owner = {key: bytes.fromhex(value) for key, value in fixture['owner'].items()}
    invitation = invite_from_url(fixture['invite_token'])
    conversation = create_conversation(invitation, derive_conversation_keys(invitation))
    record = {'id': conversation['id'].hex(), 'type': 'group', 'inviter_key_id': owner['keyID'].hex(), 'participants': [owner['keyID'].hex()]}
    save_crypto(record, conversation)
    cli._save_identity(str(tmp_path), owner)
    cli._save_conversations(str(tmp_path), [record])
    events = [{'envelope_b64': fixture[key]} for key in ('genesis', 'hello', 'forbidden_control')]
    output = receive(tmp_path, owner, record, events, 3)
    assert [event['body_type'] for event in output] == ['group_genesis', 'text']
    assert output[-1]['unsafe_body'] == 'Legacy bearer hello' and output[-1]['verified']
    saved = cli._load_conversations(str(tmp_path))[0]
    assert fixture['peer_key_id'] in saved['participants']
    assert cli._load_participant_public_keys(str(tmp_path), record['id'])[fixture['peer_key_id']].hex() == fixture['peer_public_key']
    assert state_for_record(saved).member_count() == 1
    assert state_for_record(saved).creator == owner['keyID']


def test_rejected_late_rekey_preserves_required_recovery_without_partial_state(tmp_path):
    owner, member, _, original, state = setup(tmp_path)
    candidates = sorted([rekey(owner, original, state), rekey(member, original, state)], key=lambda item: mid(item[0]))
    (low, _), (high, _) = candidates
    assert receive(tmp_path, member, original, [high], 1)[0]['body_type'] == 'group_rekey'
    saved = cli._load_conversations(str(tmp_path))[0]
    saved['rekeys'][0].pop('source_roster')
    cli._save_conversations(str(tmp_path), [saved])
    before_keys = deepcopy(saved['keys'])
    assert receive(tmp_path, member, saved, [low], 2) == []
    after = cli._load_conversations(str(tmp_path))[0]
    assert after['recovery_required']
    assert after['keys'] == before_keys and after['group_state'] == saved['group_state']
