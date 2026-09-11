"""Private QSP group state, authenticated controls and deterministic rekey replay.

This module stores only in the participant's local qntm conversation record. It
never changes creator authority or accepts old-epoch application messages.
"""
import base64
import copy
from .cbor import unmarshal
from .group import GroupState
from .group_bootstrap import resolve_rekey_candidates, open_current_epoch_invite, group_snapshot
from .identity import key_id_from_public_key
from .message import decrypt_message

GROUP_TYPES = {'group_genesis', 'group_add', 'group_remove', 'group_rekey'}

def crypto(record):
    return {'id':bytes.fromhex(record['id']), 'type':record.get('type','direct'),
            'currentEpoch':record.get('current_epoch',0),
            'participants':[bytes.fromhex(x) for x in record.get('participants',[])],
            'keys':{'root':bytes.fromhex(record['keys']['root']),
                    'aeadKey':bytes.fromhex(record['keys']['aead_key']),
                    'nonceKey':bytes.fromhex(record['keys']['nonce_key'])}}

def save_crypto(record, value):
    record['current_epoch']=value['currentEpoch']
    record['keys']={'root':value['keys']['root'].hex(),'aead_key':value['keys']['aeadKey'].hex(), 'nonce_key':value['keys']['nonceKey'].hex()}

def state_for_record(record, fallback=None):
    if record.get('group_state'):
        return GroupState.from_dict(record['group_state'])
    return copy.deepcopy(fallback) if fallback else GroupState()

def save_state(record, state):
    record['group_state']=state.to_dict()
    record['participants']=[kid.hex() for kid in state.list_members()]
    record['participant_public_keys']=[bytes(m['public_key']).hex() for m in state.members.values()]

def _members(members,sender):
    if not isinstance(members,list) or not 1<=len(members)<=128:
        raise ValueError('Invalid membership list')
    seen=set()
    for row in members:
        if (not isinstance(row,dict) or not isinstance(row.get('public_key'),bytes) or len(row['public_key'])!=32
            or row.get('key_id')!=key_id_from_public_key(row['public_key']) or row.get('role') not in ('admin','member')
            or row.get('added_by')!=sender or type(row.get('added_at')) is not int or row['added_at']<0 or row['key_id'] in seen):
            raise ValueError('Invalid member binding')
        seen.add(row['key_id'])

def apply_control(record, identity, envelope, message, wire, *, fallback=None, allow_expired=False, authorized_control_signer=None):
    """Authenticate authority, mutate the local state, return whether epoch changed."""
    if record.get('type')!='group' or message['inner']['body_type'] not in GROUP_TYPES:
        raise ValueError('Not a group control')
    state=state_for_record(record,fallback)
    inner=message['inner']; kind=inner['body_type']; sender=bytes(inner['sender_kid']); body=unmarshal(inner['body'])
    epoch=envelope['conv_epoch']; current=record.get('current_epoch',0); mid=envelope['msg_id'].hex()
    delegated = authorized_control_signer is not None and inner['sender_ik_pk'] == authorized_control_signer
    if not isinstance(body,dict) or ('group_epoch' in body and (type(body['group_epoch']) is not int or body['group_epoch']!=epoch)) or record.get('group_checkpoint') and body.get('group_epoch')!=epoch:
        raise ValueError('Membership update is not signed for this epoch')
    if epoch!=current:
        if kind!='group_rekey' or epoch>=current:
            raise ValueError('Stale or future group control')
        previous=next((x for x in record.get('rekeys',[]) if x['epoch']==epoch+1),None)
        if not previous or mid>=previous['id']:
            raise ValueError('Superseded rekey')
        old=next((x for x in record.get('epoch_archive',[]) if x['epoch']==epoch and not x.get('fork')),None)
        if not old or not previous.get('source_roster'):
            record['recovery_required']='Restore a fresh current-epoch invitation from the group creator'
            raise ValueError(record['recovery_required'])
        source=crypto({**record,'current_epoch':epoch,'keys':old['keys']})
        roster=GroupState.from_dict(previous['source_roster'])
        winner=resolve_rekey_candidates(identity,source,roster,[wire],allow_expired=allow_expired,authorized_control_signer=bytes.fromhex(previous['control_delegate']) if previous.get('control_delegate') else None)
        if not winner:
            raise ValueError('Invalid competing rekey')
        record.setdefault('epoch_archive',[]).append({'epoch':current,'keys':copy.deepcopy(record['keys']),'fork':True})
        for item in record['epoch_archive']:
            if item['epoch']>=epoch+1:item['fork']=True
        record['control_ids']=list(previous['source_control_ids'])
        record['rekeys']=[x for x in record['rekeys'] if x['epoch']<epoch+1]
        record['rekeys'].append({**previous,'id':mid})
        save_state(record,roster)
        if winner['excluded']:
            record['excluded']=True
        else:
            save_crypto(record,winner['conversation'])
        record.pop('recovery_required',None);record['needs_rekey']=False
        record.setdefault('control_ids',[]).append(mid)
        return True
    if mid in record.get('control_ids',[]):
        raise ValueError('Control already applied')
    if kind=='group_genesis':
        inviter=record.get('inviter_key_id') or (record.get('participants') or [None])[0]
        if current!=0 or state.member_count() or sender.hex()!=inviter:
            raise ValueError('Untrusted or repeated genesis')
        _members(body.get('founding_members'),sender)
        if body['founding_members'][0]['key_id']!=sender or body['founding_members'][0]['role']!='admin':
            raise ValueError('Genesis does not match creator')
        state.apply_genesis(body)
    elif kind=='group_add':
        if not state.is_admin(sender) and not delegated:raise ValueError('Only a group administrator or accepted gateway may add members')
        _members(body.get('new_members'),sender)
        if authorized_control_signer is not None and any(member['public_key'] == authorized_control_signer for member in body['new_members']):raise ValueError('A gateway cannot join its own voting roster')
        if delegated and any(member['role'] != 'member' for member in body['new_members']):raise ValueError('A gateway cannot appoint administrators')
        if state.member_count()+len(body['new_members'])>128 or any(state.is_member(x['key_id']) for x in body['new_members']):
            raise ValueError('Duplicate or excessive membership')
        state.apply_add(body);record['needs_rekey']=True
    elif kind=='group_remove':
        removed=body.get('removed_members')
        if not state.is_admin(sender) and not delegated:raise ValueError('Only a group administrator or accepted gateway may remove members')
        if not isinstance(removed,list) or not 1<=len(removed)<=128 or any(not isinstance(kid,bytes) or not state.is_member(kid) or kid==state.creator for kid in removed):
            raise ValueError('Invalid member removal; replacing the creator requires a successor group')
        state.apply_remove(body);record['needs_rekey']=True
        if identity['keyID'] in removed:record['excluded']=True
    else:
        winner=resolve_rekey_candidates(identity,crypto(record),state,[wire],allow_expired=allow_expired,authorized_control_signer=authorized_control_signer)
        if not winner:raise ValueError('Unauthorized rekey or recipients do not match current membership')
        record.setdefault('rekeys',[]).append({'epoch':current+1,'id':mid,'source_roster':state.to_dict(),'source_control_ids':list(record.get('control_ids',[])),'control_delegate':authorized_control_signer.hex() if authorized_control_signer is not None else None})
        if winner['excluded']:
            record['excluded']=True
        else:
            record.setdefault('epoch_archive',[]).append({'epoch':current,'keys':copy.deepcopy(record['keys'])})
            save_crypto(record,winner['conversation'])
        record['needs_rekey']=False
    save_state(record,state)
    record.setdefault('control_ids',[]).append(mid)
    return kind=='group_rekey'

def decrypt_for_receive(record,envelope):
    current=record.get('current_epoch',0)
    if envelope['conv_epoch']==current:
        return decrypt_message(envelope,crypto(record))
    if envelope['conv_epoch']<current:
        old=next((x for x in record.get('epoch_archive',[]) if x['epoch']==envelope['conv_epoch'] and not x.get('fork')),None)
        if old:
            message=decrypt_message(envelope,crypto({**record,'current_epoch':old['epoch'],'keys':old['keys']}))
            if message['inner']['body_type']=='group_rekey':return message
    raise ValueError('Message not decryptable in current epoch')

def import_current_invite(record,identity,token,*,conversation_id=None,creator_public_key=None):
    joined=open_current_epoch_invite(identity,token,conversation_id=conversation_id,creator_public_key=creator_public_key)
    conv=joined['conversation']; state=joined['state'];winner=joined['rekey_id'].hex()
    if record:
        old_creator=state_for_record(record).creator
        if record.get('type')!='group' or record['id']!=conv['id'].hex() or old_creator is not None and old_creator!=state.creator:
            raise ValueError('Invitation does not match existing creator and conversation')
        if record.get('excluded'):raise ValueError('This participant was removed; use a separately authorized admission')
        if conv['currentEpoch']<record.get('current_epoch',0):raise ValueError('Invitation is older than saved group keys')
        if conv['currentEpoch']==record.get('current_epoch',0):
            if conv['keys']['root'].hex()==record['keys']['root'] and not record.get('recovery_required'):return record
            previous=next((x['id'] for x in record.get('rekeys',[]) if x['epoch']==conv['currentEpoch']),None) or (record.get('group_checkpoint') or {}).get('rekey_id')
            if conv['keys']['root'].hex()!=record['keys']['root'] and (not previous or winner>=previous):raise ValueError('Invitation does not select the canonical lower rekey')
        record.setdefault('epoch_archive',[]).append({'epoch':record.get('current_epoch',0),'keys':copy.deepcopy(record['keys']),'fork':True})
    else:
        record={'id':conv['id'].hex(),'type':'group','name':state.group_name,'created_at':state.created_at}
    save_crypto(record,conv);save_state(record,state)
    record['inviter_key_id']=state.creator.hex();record['inviter_public_key']=joined['creator_public_key'].hex()
    record['group_checkpoint']={'token':token,'epoch':conv['currentEpoch'],'rekey_id':winner}
    record['rekeys']=[];record['control_ids']=[];record['needs_rekey']=False;record.pop('recovery_required',None);record.pop('pending_control',None)
    return record
