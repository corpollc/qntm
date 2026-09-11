"""QSP v1.2 creator-sealed current-epoch group invitations and rekey selection."""
import copy
import time
from .cbor import marshal_canonical, unmarshal
from .crypto import QSP1Suite
from .gate import seal_secret, open_secret
from .identity import base64url_encode, base64url_decode, key_id_from_public_key
from .group import GroupState, parse_group_rekey_body, apply_rekey
from .message import deserialize_envelope, decrypt_message

_suite = QSP1Suite()
_TYPE = 'qntm.group.join'
_MAX_BYTES = 65536
_MAX_AGE = 30*24*60*60

def _bytes(value, size):
    return isinstance(value, bytes) and len(value) == size

def _uint(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 9007199254740991

def _fields(value, names):
    return isinstance(value, dict) and set(value) == set(names.split(','))

def _fail():
    raise ValueError('Invalid current-epoch group invitation')

def _snapshot(value, creator, recipient):
    if (not _fields(value, 'group_name,description,created_at,founding_members') or
        not isinstance(value['group_name'], str) or not isinstance(value['description'], str) or
        len(value['group_name'].encode()) > 256 or len(value['description'].encode()) > 4096 or
        not _uint(value['created_at']) or not isinstance(value['founding_members'], list) or
        not 1 <= len(value['founding_members']) <= 128):
        _fail()
    seen, included, previous = set(), False, None
    for index, member in enumerate(value['founding_members']):
        if (not _fields(member, 'key_id,public_key,role,added_at,added_by') or
            not _bytes(member['key_id'], 16) or not _bytes(member['public_key'], 32) or
            member['key_id'] != key_id_from_public_key(member['public_key']) or
            not _bytes(member['added_by'], 16) or not _uint(member['added_at']) or
            member['role'] not in ('admin','member')):
            _fail()
        if member['key_id'] in seen:
            _fail()
        seen.add(member['key_id'])
        if index == 0 and (member['public_key'] != creator or member['role'] != 'admin'):
            _fail()
        if index > 1 and previous is not None and member['key_id'] <= previous:
            _fail()
        if index > 0:
            previous = member['key_id']
        included |= member['public_key'] == recipient
    if not included:
        raise ValueError('Invitation recipient has not been admitted to this group')
    return value

def group_snapshot(state):
    keys = sorted(state.members, key=lambda kid:(kid != state.creator, kid))
    return {'group_name':state.group_name,'description':state.description,'created_at':state.created_at,
            'founding_members':[copy.deepcopy(state.members[key]) for key in keys]}

def _unsigned(token):
    return {k:token[k] for k in ('v','type','creator_ik_pk','recipient_ik_pk','sealed')}

def _parse(token):
    from urllib.parse import urlparse
    fragment = urlparse(token).fragment if '://' in token else token
    if not fragment or len(fragment) > (_MAX_BYTES*4+2)//3:
        _fail()
    raw = base64url_decode(fragment)
    if not 1 <= len(raw) <= _MAX_BYTES:
        _fail()
    value = unmarshal(raw)
    if (not _fields(value, 'v,type,creator_ik_pk,recipient_ik_pk,sealed,signature') or
        value['v'] != 1 or isinstance(value['v'], bool) or value['type'] != _TYPE or
        not _bytes(value['creator_ik_pk'],32) or not _bytes(value['recipient_ik_pk'],32) or
        not _bytes(value['signature'],64) or not isinstance(value['sealed'],bytes) or not value['sealed']):
        _fail()
    return value

def is_current_epoch_invite(token):
    try:
        _parse(token)
        return True
    except Exception:
        return False

def inspect_current_epoch_invite(token):
    value=_parse(token)
    if not _suite.verify(value['creator_ik_pk'],marshal_canonical(_unsigned(value)),value['signature']):
        raise ValueError('Invalid group invitation signature')
    return {'creator_public_key':value['creator_ik_pk'],'recipient_public_key':value['recipient_ik_pk']}

def create_current_epoch_invite(identity, conversation, state, recipient, rekey_id, issued_at=None, ttl=_MAX_AGE):
    issued_at = int(time.time()) if issued_at is None else issued_at
    if (conversation['type'] != 'group' or state.creator != identity['keyID'] or not state.is_admin(identity['keyID'])):
        raise ValueError('Only the existing group creator can issue a current-epoch invitation')
    epoch = conversation['currentEpoch']
    if (not _uint(epoch) or not 1 <= epoch <= 0xffffffff or not _bytes(conversation['keys']['root'],32) or
        not _bytes(conversation['id'],16) or not _bytes(recipient,32) or not _bytes(rekey_id,16) or
        not _uint(issued_at) or not _uint(ttl) or not 1 <= ttl <= _MAX_AGE):
        _fail()
    roster = _snapshot(group_snapshot(state), identity['publicKey'], recipient)
    plain = marshal_canonical({'v':1,'conv_id':conversation['id'],'conv_epoch':epoch,
        'group_key':conversation['keys']['root'],'rekey_id':rekey_id,'group_state':roster,
        'issued_at':issued_at,'expires_at':issued_at+ttl})
    if len(plain) > 49152:
        _fail()
    value = {'v':1,'type':_TYPE,'creator_ik_pk':identity['publicKey'],'recipient_ik_pk':recipient,
             'sealed':seal_secret(identity['privateKey'],recipient,plain)}
    value['signature'] = _suite.sign(identity['privateKey'],marshal_canonical(value))
    raw = marshal_canonical(value)
    if len(raw) > _MAX_BYTES:
        _fail()
    return base64url_encode(raw)

def open_current_epoch_invite(identity, token, *, conversation_id=None, creator_public_key=None, at=None, allow_expired=False):
    at = int(time.time()) if at is None else at
    outer = _parse(token)
    if outer['recipient_ik_pk'] != identity['publicKey']:
        raise ValueError('This invitation is sealed to another participant')
    if creator_public_key is not None and creator_public_key != outer['creator_ik_pk']:
        raise ValueError('Invitation creator does not match this workspace')
    if not _suite.verify(outer['creator_ik_pk'],marshal_canonical(_unsigned(outer)),outer['signature']):
        raise ValueError('Invalid group invitation signature')
    raw = open_secret(identity['privateKey'],outer['creator_ik_pk'],outer['sealed'])
    if len(raw) > 49152:
        _fail()
    plain = unmarshal(raw)
    if (not _fields(plain,'v,conv_id,conv_epoch,group_key,rekey_id,group_state,issued_at,expires_at') or
        plain['v'] != 1 or isinstance(plain['v'],bool) or not _bytes(plain['conv_id'],16) or
        not _uint(plain['conv_epoch']) or not 1 <= plain['conv_epoch'] <= 0xffffffff or
        not _bytes(plain['group_key'],32) or not _bytes(plain['rekey_id'],16) or
        not _uint(plain['issued_at']) or not _uint(plain['expires_at']) or plain['issued_at'] > at+300 or
        plain['expires_at'] <= plain['issued_at'] or plain['expires_at']-plain['issued_at'] > _MAX_AGE):
        _fail()
    if plain['expires_at'] <= at and not allow_expired:
        raise ValueError('Current-epoch invitation expired; request a fresh invitation from the creator')
    if conversation_id is not None and conversation_id != plain['conv_id']:
        raise ValueError('Invitation belongs to a different workspace')
    roster = _snapshot(plain['group_state'],outer['creator_ik_pk'],identity['publicKey'])
    state = GroupState(); state.apply_genesis(roster)
    aead, nonce = _suite.derive_epoch_keys(plain['group_key'],plain['conv_id'],plain['conv_epoch'])
    return {'conversation':{'id':plain['conv_id'],'type':'group','name':state.group_name,
        'keys':{'root':plain['group_key'],'aeadKey':aead,'nonceKey':nonce},'participants':state.list_members(),
        'createdAt':roster['created_at'],'currentEpoch':plain['conv_epoch']},'state':state,
        'creator_public_key':outer['creator_ik_pk'],'rekey_id':plain['rekey_id'],
        'issued_at':plain['issued_at'],'expires_at':plain['expires_at']}

def resolve_rekey_candidates(identity, source, roster, wires, *, allow_expired=False, authorized_control_signer=None):
    """Select the lowest authorized signed ID, then unwrap only that winner."""
    if source['type'] != 'group' or not _uint(source['currentEpoch']):
        raise ValueError('Invalid rekey source context')
    if len(wires) > 512:
        raise ValueError('Rekey candidate limit exceeded')
    recipients = sorted(base64url_encode(kid) for kid in roster.list_members())
    if not 1 <= len(recipients) <= 128:
        raise ValueError('Invalid rekey roster')
    winner = None
    for wire in wires:
        try:
            if not 1 <= len(wire) <= 65536:
                continue
            envelope = deserialize_envelope(wire)
            if envelope['conv_epoch'] != source['currentEpoch'] or envelope['conv_id'] != source['id'] or (not allow_expired and envelope['expiry_ts'] <= time.time()):
                continue
            message = decrypt_message(envelope,source)
            if not message['verified'] or message['inner']['body_type'] != 'group_rekey' or (not roster.is_member(message['inner']['sender_kid']) and (authorized_control_signer is None or message['inner']['sender_ik_pk'] != authorized_control_signer)):
                continue
            body = parse_group_rekey_body(message['inner']['body'])
            if (type(body['new_conv_epoch']) is not int or body['new_conv_epoch'] != source['currentEpoch']+1 or
                ('group_epoch' in body and (type(body['group_epoch']) is not int or body['group_epoch'] != source['currentEpoch'])) or
                not isinstance(body['wrapped_keys'],dict) or sorted(body['wrapped_keys']) != recipients or
                any(not isinstance(value,bytes) for value in body['wrapped_keys'].values())):
                continue
            if winner is None or envelope['msg_id'] < winner[0]['msg_id']:
                winner = envelope, body['wrapped_keys']
        except Exception:
            continue
    if winner is None:
        return None
    envelope, wrapped = winner
    mine = wrapped.get(base64url_encode(identity['keyID']))
    if mine is None:
        return {'envelope':envelope,'conversation':None,'excluded':True}
    root = _suite.unwrap_key_for_recipient(mine,identity['privateKey'],identity['keyID'],source['id'])
    if len(root) != 32:
        raise ValueError('Canonical rekey has an invalid group key')
    conversation = copy.deepcopy(source)
    conversation['participants'] = roster.list_members()
    apply_rekey(conversation,root,source['currentEpoch']+1)
    return {'envelope':envelope,'conversation':conversation,'excluded':False}
