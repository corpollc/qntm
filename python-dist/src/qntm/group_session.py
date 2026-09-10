"""Authenticated ordinary-group receive state, matching TypeScript checkpoints.

Hosts persist this private state atomically with cursors and dispatch queues.
It is not network evidence and does not replace accepted gateway governance.
"""
import copy
import re
import time

from .cbor import marshal_canonical, unmarshal
from .crypto import QSP1Suite
from .group import GroupState, apply_rekey, create_rekey
from .group_welcome import _validate_snapshot, prepare_group_addition, _seal_welcome, GROUP_WELCOME_TTL
from .identity import base64url_decode, base64url_encode, validate_identity
from .message import create_message, decrypt_message, serialize_envelope

_suite = QSP1Suite()
_MAX_EPOCH = 0xffffffff
_MAX_SEEN = 8192
GROUP_REKEY_GRACE_SECONDS = 86400
MAX_GROUP_REKEY_CHECKPOINTS = 64
_CONTROLS = {'group_genesis', 'group_add', 'group_remove', 'group_rekey'}


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _uint(value):
    return type(value) is int and 0 <= value <= 9007199254740991


def _hex(value, size):
    return isinstance(value, str) and len(value) == size * 2 and re.fullmatch('[0-9a-f]+', value) is not None


def _fields(value, names):
    return isinstance(value, dict) and set(value) == set(names.split(','))


def _snapshot(encoded):
    _require(isinstance(encoded, str) and len(encoded) <= 65536, 'Invalid saved group snapshot')
    wire = base64url_decode(encoded)
    value = unmarshal(wire)
    _require(base64url_encode(wire) == encoded and wire == marshal_canonical(value), 'Noncanonical saved group snapshot')
    _validate_snapshot(value)
    return value


def _roster(encoded):
    state = GroupState()
    state.apply_genesis(_snapshot(encoded))
    return state


def _encode_roster(state):
    value = state.snapshot()
    _validate_snapshot(value)
    return base64url_encode(marshal_canonical(value))


def _valid_wrapped(value):
    if not isinstance(value, bytes) or len(value) > 256:
        return False
    try:
        wrapped = unmarshal(value)
        return (_fields(wrapped, 'ek_pk,nonce,ct')
                and isinstance(wrapped['ek_pk'], bytes) and len(wrapped['ek_pk']) == 32
                and isinstance(wrapped['nonce'], bytes) and len(wrapped['nonce']) == 24
                and isinstance(wrapped['ct'], bytes) and len(wrapped['ct']) == 48)
    except (ValueError, TypeError, KeyError):
        return False


def create_group_session(identity, conversation, group, *, signed_epoch=True):
    """Use only a trusted local roster or the result of open_group_welcome."""
    validate_identity(identity)
    _require(conversation.get('type') == 'group' and isinstance(conversation.get('id'), bytes)
             and len(conversation['id']) == 16 and _uint(conversation.get('currentEpoch'))
             and conversation['currentEpoch'] <= _MAX_EPOCH, 'Invalid group session context')
    encoded = _encode_roster(group)
    _require(group.is_member(identity['keyID']), 'Local identity is not a current group member')
    _require(sorted(conversation['participants']) == sorted(group.list_members()), 'Group roster differs from conversation')
    root = conversation['keys']['root']
    _require(isinstance(root, bytes) and len(root) == 32, 'Invalid group root')
    aead, nonce = _suite.derive_epoch_keys(root, conversation['id'], conversation['currentEpoch'])
    _require(aead == conversation['keys']['aeadKey'] and nonce == conversation['keys']['nonceKey'], 'Group keys differ from epoch')
    return {'version': 1, 'conversationId': conversation['id'].hex(), 'identityKid': identity['keyID'].hex(),
            'epoch': conversation['currentEpoch'], 'root': root.hex(), 'snapshot': encoded,
            'removed': False, 'needsRekey': False, 'signedEpoch': signed_epoch is not False, 'rekeys': [], 'seen': {}}


def restore_group_session(identity, value):
    """Validate and copy a private JSON checkpoint after restart.

    Validation binds the identity, but does not authenticate a checkpoint
    received from another party. The JSON format is shared with TypeScript.
    """
    validate_identity(identity)
    _require(_fields(value, 'version,conversationId,identityKid,epoch,root,snapshot,removed,needsRekey,signedEpoch,rekeys,seen')
             and type(value['version']) is int and value['version'] == 1
             and _hex(value['conversationId'], 16) and value['identityKid'] == identity['keyID'].hex()
             and _uint(value['epoch']) and value['epoch'] <= _MAX_EPOCH and _hex(value['root'], 32)
             and type(value['removed']) is bool and type(value['needsRekey']) is bool and type(value['signedEpoch']) is bool,
             'Invalid saved group session')
    group = _roster(value['snapshot'])
    _require(value['removed'] or group.is_member(identity['keyID']), 'Saved group omits local identity')
    _require(isinstance(value['rekeys'], list) and len(value['rekeys']) <= MAX_GROUP_REKEY_CHECKPOINTS, 'Invalid rekey archive')
    last = -1
    for frame in value['rekeys']:
        _require(_fields(frame, 'epoch,root,snapshot,messageId,expiresAt') and _uint(frame['epoch'])
                 and last < frame['epoch'] < value['epoch'] and _hex(frame['root'], 32)
                 and _hex(frame['messageId'], 16) and _uint(frame['expiresAt']), 'Invalid rekey checkpoint')
        prior = _snapshot(frame['snapshot'])
        _require(prior['founding_members'][0]['key_id'] == group.snapshot()['founding_members'][0]['key_id'], 'Saved creator changed')
        last = frame['epoch']
    _require(isinstance(value['seen'], dict) and len(value['seen']) <= _MAX_SEEN, 'Invalid group replay checkpoint')
    for mid, event in value['seen'].items():
        _require(_hex(mid, 16) and _fields(event, 'digest,epoch') and _hex(event['digest'], 32)
                 and _uint(event['epoch']) and event['epoch'] <= value['epoch'], 'Invalid saved group event')
    return copy.deepcopy(value)


def group_session_conversation(state):
    """Reconstruct current keys from a trusted checkpoint; no archived keys."""
    group = _roster(state['snapshot'])
    cid, root = bytes.fromhex(state['conversationId']), bytes.fromhex(state['root'])
    aead, nonce = _suite.derive_epoch_keys(root, cid, state['epoch'])
    return {'id': cid, 'type': 'group', 'name': group.group_name, 'participants': group.list_members(),
            'createdAt': group.created_at, 'currentEpoch': state['epoch'],
            'keys': {'root': root, 'aeadKey': aead, 'nonceKey': nonce}}


def assert_group_can_send(identity, state):
    """Membership changes must finish their rekey before application sends."""
    _require(state['identityKid'] == identity['keyID'].hex(), 'Group checkpoint belongs to another identity')
    _require(not state['removed'], 'You have been removed from this group')
    _require(not state['needsRekey'], 'Group membership update awaits key rotation')
    _require(_roster(state['snapshot']).is_member(identity['keyID']), 'Local identity is not a current group member')


def prepare_group_session_addition(identity, state, recipients, ttl=None):
    """Prepare from the authenticated checkpoint; save before publishing."""
    assert_group_can_send(identity, state)
    options = {} if ttl is None else {'ttl': ttl}
    return prepare_group_addition(identity, group_session_conversation(state), _roster(state['snapshot']), recipients, **options)


def prepare_group_welcome_refresh(identity, previous, recipients, ttl=GROUP_WELCOME_TTL):
    """Refresh current keys for members without admission or rotation.

    Hosts finish replay first, save the exact operation and recheck before
    release. Gateway-governed groups use their own authenticated reducer.
    """
    state = restore_group_session(identity, previous)
    assert_group_can_send(identity, state)
    conversation, group = group_session_conversation(state), _roster(state['snapshot'])
    _require(_uint(ttl) and 0 < ttl <= GROUP_WELCOME_TTL, 'Invalid welcome lifetime')
    _require(isinstance(recipients, list) and 0 < len(recipients) <= 128, 'Invalid refresh recipient count')
    members = {member['public_key'] for member in group.snapshot()['founding_members']}
    seen = set()
    for recipient in recipients:
        _require(isinstance(recipient, bytes) and recipient in members, 'Refresh recipient is not a current member')
        _require(recipient not in seen, 'Duplicate refresh recipient')
        seen.add(recipient)
    at = int(time.time())
    return {'conversation': conversation, 'state': group,
            'welcomes': [_seal_welcome(identity, conversation, group, recipient, at, ttl) for recipient in recipients]}


def assert_group_welcome_refresh_current(identity, state, operation):
    """A refresh must still describe accepted keys and roster when released."""
    assert_group_can_send(identity, state)
    _require(state['conversationId'] == operation['conversation']['id'].hex()
             and state['epoch'] == operation['conversation']['currentEpoch']
             and state['root'] == operation['conversation']['keys']['root'].hex()
             and state['snapshot'] == _encode_roster(operation['state']), 'Prepared welcome refresh differs from accepted group state')
    at = int(time.time())
    _require(len(operation['welcomes']) > 0 and all(w['created_ts'] <= at + 600 and w['expiry_ts'] >= at for w in operation['welcomes']),
             'Prepared welcome refresh expired')


def prepare_group_session_rekey(identity, previous, ttl=None):
    """A remaining member can finish rotation; application sends stay blocked."""
    state = restore_group_session(identity, previous)
    # Rotation itself is allowed while membership awaits its new keys.
    assert_group_can_send(identity, {**state, 'needsRekey': False})
    conversation, group = group_session_conversation(state), _roster(state['snapshot'])
    body, _ = create_rekey(identity, conversation, group, conversation['id'])
    rekey = create_group_control_message(identity, conversation, 'group_rekey', body, ttl)
    received = receive_group_event(identity, rekey, state)
    return {'conversation': received['conversation'], 'state': received['group'], 'rekey': rekey}


def assert_group_addition_accepted(identity, state, operation):
    """Require verified acceptance of the exact add/rekey before welcomes.

    A relay POST acknowledgement alone cannot establish accepted group state.
    """
    assert_group_can_send(identity, state)
    _require(state['conversationId'] == operation['conversation']['id'].hex()
             and state['epoch'] == operation['conversation']['currentEpoch']
             and state['root'] == operation['conversation']['keys']['root'].hex()
             and state['snapshot'] == _encode_roster(operation['state']), 'Prepared addition differs from accepted group state')
    for envelope in (operation['addition'], operation['rekey']):
        _require(state['seen'].get(envelope['msg_id'].hex(), {}).get('digest') == _suite.hash(serialize_envelope(envelope)).hex(),
                 'Prepared addition and rekey have not both been accepted')


def create_group_control_message(identity, conversation, body_type, body, ttl=None):
    """Bind a control to its source epoch inside the signed body.

    QSP v1.1's signature does not cover the outer conv_epoch field itself.
    """
    _require(body_type in _CONTROLS, 'Not a group control')
    value = unmarshal(body)
    _require(isinstance(value, dict), 'Invalid group control body')
    options = {} if ttl is None else {'ttl_seconds': ttl}
    return create_message(identity, conversation, body_type,
                          marshal_canonical({**value, 'group_epoch': conversation['currentEpoch']}), **options)


def receive_group_event(identity, envelope, previous):
    """Receive an ordinary-group event without mutating the supplied checkpoint.

    Old roots authenticate only lower-ID competing rekeys, never application
    traffic. A rewind invalidates descendants; hosts replay pending ciphertext.
    Accepted gateways use their own governance reducer.
    """
    validate_identity(identity)
    _require(previous['identityKid'] == identity['keyID'].hex(), 'Group checkpoint belongs to another identity')
    _require(isinstance(envelope.get('conv_id'), bytes) and envelope['conv_id'].hex() == previous['conversationId']
             and isinstance(envelope.get('msg_id'), bytes) and len(envelope['msg_id']) == 16
             and _uint(envelope.get('conv_epoch')) and envelope['conv_epoch'] <= _MAX_EPOCH, 'Invalid group envelope context')
    mid = envelope['msg_id'].hex()
    digest = _suite.hash(serialize_envelope(envelope)).hex()

    def result(state, rewound):
        return {'state': state, 'rewound': rewound, 'conversation': group_session_conversation(state), 'group': _roster(state['snapshot'])}

    if mid in previous['seen']:
        _require(previous['seen'][mid]['digest'] == digest, 'Conflicting group message ID')
        return {**result(previous, False), 'duplicate': True}
    at = int(time.time())
    state = copy.deepcopy(previous)
    state['rekeys'] = [frame for frame in state['rekeys'] if frame['expiresAt'] >= at]
    rewound = envelope['conv_epoch'] < state['epoch']
    source = next((frame for frame in state['rekeys'] if frame['epoch'] == envelope['conv_epoch']), None) if rewound else None
    _require(envelope['conv_epoch'] == state['epoch'] or source and mid < source['messageId'], 'Stale, future or superseded group epoch')
    source_state = {**state, 'epoch': source['epoch'], 'root': source['root'], 'snapshot': source['snapshot']} if source else state
    conversation = group_session_conversation(source_state)
    message = decrypt_message(envelope, conversation)
    body_type, sender = message['inner']['body_type'], message['inner']['sender_kid']
    _require(not rewound or body_type == 'group_rekey', 'Old group epochs cannot deliver application or membership events')
    group = _roster(source_state['snapshot'])
    _require(group.is_member(sender), 'Group sender is not a current member')
    if body_type in _CONTROLS:
        body = unmarshal(message['inner']['body'])
        _require(isinstance(body, dict), 'Invalid group control')
        _require(('group_epoch' not in body and not state['signedEpoch'])
                 or _uint(body.get('group_epoch')) and body['group_epoch'] == envelope['conv_epoch'], 'Group control is not signed for this epoch')
        _require(body_type != 'group_genesis', 'Group genesis is already established')
        if body_type == 'group_add':
            members = body.get('new_members')
            _require(_uint(body.get('added_at')) and isinstance(members, list) and len(members) > 0
                     and group.member_count() + len(members) <= 128, 'Invalid group addition')
            merged = group.snapshot()
            for member in members:
                _require(isinstance(member, dict) and member.get('added_by') == sender and member.get('added_at') == body['added_at']
                         and isinstance(member.get('key_id'), bytes) and not group.is_member(member['key_id']), 'Invalid added member binding')
            merged['founding_members'].extend(members)
            _validate_snapshot(merged)
            group.apply_add(body)
            state['needsRekey'] = True
        elif body_type == 'group_remove':
            members = body.get('removed_members')
            _require(_uint(body.get('removed_at')) and isinstance(body.get('reason'), str) and len(body['reason'].encode()) <= 4096
                     and isinstance(members, list) and 0 < len(members) <= 128, 'Invalid group removal')
            creator, seen = group.snapshot()['founding_members'][0]['key_id'], set()
            for kid in members:
                _require(isinstance(kid, bytes) and len(kid) == 16 and group.is_member(kid)
                         and kid != creator and kid not in seen, 'Invalid removed member')
                seen.add(kid)
            group.apply_remove(body)
            state['needsRekey'] = True
            state['removed'] = state['removed'] or not group.is_member(identity['keyID'])
        else:
            _require(_uint(body.get('new_conv_epoch')) and body['new_conv_epoch'] == envelope['conv_epoch'] + 1
                     and body['new_conv_epoch'] <= _MAX_EPOCH, 'Rekey must advance exactly one epoch')
            wrapped = body.get('wrapped_keys')
            _require(isinstance(wrapped, dict) and sorted(wrapped) == sorted(base64url_encode(kid) for kid in group.list_members())
                     and all(_valid_wrapped(value) for value in wrapped.values()), 'Rekey recipients differ from current membership')
            if not state['removed'] and group.is_member(identity['keyID']):
                root = _suite.unwrap_key_for_recipient(wrapped[base64url_encode(identity['keyID'])], identity['privateKey'], identity['keyID'], conversation['id'])
                _require(len(root) == 32, 'Invalid rekey group root')
                if source:
                    state['rekeys'] = [frame for frame in state['rekeys'] if frame['epoch'] < source['epoch']]
                    state['seen'] = {sid: event for sid, event in state['seen'].items() if event['epoch'] <= source['epoch']}
                state['rekeys'].append({'epoch': conversation['currentEpoch'], 'root': conversation['keys']['root'].hex(),
                                        'snapshot': source_state['snapshot'], 'messageId': mid,
                                        'expiresAt': min(envelope['expiry_ts'], at + GROUP_REKEY_GRACE_SECONDS)})
                state['rekeys'] = state['rekeys'][-MAX_GROUP_REKEY_CHECKPOINTS:]
                apply_rekey(conversation, root, body['new_conv_epoch'])
                state['root'], state['epoch'] = root.hex(), body['new_conv_epoch']
            else:
                state['removed'] = True
            state['needsRekey'] = False
        state['snapshot'] = _encode_roster(group)
    else:
        _require(not body_type.startswith(('gate.', 'gov.')), 'Gateway events require the gateway session reducer')
        assert_group_can_send(identity, state)
    state['seen'][mid] = {'digest': digest, 'epoch': envelope['conv_epoch']}
    if len(state['seen']) > _MAX_SEEN:
        del state['seen'][next(iter(state['seen']))]
    return {**result(state, rewound), 'duplicate': False, 'message': message}
