"""Real encrypted group events, restart checkpoints, removal and rekey forks."""
import copy
import json
import time
from types import SimpleNamespace

import pytest
from nacl.exceptions import CryptoError
from qntm import (
    generate_identity, create_invite, derive_conversation_keys, create_conversation, GroupState,
    create_group_genesis_body, parse_group_genesis_body, create_group_add_body, create_group_remove_body,
    create_rekey, apply_rekey, create_message, marshal_canonical, unmarshal,
    create_group_session, restore_group_session, receive_group_event, group_session_conversation,
    assert_group_can_send, create_group_control_message, prepare_group_addition, open_group_welcome,
    GROUP_REKEY_GRACE_SECONDS,
    prepare_group_session_addition, assert_group_addition_accepted,
)


def setup():
    owner, member, late = (generate_identity() for _ in range(3))
    invite = create_invite(owner, 'group')
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    group = GroupState()
    group.apply_genesis(parse_group_genesis_body(create_group_genesis_body('Team', '', owner, [member['publicKey']])))
    conversation['participants'] = group.list_members()
    return SimpleNamespace(owner=owner, member=member, late=late, conversation=conversation, group=group,
                           state=create_group_session(member, conversation, group))


def rotate(sender, conversation, group):
    body, root = create_rekey(sender, conversation, group, conversation['id'])
    envelope = create_group_control_message(sender, conversation, 'group_rekey', body)
    following = copy.deepcopy(conversation)
    following['participants'] = group.list_members()
    apply_rekey(following, root, conversation['currentEpoch'] + 1)
    return SimpleNamespace(envelope=envelope, conversation=following)


def text(sender, conversation):
    return create_message(sender, conversation, 'text', b'hello')


def restart(identity, state):
    return restore_group_session(identity, json.loads(json.dumps(state)))


def test_member_add_and_rekey_survive_restart_and_match_welcome():
    f = setup()
    original = copy.deepcopy(f.state)
    operation = prepare_group_addition(f.member, f.conversation, f.group, [f.late['publicKey']])
    current = receive_group_event(f.member, operation['addition'], f.state)
    assert current['group'].is_member(f.late['keyID'])
    with pytest.raises(ValueError, match='key rotation'):
        assert_group_can_send(f.member, current['state'])
    with pytest.raises(ValueError, match='key rotation'):
        receive_group_event(f.member, text(f.owner, f.conversation), current['state'])
    current = receive_group_event(f.member, operation['rekey'], restart(f.member, current['state']))
    assert current['conversation']['keys'] == operation['conversation']['keys']
    assert_group_can_send(f.member, current['state'])
    assert f.state == original
    welcome = open_group_welcome(f.late, marshal_canonical(operation['welcomes'][0]),
                                 conversation_id=f.conversation['id'], inviter_public_key=f.member['publicKey'])
    newcomer = create_group_session(f.late, welcome['conversation'], welcome['state'])
    assert newcomer['rekeys'] == []
    assert not receive_group_event(f.member, text(f.late, group_session_conversation(newcomer)), current['state'])['duplicate']
    assert receive_group_event(f.member, operation['rekey'], restart(f.member, current['state']))['duplicate']


def test_removal_stays_excluded_across_restart_and_old_key_readmission():
    f = setup()
    removal = create_group_control_message(f.owner, f.conversation, 'group_remove', create_group_remove_body([f.member['keyID']]))
    current = receive_group_event(f.member, removal, f.state)
    assert current['state']['removed']
    rotation = rotate(f.owner, f.conversation, current['group'])
    current = receive_group_event(f.member, rotation.envelope, restart(f.member, current['state']))
    assert current['state']['root'] == f.state['root'] and not current['state']['rekeys']
    with pytest.raises(ValueError, match='removed'):
        assert_group_can_send(f.member, current['state'])
    with pytest.raises(ValueError):
        receive_group_event(f.member, text(f.owner, rotation.conversation), current['state'])
    addition = create_group_control_message(f.owner, f.conversation, 'group_add', create_group_add_body(f.owner, [f.member['publicKey']]))
    current = receive_group_event(f.member, addition, current['state'])
    old_key_rotation = rotate(f.owner, f.conversation, current['group'])
    current = receive_group_event(f.member, old_key_rotation.envelope, current['state'])
    assert current['state']['removed'] and current['state']['root'] == f.state['root']


def test_welcome_release_requires_exact_accepted_add_and_rekey():
    f = setup()
    operation = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    with pytest.raises(ValueError):
        assert_group_addition_accepted(f.member, f.state, operation)
    pending = receive_group_event(f.member, operation['addition'], f.state)
    with pytest.raises(ValueError):
        assert_group_addition_accepted(f.member, pending['state'], operation)
    with pytest.raises(ValueError, match='key rotation'):
        prepare_group_session_addition(f.member, pending['state'], [generate_identity()['publicKey']])
    accepted = receive_group_event(f.member, operation['rekey'], pending['state'])
    assert_group_addition_accepted(f.member, accepted['state'], operation)
    missing = copy.deepcopy(accepted['state'])
    del missing['seen'][operation['addition']['msg_id'].hex()]
    with pytest.raises(ValueError, match='not both'):
        assert_group_addition_accepted(f.member, missing, operation)
    advanced = receive_group_event(f.member, rotate(f.owner, accepted['conversation'], accepted['group']).envelope, accepted['state'])
    with pytest.raises(ValueError, match='differs'):
        assert_group_addition_accepted(f.member, advanced['state'], operation)


def test_unauthorized_and_malformed_controls_never_mutate_state():
    f, outsider = setup(), generate_identity()
    original = copy.deepcopy(f.state)
    cases = [
        create_group_control_message(outsider, f.conversation, 'group_add', create_group_add_body(outsider, [f.late['publicKey']])),
        create_group_control_message(f.owner, f.conversation, 'group_remove', create_group_remove_body([f.owner['keyID']])),
        create_group_control_message(f.owner, f.conversation, 'group_add', create_group_add_body(f.owner, [f.late['publicKey'], f.late['publicKey']])),
        create_group_control_message(f.owner, f.conversation, 'group_add', create_group_add_body(f.member, [f.late['publicKey']])),
        text(outsider, f.conversation),
    ]
    for envelope in cases:
        with pytest.raises(ValueError):
            receive_group_event(f.member, envelope, f.state)
    assert f.state == original
    removed = receive_group_event(f.member,
                                  create_group_control_message(f.owner, f.conversation, 'group_remove', create_group_remove_body([f.member['keyID']])), f.state)
    with pytest.raises(ValueError, match='current member'):
        receive_group_event(f.member, text(f.member, f.conversation), removed['state'])


def test_signed_source_epoch_and_explicit_legacy_migration():
    f = setup()
    body = create_group_add_body(f.owner, [f.late['publicKey']])
    legacy = create_message(f.owner, f.conversation, 'group_add', body)
    with pytest.raises(ValueError, match='signed for this epoch'):
        receive_group_event(f.member, legacy, f.state)
    migrated = create_group_session(f.member, f.conversation, f.group, signed_epoch=False)
    assert receive_group_event(f.member, legacy, migrated)['state']['needsRekey']
    wrong_epoch = create_message(f.owner, f.conversation, 'group_add', marshal_canonical({**unmarshal(body), 'group_epoch': 1}))
    with pytest.raises(ValueError, match='signed for this epoch'):
        receive_group_event(f.member, wrong_epoch, migrated)


def test_rekey_requires_complete_roster():
    f = setup()
    body, _ = create_rekey(f.owner, f.conversation, f.group, f.conversation['id'])
    value = unmarshal(body)
    del value['wrapped_keys'][next(iter(value['wrapped_keys']))]
    envelope = create_group_control_message(f.owner, f.conversation, 'group_rekey', marshal_canonical(value))
    with pytest.raises(ValueError, match='recipients'):
        receive_group_event(f.member, envelope, f.state)


def test_delayed_lower_rekey_rewinds_descendants_and_resumes_winner():
    f = setup()
    low, high = sorted([rotate(f.owner, f.conversation, f.group), rotate(f.member, f.conversation, f.group)], key=lambda candidate: candidate.envelope['msg_id'])
    current = receive_group_event(f.member, high.envelope, f.state)
    losing_child = rotate(f.owner, high.conversation, f.group)
    current = receive_group_event(f.member, losing_child.envelope, current['state'])
    assert current['state']['epoch'] == 2
    winning_child = rotate(f.owner, low.conversation, f.group)
    with pytest.raises((ValueError, CryptoError)):
        receive_group_event(f.member, winning_child.envelope, current['state'])
    current = receive_group_event(f.member, low.envelope, restart(f.member, current['state']))
    assert current['rewound'] and current['state']['epoch'] == 1
    assert current['conversation']['keys'] == low.conversation['keys']
    assert len(current['state']['rekeys']) == 1
    assert losing_child.envelope['msg_id'].hex() not in current['state']['seen']
    with pytest.raises((ValueError, CryptoError)):
        receive_group_event(f.member, text(f.owner, high.conversation), current['state'])
    current = receive_group_event(f.member, winning_child.envelope, current['state'])
    assert current['conversation']['keys'] == winning_child.conversation['keys']
    assert not receive_group_event(f.member, text(f.owner, winning_child.conversation), current['state'])['duplicate']


def test_old_epochs_cannot_deliver_application_events_and_archive_expires(monkeypatch):
    f = setup()
    low, high = sorted([rotate(f.owner, f.conversation, f.group), rotate(f.member, f.conversation, f.group)], key=lambda candidate: candidate.envelope['msg_id'])
    current = receive_group_event(f.member, high.envelope, f.state)
    with pytest.raises(ValueError):
        receive_group_event(f.member, text(f.owner, f.conversation), current['state'])
    saved = restart(f.member, current['state'])
    later = time.time() + GROUP_REKEY_GRACE_SECONDS + 1
    monkeypatch.setattr('qntm.group_session.time.time', lambda: later)
    with pytest.raises(ValueError, match='epoch'):
        receive_group_event(f.member, low.envelope, saved)


def test_checkpoint_identity_schema_and_message_id_conflict():
    f = setup()
    with pytest.raises(ValueError):
        restore_group_session(f.owner, f.state)
    for change in ({'epoch': -1}, {'epoch': True}, {'root': '00'}, {'extra': True}, {'removed': 'false'}, {'snapshot': f.state['snapshot'] + '='}):
        with pytest.raises(ValueError):
            restore_group_session(f.member, {**f.state, **change})
    envelope = text(f.owner, f.conversation)
    current = receive_group_event(f.member, envelope, f.state)
    forged = {**envelope, 'ciphertext': b'\x00' + envelope['ciphertext'][1:]}
    if forged['ciphertext'] == envelope['ciphertext']:
        forged['ciphertext'] = b'\x01' + envelope['ciphertext'][1:]
    with pytest.raises(ValueError, match='Conflicting'):
        receive_group_event(f.member, forged, current['state'])
