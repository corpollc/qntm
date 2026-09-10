"""Accepted admission provenance survives delivery expiry, forks and removal."""
import copy

import pytest

from qntm import (
    generate_identity, create_group_session, group_session_from_welcome, group_session_conversation,
    prepare_group_session_addition, prepare_group_session_rekey, receive_group_event,
    restore_group_session, prepare_group_admission_renewal, assert_group_admission_renewal_current,
    prepare_group_welcome_refresh, require_group_recovery, create_group_control_message,
    create_group_remove_body, open_group_welcome, marshal_canonical, create_message, decrypt_message,
    QSP1Suite, unmarshal, check_group_welcome_replay,
    create_group_add_body, create_rekey,
)
from qntm.gate import open_secret, seal_secret
from test_group_session import setup, restart, rotate


def accept(identity, state, operation):
    for envelope in (operation['addition'], operation['rekey']):
        state = receive_group_event(identity, envelope, state)['state']
    return state


def open_for(identity, sender, operation, sequence=100, previous=None):
    opened = open_group_welcome(identity, marshal_canonical(operation['welcomes'][0]),
                                conversation_id=operation['conversation']['id'], inviter_public_key=sender['publicKey'])
    return group_session_from_welcome(identity, opened, sequence, previous), opened


def expected(state, kid):
    entry = state['admissions'][kid.hex()]
    return {key: entry[key] for key in ('addId', 'addDigest')}


def advance(identity, state):
    return receive_group_event(identity, prepare_group_session_rekey(identity, state)['rekey'], state)['state']


def remove(sender, state, target, target_state):
    envelope = create_group_control_message(sender, group_session_conversation(state), 'group_remove', create_group_remove_body([target['keyID']]))
    state = receive_group_event(sender, envelope, state)['state']
    target_state = receive_group_event(target, envelope, target_state)['state']
    rotation = prepare_group_session_rekey(sender, state)['rekey']
    return receive_group_event(sender, rotation, state)['state'], receive_group_event(target, rotation, target_state)['state']


def test_renewal_survives_later_rotations_and_seen_eviction_without_old_keys():
    f = setup()
    before = create_message(f.member, f.conversation, 'text', b'before admission')
    operation = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    state = accept(f.member, f.state, operation)
    proof = copy.deepcopy(state['admissions'][f.late['keyID'].hex()])
    assert proof['completion']['rekeyId'] == operation['rekey']['msg_id'].hex()
    assert state['rekeys'][0]['admissions'][f.late['keyID'].hex()]['completion'] is None
    state = advance(f.member, advance(f.member, state))
    state['seen'] = {}  # Original controls have left the independent bounded dedup cache.
    state = restart(f.member, state)
    renewal = prepare_group_admission_renewal(f.member, state, f.late['publicKey'], expected(state, f.late['keyID']), replay_from_sequence=40)
    assert_group_admission_renewal_current(f.member, state, renewal)
    joined, opened = open_for(f.late, f.member, renewal, 41)
    assert opened['purpose'] == 'renewal'
    assert 'addition_id' not in opened and 'rekey_id' not in opened
    assert joined['admissions'][f.late['keyID'].hex()] == proof
    assert joined['epoch'] == 3 and joined['rekeys'] == []
    with pytest.raises(Exception):
        decrypt_message(before, opened['conversation'])
    reply = create_message(f.late, opened['conversation'], 'text', b'finally opened')
    assert receive_group_event(f.member, reply, state)['message']['inner']['body'] == b'finally opened'
    # Historical proof is not a bootstrap exemption for old-source ciphertext.
    checked = check_group_welcome_replay(joined, opened, 42, [
        {'seq': 41, 'envelope': marshal_canonical(renewal['welcomes'][0])},
        {'seq': 42, 'envelope': marshal_canonical(operation['rekey'])},
    ])
    assert checked['recovery'] is not None
    with pytest.raises(ValueError, match='differs'):
        assert_group_admission_renewal_current(f.member, advance(f.member, state), renewal)


def test_delayed_readmission_renewal_cannot_undo_a_later_removal():
    f = setup()
    first = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    state = accept(f.member, f.state, first)
    late, _ = open_for(f.late, f.member, first)
    state, removed = remove(f.member, state, f.late, late)
    assert removed['removedAtEpoch'] == 1 and f.late['keyID'].hex() not in removed['admissions']
    excluded = create_message(f.member, group_session_conversation(state), 'text', b'during exclusion')
    second = prepare_group_session_addition(f.member, state, [f.late['publicKey']])
    state = accept(f.member, state, second)
    state = advance(f.member, advance(f.member, state))
    assert state['epoch'] == 5
    generic = prepare_group_welcome_refresh(f.member, state, [f.late['publicKey']])
    with pytest.raises(ValueError, match='removal'):
        open_for(f.late, f.member, generic, previous=removed)
    renewal = prepare_group_admission_renewal(f.member, state, f.late['publicKey'], expected(state, f.late['keyID']))
    recovered, opened = open_for(f.late, f.member, renewal, previous=restart(f.late, removed))
    assert not recovered['removed'] and recovered['removedAtEpoch'] == 1
    assert recovered['admissions'][f.late['keyID'].hex()]['sourceEpoch'] == 2
    with pytest.raises(Exception):
        decrypt_message(excluded, opened['conversation'])
    state, removed_again = remove(f.member, state, f.late, recovered)
    assert removed_again['removedAtEpoch'] == 5
    with pytest.raises(ValueError, match='removal'):
        open_for(f.late, f.member, renewal, previous=removed_again)
    with pytest.raises(ValueError, match='unknown or changed'):
        prepare_group_admission_renewal(f.member, state, f.late['publicKey'], expected(recovered, f.late['keyID']))


def test_unknown_or_equal_removal_fence_and_changed_incarnation_fail_closed():
    f = setup()
    operation = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    state = accept(f.member, f.state, operation)
    joined, _ = open_for(f.late, f.member, operation)
    renewal = prepare_group_admission_renewal(f.member, state, f.late['publicKey'], expected(state, f.late['keyID']))
    for fence in (None, 0, 1):
        removed = {**joined, 'removed': True, 'removedAtEpoch': fence}
        with pytest.raises(ValueError, match='removal'):
            open_for(f.late, f.member, renewal, previous=removed)
    wrong = {**expected(state, f.late['keyID']), 'addDigest': '00' * 32}
    with pytest.raises(ValueError, match='changed'):
        prepare_group_admission_renewal(f.member, state, f.late['publicKey'], wrong)
    unknown = {**state, 'admissions': {}}
    with pytest.raises(ValueError, match='unknown'):
        prepare_group_admission_renewal(f.member, unknown, f.late['publicKey'], expected(state, f.late['keyID']))
    with pytest.raises(ValueError, match='differs'):
        assert_group_admission_renewal_current(f.member, unknown, renewal)
    invalid = copy.deepcopy(state)
    invalid['admissions'][f.late['keyID'].hex()]['sourceEpoch'] = False  # False compares equal to 0 in Python.
    with pytest.raises(ValueError):
        assert_group_admission_renewal_current(f.member, invalid, renewal)
    changed = copy.deepcopy(renewal)
    changed['admission']['sourceEpoch'] = False
    with pytest.raises(ValueError):
        assert_group_admission_renewal_current(f.member, state, changed)


def test_new_member_can_renew_another_admission_and_recovery_still_requires_saved_challenge():
    f = setup()
    second = generate_identity()
    first = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    state = accept(f.member, f.state, first)
    later = prepare_group_session_addition(f.member, state, [second['publicKey']])
    state = accept(f.member, state, later)
    second_state, _ = open_for(second, f.member, later)
    assert second_state['admissions'] == state['admissions']
    late, _ = open_for(f.late, f.member, first)
    late = require_group_recovery(late, 10, 'missing_history')
    ordinary = prepare_group_admission_renewal(second, second_state, f.late['publicKey'], expected(second_state, f.late['keyID']))
    with pytest.raises(ValueError, match='challenge'):
        open_for(f.late, second, ordinary, previous=late)
    challenged = prepare_group_admission_renewal(second, second_state, f.late['publicKey'], expected(second_state, f.late['keyID']),
                                                recovery_challenge=bytes.fromhex(late['recovery']['challenge']), replay_from_sequence=10)
    recovered, _ = open_for(f.late, second, challenged, 11, late)
    assert recovered['recovery'] is None and recovered['admissions'] == state['admissions']


def test_rekey_rewind_restores_provenance_and_removes_descendant_admissions():
    f = setup()
    addition = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    pending = receive_group_event(f.member, addition['addition'], f.state)
    low, high = sorted([rotate(f.owner, pending['conversation'], pending['group']), rotate(f.member, pending['conversation'], pending['group'])], key=lambda v: v.envelope['msg_id'])
    state = receive_group_event(f.member, high.envelope, pending['state'])['state']
    second = generate_identity()
    child = prepare_group_session_addition(f.member, state, [second['publicKey']])
    state = accept(f.member, state, child)
    result = receive_group_event(f.member, low.envelope, restart(f.member, state))
    assert result['rewound'] and second['keyID'].hex() not in result['state']['admissions']
    assert result['state']['admissions'][f.late['keyID'].hex()]['completion']['rekeyId'] == low.envelope['msg_id'].hex()
    assert restore_group_session(f.member, result['state']) == result['state']


def test_removed_receiver_rewinds_provenance_without_forgetting_its_removal():
    f = setup()
    low, high = sorted([rotate(f.owner, f.conversation, f.group), rotate(f.member, f.conversation, f.group)], key=lambda v: v.envelope['msg_id'])
    state = receive_group_event(f.member, high.envelope, f.state)['state']
    child = prepare_group_session_addition(f.member, state, [f.late['publicKey']])
    state = accept(f.member, state, child)
    removal = create_group_control_message(f.owner, group_session_conversation(state), 'group_remove', create_group_remove_body([f.member['keyID']]))
    state = receive_group_event(f.member, removal, state)['state']
    assert state['removedAtEpoch'] == 2
    result = receive_group_event(f.member, low.envelope, restart(f.member, state))
    assert result['rewound'] and result['state']['removed'] and result['state']['removedAtEpoch'] == 2
    assert f.late['keyID'].hex() not in result['state']['admissions']
    assert restore_group_session(f.member, result['state']) == result['state']


def test_private_schema_defaults_and_same_epoch_enrichment_do_not_fabricate_provenance():
    f = setup()
    addition = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    joined, welcome = open_for(f.late, f.member, addition)
    older = {key: value for key, value in joined.items() if key not in ('admissions', 'removedAtEpoch')}
    unknown = restore_group_session(f.late, older)
    assert unknown['admissions'] == {} and unknown['removedAtEpoch'] is None
    assert group_session_from_welcome(f.late, welcome, 100, unknown)['admissions'] == joined['admissions']
    conflicting = copy.deepcopy(joined)
    conflicting['admissions'][f.late['keyID'].hex()]['addDigest'] = '00' * 32
    with pytest.raises(ValueError, match='conflicts'):
        group_session_from_welcome(f.late, welcome, 100, conflicting)
    for mutate in (
        lambda value: value['admissions'][f.late['keyID'].hex()].update(completion=None),
        lambda value: value['admissions'][f.late['keyID'].hex()].update(sourceEpoch=True),
        lambda value: value['admissions'].update({'00' * 16: next(iter(value['admissions'].values()))}),
        lambda value: value.update(removedAtEpoch=True),
    ):
        broken = copy.deepcopy(joined)
        mutate(broken)
        with pytest.raises(ValueError):
            restore_group_session(f.late, broken)


def test_legacy_controls_without_signed_source_epoch_do_not_establish_provenance():
    f = setup()
    initial = create_group_session(f.member, f.conversation, f.group, signed_epoch=False)
    legacy_add = create_message(f.owner, f.conversation, 'group_add', create_group_add_body(f.owner, [f.late['publicKey']]))
    added = receive_group_event(f.member, legacy_add, initial)
    assert added['state']['admissions'] == {}
    signed = prepare_group_session_addition(f.member, initial, [f.late['publicKey']])
    pending = receive_group_event(f.member, signed['addition'], initial)
    body, _ = create_rekey(f.owner, pending['conversation'], pending['group'], f.conversation['id'])
    legacy_rekey = create_message(f.owner, pending['conversation'], 'group_rekey', body)
    completed = receive_group_event(f.member, legacy_rekey, pending['state'])['state']
    assert not completed['needsRekey'] and completed['admissions'] == {}
    assert restore_group_session(f.member, completed) == completed
    legacy_remove = create_message(f.owner, f.conversation, 'group_remove', create_group_remove_body([f.member['keyID']]))
    removed = receive_group_event(f.member, legacy_remove, initial)['state']
    assert removed['removed'] and removed['removedAtEpoch'] is None


@pytest.mark.parametrize('mutation', ['recipient_missing', 'pending', 'wrong_digest', 'future', 'extra_field'])
def test_signed_welcome_rejects_malformed_provenance(mutation):
    f = setup()
    operation = prepare_group_session_addition(f.member, f.state, [f.late['publicKey']])
    envelope = copy.deepcopy(operation['welcomes'][0])
    signed = unmarshal(open_secret(f.late['privateKey'], f.member['publicKey'], envelope['ciphertext']))
    kid = f.late['keyID'].hex()
    entry = signed['payload']['admissions'][kid]
    if mutation == 'recipient_missing':
        del signed['payload']['admissions'][kid]
    elif mutation == 'pending':
        entry['rekey_id'] = None
    elif mutation == 'wrong_digest':
        entry['add_hash'] = bytes(32)
    elif mutation == 'future':
        entry['source_epoch'] = 1
    else:
        entry['future_permission'] = True
    signed['signature'] = QSP1Suite().sign(f.member['privateKey'], marshal_canonical(signed['payload']))
    envelope['ciphertext'] = seal_secret(f.member['privateKey'], f.late['publicKey'], marshal_canonical(signed))
    with pytest.raises(ValueError):
        open_group_welcome(f.late, marshal_canonical(envelope), conversation_id=f.conversation['id'], inviter_public_key=f.member['publicKey'])
