"""Missing history cannot silently preserve permission to use stale group keys."""
import copy

import pytest

from qntm import (
    generate_identity, create_invite, create_conversation, derive_conversation_keys, GroupState,
    create_group_genesis_body, parse_group_genesis_body, create_group_session, prepare_group_session_addition,
    receive_group_event, prepare_group_welcome_refresh, open_group_welcome, marshal_canonical,
    check_group_replay_coverage, restore_group_session, group_session_from_welcome, assert_group_can_send,
    prepare_group_session_rekey, create_group_control_message, create_group_remove_body, create_message,
    check_expired_group_control,
)


def setup():
    owner, peer = generate_identity(), generate_identity()
    invite = create_invite(owner, 'group')
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    group = GroupState()
    group.apply_genesis(parse_group_genesis_body(create_group_genesis_body('Recovery team', '', owner, [])))
    conversation['participants'] = group.list_members()
    initial = create_group_session(owner, conversation, group)
    addition = prepare_group_session_addition(owner, initial, [peer['publicKey']])
    state = receive_group_event(owner, addition['addition'], initial)['state']
    state = receive_group_event(owner, addition['rekey'], state)['state']
    pin = {'conversation_id': conversation['id'], 'inviter_public_key': owner['publicKey']}
    welcome = open_group_welcome(peer, marshal_canonical(addition['welcomes'][0]), **pin)
    return owner, peer, state, welcome, pin, group_session_from_welcome(peer, welcome, 3)


def test_coverage_detects_every_omission_and_persists_across_later_replay():
    _, peer, _, _, _, initial = setup()
    for sequences, boundary in [([5, 6], 4), ([4, 6], 5), ([4, 5], 6), ([], 6)]:
        blocked = check_group_replay_coverage(initial, 3, 6, sequences)
        assert blocked['recovery']['afterSequence'] == boundary and blocked['recovery']['reason'] == 'missing_history'
        assert len(bytes.fromhex(blocked['recovery']['challenge'])) == 32
        assert restore_group_session(peer, copy.deepcopy(blocked))['recovery'] == blocked['recovery']
        assert check_group_replay_coverage(blocked, 6, 7, [7])['recovery'] == blocked['recovery']
    assert check_group_replay_coverage(initial, 3, 6, [2, 6, 4, 5, 5])['recovery'] is None
    assert initial['recovery'] is None
    for start, head, seqs in [(3, 2, []), (3, 4, [5]), (0, 1, [0]), (0, 1, [True])]:
        with pytest.raises(ValueError, match='coverage'):
            check_group_replay_coverage(initial, start, head, seqs)


def test_gap_blocks_producers_and_events_until_a_later_welcome():
    owner, peer, owner_state, welcome, pin, initial = setup()
    blocked = check_group_replay_coverage(initial, 3, 5, [5])
    for operation in [lambda: assert_group_can_send(peer, blocked),
                      lambda: prepare_group_session_addition(peer, blocked, [generate_identity()['publicKey']]),
                      lambda: prepare_group_session_rekey(peer, blocked),
                      lambda: prepare_group_welcome_refresh(peer, blocked, [owner['publicKey']]),
                      lambda: receive_group_event(peer, create_message(owner, welcome['conversation'], 'text', b'after gap'), blocked)]:
        with pytest.raises(ValueError, match='incomplete'):
            operation()
    with pytest.raises(ValueError, match='predates'):
        group_session_from_welcome(peer, welcome, 3, blocked)
    with pytest.raises(ValueError, match='challenge'):
        group_session_from_welcome(peer, welcome, 6, blocked)  # Reposted ciphertext is not fresh.
    wrong = prepare_group_welcome_refresh(owner, owner_state, [peer['publicKey']], recovery_challenge=bytes(32))
    with pytest.raises(ValueError, match='challenge'):
        group_session_from_welcome(peer, open_group_welcome(peer, marshal_canonical(wrong['welcomes'][0]), **pin), 6, blocked)
    refresh = prepare_group_welcome_refresh(owner, owner_state, [peer['publicKey']], recovery_challenge=bytes.fromhex(blocked['recovery']['challenge']))
    opened = open_group_welcome(peer, marshal_canonical(refresh['welcomes'][0]), **pin)
    recovered = group_session_from_welcome(peer, opened, 6, blocked)
    assert_group_can_send(peer, recovered)
    assert recovered['root'] == initial['root'] and recovered['rekeys'] == [] and recovered['recovery'] is None
    assert check_group_replay_coverage(recovered, 6, 8, [8])['recovery']['afterSequence'] == 7
    later_gap = check_group_replay_coverage(blocked, 5, 7, [7])
    assert later_gap['recovery']['challenge'] != blocked['recovery']['challenge']
    with pytest.raises(ValueError, match='challenge'):
        group_session_from_welcome(peer, opened, 8, later_gap)


def test_expired_control_requires_recovery_without_applying_it(monkeypatch):
    owner, peer, _, welcome, _, initial = setup()
    removal = create_group_control_message(owner, welcome['conversation'], 'group_remove', create_group_remove_body([peer['keyID']]), 1)
    expired_text = create_message(owner, welcome['conversation'], 'text', b'old', ttl_seconds=1)
    forged = create_group_control_message(generate_identity(), welcome['conversation'], 'group_remove', create_group_remove_body([peer['keyID']]), 1)
    at = removal['expiry_ts'] + 2
    monkeypatch.setattr('time.time', lambda: at)
    blocked = check_expired_group_control(peer, initial, removal, 4)
    assert blocked['recovery']['afterSequence'] == 4 and blocked['recovery']['reason'] == 'expired_control'
    assert len(bytes.fromhex(blocked['recovery']['challenge'])) == 32
    assert not blocked['removed'] and blocked['snapshot'] == initial['snapshot']
    assert check_expired_group_control(peer, initial, expired_text, 4)['recovery'] is None
    assert check_expired_group_control(peer, initial, forged, 4)['recovery'] is None


def test_welcome_recovery_cannot_bypass_removal_or_pending_rotation():
    owner, peer, owner_state, _, pin, initial = setup()
    refresh = prepare_group_welcome_refresh(owner, owner_state, [peer['publicKey']])
    opened = open_group_welcome(peer, marshal_canonical(refresh['welcomes'][0]), **pin)
    with pytest.raises(ValueError, match='removal'):
        group_session_from_welcome(peer, opened, 6, {**initial, 'removed': True})
    with pytest.raises(ValueError, match='epoch'):
        group_session_from_welcome(peer, opened, 6, {**initial, 'needsRekey': True})
    opened['state'].group_name = 'Conflicting metadata'
    with pytest.raises(ValueError, match='roster'):
        group_session_from_welcome(peer, opened, 6, initial)
    with pytest.raises(ValueError, match='recovery'):
        restore_group_session(peer, {**initial, 'recovery': {'afterSequence': True, 'reason': 'missing_history'}})
    for challenge in (bytes(31), bytes(33), '00' * 32):
        with pytest.raises(ValueError, match='challenge'):
            prepare_group_welcome_refresh(owner, owner_state, [peer['publicKey']], recovery_challenge=challenge)
        with pytest.raises(ValueError, match='challenge'):
            prepare_group_session_addition(owner, owner_state, [generate_identity()['publicKey']], recovery_challenge=challenge)
    with pytest.raises(ValueError, match='challenge'):
        prepare_group_welcome_refresh(owner, owner_state, [peer['publicKey'], owner['publicKey']], recovery_challenge=bytes(32))
