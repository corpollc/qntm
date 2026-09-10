"""Current-key recovery is not a new admission or a key rotation."""
import copy

import pytest

from qntm import (
    generate_identity, create_invite, create_conversation, derive_conversation_keys, GroupState,
    create_group_genesis_body, parse_group_genesis_body, create_group_session, receive_group_event,
    prepare_group_session_addition, prepare_group_welcome_refresh, assert_group_welcome_refresh_current,
    open_group_welcome, marshal_canonical, create_message, decrypt_message, GROUP_WELCOME_TTL,
    create_group_control_message, create_group_remove_body, create_rekey, prepare_group_session_rekey, assert_group_can_send,
)


def setup():
    owner, contact = generate_identity(), generate_identity()
    invite = create_invite(owner, 'group')
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    group = GroupState()
    group.apply_genesis(parse_group_genesis_body(create_group_genesis_body('Refresh team', '', owner, [])))
    conversation['participants'] = group.list_members()
    initial = create_group_session(owner, conversation, group)
    operation = prepare_group_session_addition(owner, initial, [contact['publicKey']])
    added = receive_group_event(owner, operation['addition'], initial)
    accepted = receive_group_event(owner, operation['rekey'], added['state'])
    return owner, contact, initial, operation, accepted, {'conversation_id': conversation['id'], 'inviter_public_key': owner['publicKey']}


def test_expired_welcome_recovery_preserves_membership_epoch_and_keys(monkeypatch):
    owner, contact, _, operation, accepted, pin = setup()
    before = copy.deepcopy(accepted['state'])
    at = operation['welcomes'][0]['expiry_ts'] + 1
    monkeypatch.setattr('time.time', lambda: at)
    with pytest.raises(ValueError, match='expired'):
        open_group_welcome(contact, marshal_canonical(operation['welcomes'][0]), **pin)
    refresh = prepare_group_welcome_refresh(owner, accepted['state'], [contact['publicKey']])
    assert_group_welcome_refresh_current(owner, accepted['state'], refresh)
    opened = open_group_welcome(contact, marshal_canonical(refresh['welcomes'][0]), **pin)
    assert opened['purpose'] == 'refresh' and 'addition_id' not in opened and 'rekey_id' not in opened
    assert opened['conversation']['keys'] == accepted['conversation']['keys']
    assert opened['conversation']['currentEpoch'] == 1
    assert 'inviteToken' not in opened['conversation'] and 'epochKeys' not in opened['conversation']
    assert opened['state'].snapshot() == accepted['group'].snapshot()
    message = create_message(contact, opened['conversation'], 'text', b'recovered')
    assert decrypt_message(message, accepted['conversation'])['inner']['body'] == b'recovered'
    assert accepted['state'] == before


def test_removed_recipient_and_stale_refresh_are_rejected():
    owner, contact, _, _, accepted, _ = setup()
    refresh = prepare_group_welcome_refresh(owner, accepted['state'], [contact['publicKey']])
    removal = create_group_control_message(owner, accepted['conversation'], 'group_remove', create_group_remove_body([contact['keyID']]))
    removed = receive_group_event(owner, removal, accepted['state'])
    with pytest.raises(ValueError, match='rotation'):
        assert_group_welcome_refresh_current(owner, removed['state'], refresh)
    body, _ = create_rekey(owner, removed['conversation'], removed['group'], removed['conversation']['id'])
    rotated = receive_group_event(owner, create_group_control_message(owner, removed['conversation'], 'group_rekey', body), removed['state'])
    with pytest.raises(ValueError, match='current member'):
        prepare_group_welcome_refresh(owner, rotated['state'], [contact['publicKey']])
    with pytest.raises(ValueError, match='differs'):
        assert_group_welcome_refresh_current(owner, rotated['state'], refresh)
    with pytest.raises(ValueError, match='removed'):
        prepare_group_welcome_refresh(owner, {**accepted['state'], 'removed': True}, [contact['publicKey']])


def test_recipients_identity_and_lifetime_validation(monkeypatch):
    owner, contact, _, _, accepted, _ = setup()
    for recipients in [[], [generate_identity()['publicKey']], [contact['publicKey'], contact['publicKey']], [bytes(32)]]:
        with pytest.raises(ValueError):
            prepare_group_welcome_refresh(owner, accepted['state'], recipients)
    with pytest.raises(ValueError):
        prepare_group_welcome_refresh(contact, accepted['state'], [owner['publicKey']])
    for ttl in [0, -1, 1.5, True, GROUP_WELCOME_TTL + 1]:
        with pytest.raises(ValueError, match='lifetime'):
            prepare_group_welcome_refresh(owner, accepted['state'], [contact['publicKey']], ttl)
    refresh = prepare_group_welcome_refresh(owner, accepted['state'], [contact['publicKey']], 1)
    at = refresh['welcomes'][0]['expiry_ts'] + 1
    monkeypatch.setattr('time.time', lambda: at)
    with pytest.raises(ValueError, match='expired'):
        assert_group_welcome_refresh_current(owner, accepted['state'], refresh)


def test_epoch_zero_refresh_is_not_an_admission():
    owner, _, initial, _, _, pin = setup()
    refresh = prepare_group_welcome_refresh(owner, initial, [owner['publicKey']])
    opened = open_group_welcome(owner, marshal_canonical(refresh['welcomes'][0]), **pin)
    assert opened['purpose'] == 'refresh' and opened['conversation']['currentEpoch'] == 0


def test_noncreator_can_finish_another_members_interrupted_rotation():
    owner, contact, _, _, accepted, pin = setup()
    newcomer = generate_identity()
    member_state = create_group_session(contact, accepted['conversation'], accepted['group'])
    addition = prepare_group_session_addition(owner, accepted['state'], [newcomer['publicKey']])
    pending = receive_group_event(contact, addition['addition'], member_state)
    with pytest.raises(ValueError, match='rotation'):
        assert_group_can_send(contact, pending['state'])
    before = copy.deepcopy(pending['state'])
    rotation = prepare_group_session_rekey(contact, pending['state'])
    assert pending['state'] == before
    received = receive_group_event(contact, rotation['rekey'], pending['state'])
    assert_group_can_send(contact, received['state'])
    assert received['state']['epoch'] == 2
    refresh = prepare_group_welcome_refresh(contact, received['state'], [newcomer['publicKey']])
    opened = open_group_welcome(newcomer, marshal_canonical(refresh['welcomes'][0]),
                               **{**pin, 'inviter_public_key': contact['publicKey']})
    assert opened['conversation']['keys'] == rotation['conversation']['keys']
    assert opened['state'].creator == owner['keyID']
    with pytest.raises(ValueError, match='removed'):
        prepare_group_session_rekey(contact, {**pending['state'], 'removed': True})
