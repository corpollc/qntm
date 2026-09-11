"""Actual encrypted acceptance binds gateway control without granting group roles."""
import hashlib
import json
from copy import deepcopy
from qntm import cli
from qntm.cbor import marshal_canonical, unmarshal
from qntm.gateway_handshake import create_gateway_invite_body
from qntm.group import GroupState, create_group_genesis_body, parse_group_genesis_body, create_group_add_body, create_group_remove_body
from qntm.group_gateway import control_delegate
from qntm.group_session import crypto, save_state, state_for_record
from qntm.identity import generate_identity, base64url_encode
from test_group_session import setup, wire, receive, rekey, mid


def accept_gateway(tmp_path, *, strict=False, admin_inviter=True):
    owner, member, newcomer, record, _ = setup(tmp_path)
    state = GroupState()
    state.apply_genesis(parse_group_genesis_body(create_group_genesis_body('Legacy group', '', owner, [])))
    save_state(record, state)
    if strict:
        state.apply_add({'new_members': unmarshal(create_group_add_body(owner, [member['publicKey']]))['new_members']})
        save_state(record, state)
        _, record = rekey(owner, record, state)
    cli._save_conversations(str(tmp_path), [record])
    gateway = generate_identity()
    invitation = {'invitation_id': 'ab' * 16, 'gateway_public_key': base64url_encode(gateway['publicKey']),
                  'gateway_kid': base64url_encode(gateway['keyID']), 'expires_at': '2099-01-01T00:00:00Z'}
    participants = {base64url_encode(i['keyID']): base64url_encode(i['publicKey']) for i in (owner, member)}
    body = create_gateway_invite_body(invitation, crypto(record), participants, 2)
    text = json.dumps(body, separators=(',', ':'))
    promotion = wire(owner if admin_inviter else member, record, 'gate.promote', text.encode())
    acceptance = {'type': 'gate.accept', **{key: body[key] for key in ('conv_id', 'conv_epoch', 'invitation_id', 'gateway_kid', 'gateway_public_key')},
                  'invitation_msg_id': mid(promotion).hex(), 'invitation_hash': hashlib.sha256(text.encode()).hexdigest()}
    accepted = wire(gateway, record, 'gate.accept', json.dumps(acceptance).encode())
    out = receive(tmp_path, owner, record, [promotion, accepted], 2)
    assert [m['body_type'] for m in out] == ['gate.promote', 'gate.accept']
    record = cli._load_conversations(str(tmp_path))[0]
    return owner, member, newcomer, gateway, record


def test_verified_gateway_acceptance_retains_creator_and_never_adds_gateway_as_member(tmp_path):
    owner, member, _, gateway, record = accept_gateway(tmp_path)
    state = state_for_record(record)
    assert control_delegate(record) == gateway['publicKey']
    assert state.creator == owner['keyID'] and state.list_admins() == [owner['keyID']]
    assert state.is_member(member['keyID']) and not state.is_admin(member['keyID'])
    assert not state.is_member(gateway['keyID'])
    assert gateway['keyID'].hex() not in record['participants']


def test_delegated_membership_and_rekey_apply_without_granting_gateway_roles(tmp_path):
    owner, _, newcomer, gateway, record = accept_gateway(tmp_path)
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [add], 3)[0]['body_type'] == 'group_add'
    added = cli._load_conversations(str(tmp_path))[0]
    rotation, current = rekey(gateway, added, state_for_record(added))
    out = receive(tmp_path, owner, added, [rotation, wire(newcomer, current, 'text', b'after voted admission')], 5)
    assert [m['body_type'] for m in out] == ['group_rekey', 'text']
    saved = cli._load_conversations(str(tmp_path))[0]
    assert saved['current_epoch'] == 1
    assert state_for_record(saved).creator == owner['keyID']
    assert not state_for_record(saved).is_member(gateway['keyID'])


def test_unpinned_gateway_admin_appointment_and_creator_removal_are_rejected(tmp_path):
    owner, _, newcomer, gateway, record = accept_gateway(tmp_path)
    impostor = generate_identity()
    assert receive(tmp_path, owner, record, [wire(impostor, record, 'group_add', create_group_add_body(impostor, [newcomer['publicKey']]))], 3) == []
    admin = unmarshal(create_group_add_body(gateway, [newcomer['publicKey']]))
    admin['new_members'][0]['role'] = 'admin'
    assert receive(tmp_path, owner, record, [wire(gateway, record, 'group_add', marshal_canonical(admin))], 4) == []
    assert receive(tmp_path, owner, record, [wire(gateway, record, 'group_remove', create_group_remove_body([owner['keyID']]))], 5) == []
    pending = deepcopy(record); pending['gateway']['status'] = 'waiting'
    assert control_delegate(pending) is None
    unaccepted = deepcopy(record); unaccepted['gateway'].pop('membership_authority')
    assert control_delegate(unaccepted) is None
    cli._save_conversations(str(tmp_path), [unaccepted])
    assert receive(tmp_path, owner, unaccepted, [wire(gateway, unaccepted, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))], 6) == []
    mismatch = deepcopy(record); mismatch['gateway']['publicKey'] = base64url_encode(impostor['publicKey'])
    assert control_delegate(mismatch) is None
    assert state_for_record(cli._load_conversations(str(tmp_path))[0]).creator == owner['keyID']


def test_verified_nonadmin_current_epoch_promotion_cannot_delegate_group_control(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, strict=True, admin_inviter=False)
    assert record['gateway']['status'] == 'active'
    assert control_delegate(record) is None
    before = state_for_record(record).to_dict()
    attempt = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [attempt], 3) == []
    assert state_for_record(cli._load_conversations(str(tmp_path))[0]).to_dict() == before
    assert not state_for_record(record).is_admin(member['keyID'])


def test_gateway_acceptance_cannot_restore_members_during_pending_removal(tmp_path):
    from qntm.group_gateway import accept_gateway_membership
    owner, member, _, record, state = setup(tmp_path)
    gateway = generate_identity()
    participants = {base64url_encode(i['keyID']): base64url_encode(i['publicKey']) for i in (owner, member)}
    invite = {'conv_id': record['id'], 'conv_epoch': 0, 'participants': participants, 'gateway_kid': base64url_encode(gateway['keyID'])}
    state.apply_remove({'removed_members': [member['keyID']]}); save_state(record, state)
    record['needs_rekey'] = True
    assert accept_gateway_membership(record, invite, owner['keyID'], 'ab' * 16) is None
    assert not state_for_record(record).is_member(member['keyID'])


def proposal_events(owner, member, newcomer, gateway, record, *, required=2):
    from qntm.governance import create_proposal_body, hash_proposal_body, sign_gov_approval
    proposal = create_proposal_body(owner, conv_id=record['id'], proposal_type='member_add',
        gateway_kid=base64url_encode(gateway['keyID']),
        proposed_members=[{'kid': base64url_encode(newcomer['keyID']), 'public_key': base64url_encode(newcomer['publicKey'])}],
        eligible_signer_kids=[base64url_encode(identity['keyID']) for identity in (owner, member)], required_approvals=required)
    approval = {'type': 'gov.approve', 'conv_id': record['id'], 'proposal_id': proposal['proposal_id'],
        'gateway_kid': base64url_encode(gateway['keyID']), 'signer_kid': base64url_encode(member['keyID']),
        'signature': base64url_encode(sign_gov_approval(member['privateKey'], conv_id=record['id'],
            proposal_id=proposal['proposal_id'], proposal_hash=hash_proposal_body(proposal)))}
    return proposal, approval, [wire(owner, record, 'gov.propose', json.dumps(proposal).encode()),
        wire(member, record, 'gov.approve', json.dumps(approval).encode())]


def test_nonadmin_tool_gateway_requires_exact_signed_quorum_for_one_membership_transition(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    assert control_delegate(record) is None
    assert not state_for_record(record).is_member(member['keyID'])
    _, _, events = proposal_events(owner, member, newcomer, gateway, record)
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    out = receive(tmp_path, owner, record, [*events, add], 5)
    assert [event['body_type'] for event in out] == ['gov.propose', 'gov.approve', 'group_add']
    added = cli._load_conversations(str(tmp_path))[0]
    assert added['pending_governed_membership'] and not control_delegate(added)
    rotation, current = rekey(gateway, added, state_for_record(added))
    out = receive(tmp_path, owner, added, [rotation, wire(newcomer, current, 'text', b'quorum admitted')], 7)
    assert [event['body_type'] for event in out] == ['group_rekey', 'text']
    saved = cli._load_conversations(str(tmp_path))[0]
    assert not saved.get('pending_governed_membership') and not control_delegate(saved)
    assert state_for_record(saved).creator == owner['keyID']
    assert not state_for_record(saved).is_member(gateway['keyID'])
    unauthorized = wire(gateway, saved, 'group_add', create_group_add_body(gateway, [generate_identity()['publicKey']]))
    assert receive(tmp_path, owner, saved, [unauthorized], 8) == []


def test_tool_only_gateway_cannot_supply_its_own_quorum_or_replay_cached_verified_flags(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    proposal, _, events = proposal_events(owner, member, newcomer, gateway, record, required=1)
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    # Proposer alone remains below the independently calculated roster majority.
    assert [event['body_type'] for event in receive(tmp_path, owner, record, [events[0], add], 4)] == ['gov.propose']
    saved = cli._load_conversations(str(tmp_path))[0]
    assert not saved.get('pending_governed_membership')
    # A gateway's own signed terminal marker is not an approval from the members.
    applied = wire(gateway, saved, 'gov.applied', json.dumps({'type': 'gov.applied', 'proposal_id': proposal['proposal_id']}).encode())
    receive(tmp_path, owner, saved, [applied], 5)
    again = wire(gateway, saved, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, saved, [again], 6) == []


def test_latest_signed_withdrawal_blocks_membership_even_after_two_approvals(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    proposal, _, events = proposal_events(owner, member, newcomer, gateway, record)
    withdrawal = {'type': 'gov.disapprove', 'conv_id': record['id'], 'proposal_id': proposal['proposal_id'],
                  'gateway_kid': base64url_encode(gateway['keyID']), 'signer_kid': base64url_encode(member['keyID'])}
    denied = wire(member, record, 'gov.disapprove', json.dumps(withdrawal).encode())
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    out = receive(tmp_path, owner, record, [*events, denied, add], 6)
    assert [event['body_type'] for event in out] == ['gov.propose', 'gov.approve', 'gov.disapprove']
    assert not cli._load_conversations(str(tmp_path))[0].get('pending_governed_membership')


def test_gateway_cannot_add_itself_and_does_not_suppress_creator_controls(tmp_path):
    owner, _, newcomer, gateway, record = accept_gateway(tmp_path)
    own_add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [gateway['publicKey']]))
    assert receive(tmp_path, owner, record, [own_add], 3) == []
    owner_add = wire(owner, record, 'group_add', create_group_add_body(owner, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [owner_add], 4)[0]['body_type'] == 'group_add'


def test_expired_transport_withdrawal_remains_authoritative(tmp_path, monkeypatch):
    import base64
    import time
    from qntm.message import create_message, serialize_envelope
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    proposal, _, events = proposal_events(owner, member, newcomer, gateway, record)
    withdrawal = {'type': 'gov.disapprove', 'conv_id': record['id'], 'proposal_id': proposal['proposal_id'],
                  'gateway_kid': base64url_encode(gateway['keyID']), 'signer_kid': base64url_encode(member['keyID'])}
    started = int(time.time())
    monkeypatch.setattr(time, 'time', lambda: started)
    envelope = create_message(member, crypto(record), 'gov.disapprove', json.dumps(withdrawal).encode(), ttl_seconds=1)
    denied = {'envelope_b64': base64.b64encode(serialize_envelope(envelope)).decode()}
    assert len(receive(tmp_path, owner, record, [*events, denied], 5)) == 3
    monkeypatch.setattr(time, 'time', lambda: started + 2)
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [add], 6) == []
    assert not cli._load_conversations(str(tmp_path))[0].get('pending_governed_membership')


def test_gateway_backdated_control_cannot_revive_expired_proposal(tmp_path, monkeypatch):
    import time
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    now = int(time.time())
    with monkeypatch.context() as clock:
        clock.setattr(time, 'time', lambda: now - 7200)
        _, _, events = proposal_events(owner, member, newcomer, gateway, record)
        add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    # All transport envelopes remain live for 24h; the proposal expired an hour ago.
    out = receive(tmp_path, owner, record, [*events, add], 5)
    assert [row['body_type'] for row in out] == ['gov.propose', 'gov.approve']
    assert not cli._load_conversations(str(tmp_path))[0].get('pending_governed_membership')


def test_malformed_governance_messages_do_not_poison_later_valid_quorum(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    proposal, approval, events = proposal_events(owner, member, newcomer, gateway, record)
    malformed = [wire(member, record, 'gov.propose', b'[]'),
        wire(owner, record, 'gov.propose', json.dumps({**proposal, 'expires_at': []}).encode()),
        wire(member, record, 'gov.approve', json.dumps({**approval, 'signature': []}).encode()),
        wire(member, record, 'gov.propose', json.dumps({**proposal, 'signer_kid': base64url_encode(member['keyID'])}).encode())]
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    out = receive(tmp_path, owner, record, [malformed[0], *events, *malformed[1:], add], 9)
    assert out[-1]['body_type'] == 'group_add'
    saved = cli._load_conversations(str(tmp_path))[0]
    assert state_for_record(saved).is_member(newcomer['keyID'])
    assert not control_delegate(saved)


def test_previous_release_separate_group_state_preserves_creator_controls(tmp_path):
    owner, _, newcomer, record, state = setup(tmp_path)
    cli._save_group_state(str(tmp_path), record['id'], state)
    record.pop('group_state')
    cli._save_conversations(str(tmp_path), [record])
    add = wire(owner, record, 'group_add', create_group_add_body(owner, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [add], 1)[0]['body_type'] == 'group_add'
    saved = cli._load_conversations(str(tmp_path))[0]
    assert state_for_record(saved).creator == owner['keyID']
    assert state_for_record(saved).is_member(newcomer['keyID'])


def test_previous_active_gateway_uses_learned_keys_only_with_new_signed_quorum(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path, admin_inviter=False)
    state = state_for_record(record)
    cli._save_group_state(str(tmp_path), record['id'], state)
    record.pop('group_state')
    record['gateway'].pop('membership_offer')
    record['gateway'].pop('membership_authority')
    cli._merge_participant_public_key(str(tmp_path), record['id'], member['publicKey'])
    cli._save_conversations(str(tmp_path), [record])
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [add], 3) == []
    _, _, events = proposal_events(owner, member, newcomer, gateway, record)
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    assert receive(tmp_path, owner, record, [*events, add], 6)[-1]['body_type'] == 'group_add'
    saved = cli._load_conversations(str(tmp_path))[0]
    assert not control_delegate(saved)
    assert state_for_record(saved).is_member(newcomer['keyID'])


def test_pending_gateway_authority_survives_member_first_competing_rekey(tmp_path):
    owner, member, newcomer, gateway, record = accept_gateway(tmp_path / 'setup', admin_inviter=False)
    _, _, events = proposal_events(owner, member, newcomer, gateway, record)
    add = wire(gateway, record, 'group_add', create_group_add_body(gateway, [newcomer['publicKey']]))
    receive(tmp_path / 'setup', owner, record, [*events, add], 5)
    added = cli._load_conversations(str(tmp_path / 'setup'))[0]
    owner_rekey, _ = rekey(owner, added, state_for_record(added))
    gateway_rekey, winner = rekey(gateway, added, state_for_record(added))
    while mid(gateway_rekey) >= mid(owner_rekey):
        owner_rekey, _ = rekey(owner, added, state_for_record(added))
        gateway_rekey, winner = rekey(gateway, added, state_for_record(added))
    results = []
    for name, order in [('owner-first', [owner_rekey, gateway_rekey]), ('gateway-first', [gateway_rekey, owner_rekey])]:
        path = tmp_path / name
        cli._save_conversations(str(path), [deepcopy(added)])
        for index, event in enumerate(order):
            receive(path, owner, added, [event], index + 6)
        saved = cli._load_conversations(str(path))[0]
        assert saved['rekeys'][0]['id'] == mid(gateway_rekey).hex()
        assert saved['rekeys'][0]['control_delegate'] == gateway['publicKey'].hex()
        assert not saved.get('pending_governed_membership') and control_delegate(saved) is None
        results.append(saved['keys'])
    assert results[0] == results[1] == winner['keys']
