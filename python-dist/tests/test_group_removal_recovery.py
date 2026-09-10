"""An accepted removal or standalone rotation whose saved rekey went stale finishes from current membership."""
import base64
import copy

import pytest

from qntm import (cli, create_group_add_body, create_group_control_message, create_group_remove_body,
                  deserialize_envelope, generate_identity, group_session_conversation, prepare_group_session_rekey,
                  require_group_recovery, serialize_envelope)
from qntm.group_client import GroupClient, _control_accepted, join, set_contact
from test_group_client import setup


def lost(cid, wire):
    return cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())


def unposted(url, cid, wire):
    raise lost(cid, wire)


def encoded_wire(operation, index):
    return base64.b64decode(operation['controls'][index])


def add_member(f, owner, name):
    identity = generate_identity()
    directory = f.contact_dir + '-' + name.lower()
    cli._save_identity(directory, identity)
    set_contact(f.owner_dir, name, identity['publicKey'].hex())
    join(directory, identity, owner.add(f.cid, name)['group_link'])
    return identity, directory, GroupClient(directory, identity, f.relay)


def stage_removal(f, monkeypatch, owner, *, delivery='unposted', ttl=60):
    """Owner removes Colleague with a short-lived rekey; only the rekey POST fails."""
    calls = 0
    def partial(url, cid, wire):
        nonlocal calls
        calls += 1
        if calls == 2:
            if delivery == 'lost_ack':
                f.send(url, cid, wire)
            raise lost(cid, wire)
        if delivery == 'none':
            raise lost(cid, wire)
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', partial)
    with owner._operation_lock(f.cid):
        record = owner.sync(f.cid)
        owner._save_operation(f.cid, owner.prepare_change(record, 'Colleague', 'stale rotation', ttl))
        with pytest.raises(cli.SendDeliveryUnknown):
            owner._resume(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    original = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert original['kind'] == 'remove' and original['target']['key_id'] == f.contact['keyID'].hex()
    return original


def expire_rekey(operation, monkeypatch):
    deadline = deserialize_envelope(encoded_wire(operation, -1))['expiry_ts']
    monkeypatch.setattr('time.time', lambda: deadline + 1)


def journals_before_post(f, monkeypatch):
    captured = []
    def inspect(url, cid, wire):
        journal = cli._load_conversations(f.owner_dir)[0].get('group_operation')
        if journal:
            captured.append(copy.deepcopy(journal))
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', inspect)
    return captured


def craft(identity, state, body_type, body):
    return create_group_control_message(identity, group_session_conversation(state), body_type, body)


@pytest.mark.parametrize('roster', ['sole_survivor', 'helper_present'])
def test_accepted_removal_with_expired_rekey_completes_from_current_roster(setup, monkeypatch, roster):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper = add_member(f, owner, 'Helper') if roster == 'helper_present' else None
    original = stage_removal(f, monkeypatch, owner)
    source = deserialize_envelope(encoded_wire(original, 0))['conv_epoch']
    before_retry = owner.sync(f.cid)
    assert before_retry['group_session']['needsRekey'] and f.contact['keyID'].hex() not in before_retry['participants']
    assert _control_accepted(before_retry, encoded_wire(original, 0))
    expire_rekey(original, monkeypatch)
    captured = journals_before_post(f, monkeypatch)
    count = len(f.attempted)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert len(f.attempted) == count + 1 and f.attempted[-1] != encoded_wire(original, 1)
    rotation = deserialize_envelope(f.attempted[-1])
    assert rotation['conv_epoch'] == source
    assert captured == [{'kind': 'removal_rekey', 'controls': [base64.b64encode(f.attempted[-1]).decode()], 'welcomes': [],
                         'welcomes_sent': 0, 'expected': captured[0]['expected'],
                         'origin': {'kind': 'remove', 'controls': original['controls'], 'welcomes': [], 'welcomes_sent': 0,
                                    'target': original['target'], 'delivery': 'unknown'}}]
    assert captured[0]['expected']['root'] != original['expected']['root']
    record = cli._load_conversations(f.owner_dir)[0]
    assert not record.get('group_operation') and not record['group_session']['needsRekey']
    assert result['current_epoch'] == source + 1 == record['current_epoch']
    assert result['members'] == (1 if helper is None else 2)
    assert f.contact['keyID'].hex() not in record['participants']
    assert GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)['group_session']['removed']
    if helper:
        _, helper_dir, helper_client = helper
        state = helper_client.sync(f.cid)['group_session']
        assert state['epoch'] == source + 1 and state['root'] == record['group_session']['root'] and not state['needsRekey']
        f.command(helper_dir, 'send', f.cid, 'helper after completed removal')
        assert any(row.get('unsafe_body') == 'helper after completed removal' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])
    with pytest.raises(SystemExit):
        f.command(f.contact_dir, 'send', f.cid, 'removed member cannot send')


def test_replacement_rotation_survives_lost_ack_and_restart(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_removal(f, monkeypatch, owner)
    expire_rekey(original, monkeypatch)
    repair = []
    def lose_ack(url, cid, wire):
        repair.append(wire)
        f.send(url, cid, wire)
        raise lost(cid, wire)
    monkeypatch.setattr(cli, '_http_send', lose_ack)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.retry(f.cid)
    saved = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert saved['kind'] == 'removal_rekey' and saved['controls'] == [base64.b64encode(repair[0]).decode()]
    monkeypatch.setattr(cli, '_http_send', f.send)
    count = len(f.attempted)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert len(f.attempted) == count and result['current_epoch'] == 2
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')
    assert f.rows[f.cid].count(repair[0]) == 1


@pytest.mark.parametrize('when', ['before_retry', 'between_stage_and_post'])
def test_helper_rotation_finishes_accepted_removal_without_posting(setup, monkeypatch, when):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, _, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    helper.sync(f.cid)
    expire_rekey(original, monkeypatch)
    def complete():
        assert helper.change(f.cid)['current_epoch'] == 3
    if when == 'before_retry':
        complete()
    else:
        release = owner._post_removal_rekey
        def race(cid, operation):
            complete()
            owner.sync(cid)  # Resident receive commits the helper's rotation before release.
            release(cid, operation)
        monkeypatch.setattr(owner, '_post_removal_rekey', race)
    count = len(f.attempted)
    result = owner.retry(f.cid)
    assert len(f.attempted) == count + (0 if when == 'before_retry' else 1)
    assert result['current_epoch'] == 3 and result['members'] == 2
    record = cli._load_conversations(f.owner_dir)[0]
    assert not record.get('group_operation') and record['group_session']['root'] == helper.sync(f.cid)['group_session']['root']


def test_later_readmission_after_completion_is_never_re_removed(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, helper_dir, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    helper.sync(f.cid)
    expire_rekey(original, monkeypatch)
    helper.change(f.cid)
    set_contact(helper_dir, 'Colleague', f.contact['publicKey'].hex())
    link = helper.add(f.cid, 'Colleague')['group_link']
    assert join(f.contact_dir, f.contact, link)['current_epoch'] == 4
    count = len(f.attempted)
    result = owner.retry(f.cid)
    assert len(f.attempted) == count and result['current_epoch'] == 4 and result['members'] == 3
    record = cli._load_conversations(f.owner_dir)[0]
    assert not record.get('group_operation') and f.contact['keyID'].hex() in record['participants']
    f.command(f.contact_dir, 'send', f.cid, 'readmitted and still present')
    assert any(row.get('unsafe_body') == 'readmitted and still present' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


def test_same_epoch_readmission_completes_the_current_roster_without_re_removal(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, _, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    state = helper.sync(f.cid)['group_session']
    # A racing member re-adds the target inside the removal's source epoch.
    f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_add', create_group_add_body(helper_identity, [f.contact['publicKey']]))))
    expire_rekey(original, monkeypatch)
    current = owner.sync(f.cid)
    assert f.contact['keyID'].hex() in current['participants'] and current['group_session']['needsRekey']
    count = len(f.attempted)
    result = owner.retry(f.cid)
    assert len(f.attempted) == count + 1 and result['current_epoch'] == 3 and result['members'] == 3
    record = cli._load_conversations(f.owner_dir)[0]
    assert deserialize_envelope(f.attempted[-1])['conv_epoch'] == 2 and f.contact['keyID'].hex() in record['participants']
    assert record['group_session']['admissions'][f.contact['keyID'].hex()]['completion']['rekeyId'] == deserialize_envelope(f.attempted[-1])['msg_id'].hex()


@pytest.mark.parametrize('journal', ['pinned', 'legacy'])
def test_exact_unaccepted_removal_never_targets_a_same_epoch_readmission(setup, monkeypatch, journal):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, _, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner, delivery='none')
    if journal == 'legacy':
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_operation'].pop('target')
        cli._save_conversations(f.owner_dir, records)
        original = copy.deepcopy(records[0]['group_operation'])
    state = helper.sync(f.cid)['group_session']
    removal = craft(helper_identity, state, 'group_remove', create_group_remove_body([f.contact['keyID']]))
    f.send(f.relay, f.cid, serialize_envelope(removal))
    f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_add', create_group_add_body(helper_identity, [f.contact['publicKey']]))))
    current = owner.sync(f.cid)
    assert f.contact['keyID'].hex() in current['participants']
    count = len(f.attempted)
    with pytest.raises(ValueError, match='later admission|original admission'):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


@pytest.mark.parametrize('when', ['after_post', 'before_post'])
def test_losing_replacement_rotation_finishes_through_the_verified_competitor(setup, monkeypatch, when):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_removal(f, monkeypatch, owner)
    source = copy.deepcopy(owner.sync(f.cid)['group_session'])
    expire_rekey(original, monkeypatch)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        competing = prepare_group_session_rekey(f.owner, source)['rekey']
    repair = []
    if when == 'after_post':
        def lose_ack(url, cid, wire):
            repair.append(wire)
            f.send(url, cid, wire)
            raise lost(cid, wire)
        with monkeypatch.context() as fixed:
            fixed.setattr(cli, '_http_send', lose_ack)
            fixed.setattr('qntm.message.generate_message_id', lambda: b'\xf0' * 16)
            with pytest.raises(cli.SendDeliveryUnknown):
                owner.retry(f.cid)
        f.send(f.relay, f.cid, serialize_envelope(competing))
    else:
        release = owner._post_removal_rekey
        def race(cid, operation):
            f.send(f.relay, f.cid, serialize_envelope(competing))
            owner.sync(cid)
            release(cid, operation)
        monkeypatch.setattr(owner, '_post_removal_rekey', race)
    count = len(f.attempted)
    result = owner.retry(f.cid)
    record = cli._load_conversations(f.owner_dir)[0]
    assert len(f.attempted) == count + (0 if when == 'after_post' else 1)
    assert result['current_epoch'] == 2 and not record.get('group_operation')
    assert record['group_session']['rekeys'][-1]['messageId'] == competing['msg_id'].hex()
    if when == 'after_post':
        mid = deserialize_envelope(repair[0])['msg_id'].hex()
        assert any(row['msg_id'] == mid and row['receive_binding']['valid'] is False for row in record['group_history'])
    assert _control_accepted(record, encoded_wire(original, 0))


def test_removal_invalidated_by_a_lower_branch_is_preserved_without_rotation(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    state = owner.sync(f.cid)['group_session']
    frame = state['rekeys'][-1]
    source = {**state, 'epoch': frame['epoch'], 'root': frame['root'], 'snapshot': frame['snapshot'],
              'rekeys': [], 'seen': {}, 'admissions': copy.deepcopy(frame['admissions']), 'needsRekey': True}
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        competing = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(competing))
    current = owner.sync(f.cid)
    assert current['group_session']['epoch'] == 2 and f.contact['keyID'].hex() in current['participants']
    assert not _control_accepted(current, encoded_wire(original, 0))
    expire_rekey(original, monkeypatch)
    count = len(f.attempted)
    with pytest.raises(ValueError, match='current branch'):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


@pytest.mark.parametrize('barrier', ['recovery', 'sender_removed', 'journal_changed', 'roster_changed', 'removal_unproven'])
def test_repair_rechecks_authority_and_proof_between_stage_and_post(setup, monkeypatch, barrier):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, _, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    helper_state = helper.sync(f.cid)['group_session']
    expire_rekey(original, monkeypatch)
    release = owner._post_removal_rekey
    def change(cid, operation):
        records = cli._load_conversations(f.owner_dir)
        state = records[0]['group_session']
        if barrier == 'recovery':
            records[0]['group_session'] = require_group_recovery(state, records[0]['group_cursor'], 'missing_history')
        elif barrier == 'sender_removed':
            state['removed'] = True
        elif barrier == 'journal_changed':
            records[0]['group_operation']['welcomes_sent'] = 1
        elif barrier == 'roster_changed':
            f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, helper_state, 'group_add',
                                                            create_group_add_body(helper_identity, [generate_identity()['publicKey']]))))
            records = None
        else:
            mid = deserialize_envelope(encoded_wire(original, 0))['msg_id'].hex()
            state['seen'].pop(mid)
            next(row for row in records[0]['group_history'] if row['msg_id'] == mid)['receive_binding']['valid'] = False
        if records is not None:
            cli._save_conversations(f.owner_dir, records)
        else:
            owner.sync(cid)
        release(cid, operation)
    monkeypatch.setattr(owner, '_post_removal_rekey', change)
    count = len(f.attempted)
    with pytest.raises(ValueError):
        owner.retry(f.cid)
    assert len(f.attempted) == count + (1 if barrier == 'roster_changed' else 0)
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation']['kind'] == 'removal_rekey' and record['group_operation']['origin']['controls'] == original['controls']


@pytest.mark.parametrize('bound', ['none', 'revisions', 'bytes'])
def test_repeated_expired_repairs_keep_flat_evidence_and_enforce_bounds(setup, monkeypatch, bound):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_removal(f, monkeypatch, owner)
    expire_rekey(original, monkeypatch)
    monkeypatch.setattr(cli, '_http_send', unposted)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.retry(f.cid)
    first = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert first['kind'] == 'removal_rekey' and 'superseded_operations' not in first
    expire_rekey(first, monkeypatch)
    if bound != 'none':
        monkeypatch.setattr('qntm.group_client.MAX_OPERATION_REVISIONS' if bound == 'revisions' else 'qntm.group_client.MAX_OPERATION_EVIDENCE_BYTES', 0 if bound == 'revisions' else 1)
        monkeypatch.setattr(cli, '_http_send', f.send)
        count = len(f.attempted)
        with pytest.raises(ValueError, match='limit'):
            owner.retry(f.cid)
        assert len(f.attempted) == count
        assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == first
        return
    with pytest.raises(cli.SendDeliveryUnknown):
        GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    second = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert second['kind'] == 'removal_rekey' and second['controls'] != first['controls']
    assert second['origin'] == first['origin'] == {'kind': 'remove', 'controls': original['controls'], 'welcomes': [],
                                                   'welcomes_sent': 0, 'target': original['target'], 'delivery': 'unknown'}
    assert second['superseded_operations'] == [{'kind': 'removal_rekey', 'controls': first['controls'], 'welcomes': [],
                                                'welcomes_sent': 0, 'delivery': 'unknown'}]
    monkeypatch.setattr(cli, '_http_send', f.send)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert result['current_epoch'] == 2 and f.attempted[-1] == encoded_wire(second, 0)
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')


def test_failed_repair_staging_keeps_original_intent_and_sends_nothing(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_removal(f, monkeypatch, owner)
    expire_rekey(original, monkeypatch)
    save = cli._save_conversations
    def fail(config, records):
        if records[0].get('group_operation', {}).get('kind') == 'removal_rekey':
            raise OSError('simulated atomic write failure')
        save(config, records)
    monkeypatch.setattr(cli, '_save_conversations', fail)
    count = len(f.attempted)
    with pytest.raises(OSError, match='atomic'):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


@pytest.mark.parametrize('evidence', ['valid', 'missing', 'invalidated', 'unverified', 'wrong_digest', 'wrong_epoch', 'future_sequence'])
def test_removal_proof_after_cache_eviction_requires_authenticated_history(setup, monkeypatch, evidence):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_removal(f, monkeypatch, owner)
    expire_rekey(original, monkeypatch)
    record = owner.sync(f.cid)
    wire = encoded_wire(original, 0)
    mid = deserialize_envelope(wire)['msg_id'].hex()
    record['group_session']['seen'] = {}
    row = next(row for row in record['group_history'] if row['msg_id'] == mid)
    assert row['body_type'] == 'group_remove' and row['verified'] and row['receive_binding']['valid']
    if evidence == 'missing':
        record['group_history'].remove(row)
    elif evidence == 'invalidated':
        row['receive_binding']['valid'] = False
    elif evidence == 'unverified':
        row['verified'] = False
    elif evidence == 'wrong_digest':
        row['receive_binding']['digest'] = '00' * 32
    elif evidence == 'wrong_epoch':
        row['receive_binding']['epoch'] += 1
    elif evidence == 'future_sequence':
        row['sequence'] = record['group_cursor'] + 1
    cli._save_conversations(f.owner_dir, [record])
    assert _control_accepted(record, wire) is (evidence == 'valid')
    count = len(f.attempted)
    if evidence == 'valid':
        assert owner.retry(f.cid)['current_epoch'] == 2
        assert len(f.attempted) == count + 1 and not cli._load_conversations(f.owner_dir)[0].get('group_operation')
        return
    with pytest.raises(ValueError):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_removal_proof_survives_real_cache_eviction_by_authenticated_controls(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, _, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    wire = encoded_wire(original, 0)
    mid = deserialize_envelope(wire)['msg_id'].hex()
    state = helper.sync(f.cid)['group_session']
    record = owner.sync(f.cid)
    # Real eviction: authenticated same-epoch controls fill the bounded cache.
    monkeypatch.setattr('qntm.group_session._MAX_SEEN', max(4, len(record['group_session']['seen'])))
    for _ in range(8):
        f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_add', create_group_add_body(helper_identity, [generate_identity()['publicKey']]))))
    record = owner.sync(f.cid)
    assert mid not in record['group_session']['seen'] and _control_accepted(record, wire)
    expire_rekey(original, monkeypatch)
    count = len(f.attempted)
    result = owner.retry(f.cid)
    assert len(f.attempted) == count + 1 and result['current_epoch'] == 3 and result['members'] == 10
    assert f.contact['keyID'].hex() not in cli._load_conversations(f.owner_dir)[0]['participants']


@pytest.mark.parametrize('stale', ['expired', 'superseded'])
def test_unaccepted_removal_is_preserved_with_a_precise_error(setup, monkeypatch, stale):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, _, helper = add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner, delivery='none')
    if stale == 'expired':
        deadline = deserialize_envelope(encoded_wire(original, 0))['expiry_ts']
        monkeypatch.setattr('time.time', lambda: deadline + 1)
    else:
        helper.sync(f.cid)
        helper.change(f.cid)
    count = len(f.attempted)
    with pytest.raises(ValueError, match=stale):
        owner.retry(f.cid)
    with pytest.raises(ValueError, match='pending'):
        owner.change(f.cid, 'Colleague')
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation'] == original and f.contact['keyID'].hex() in record['participants']


def staged_rotation(f, monkeypatch, actor_dir, actor, *, delivery='unposted'):
    client = GroupClient(actor_dir, actor, f.relay)
    def fail(url, cid, wire):
        if delivery == 'lost_ack':
            f.send(url, cid, wire)
        raise lost(cid, wire)
    monkeypatch.setattr(cli, '_http_send', fail)
    with pytest.raises(cli.SendDeliveryUnknown):
        client.change(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    original = copy.deepcopy(cli._load_conversations(actor_dir)[0]['group_operation'])
    assert original['kind'] == 'rekey'
    return client, original


@pytest.mark.parametrize('stale', ['expired', 'rewound_branch', 'roster_changed', 'exact', 'superseded', 'lost_ack'])
def test_standalone_rotation_intent_is_kept_exact_renewed_or_finished(setup, monkeypatch, stale):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    add_member(f, owner, 'Helper')
    GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)
    _, original = staged_rotation(f, monkeypatch, f.contact_dir, f.contact, delivery='lost_ack' if stale == 'lost_ack' else 'unposted')
    source = deserialize_envelope(encoded_wire(original, 0))['conv_epoch']
    assert source == 2
    if stale == 'expired':
        expire_rekey(original, monkeypatch)
    elif stale == 'rewound_branch':
        # A lower-ID competitor from the previous epoch rewinds both the owner
        # and the member, who holds that frame; the exact old bytes never apply.
        state = owner.sync(f.cid)['group_session']
        frame = state['rekeys'][-1]
        branch = {**state, 'epoch': frame['epoch'], 'root': frame['root'], 'snapshot': frame['snapshot'],
                  'rekeys': [], 'seen': {}, 'admissions': copy.deepcopy(frame['admissions']), 'needsRekey': True}
        with monkeypatch.context() as fixed:
            fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
            f.send(f.relay, f.cid, serialize_envelope(prepare_group_session_rekey(f.owner, branch)['rekey']))
    elif stale == 'roster_changed':
        state = owner.sync(f.cid)['group_session']
        f.send(f.relay, f.cid, serialize_envelope(craft(f.owner, state, 'group_add', create_group_add_body(f.owner, [generate_identity()['publicKey']]))))
    elif stale == 'superseded':
        owner.change(f.cid)
    captured = []
    def inspect(url, cid, wire):
        journal = cli._load_conversations(f.contact_dir)[0].get('group_operation')
        if journal:
            captured.append(copy.deepcopy(journal))
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', inspect)
    count = len(f.attempted)
    result = GroupClient(f.contact_dir, f.contact, f.relay).retry(f.cid)
    posted = f.attempted[count:]
    record = cli._load_conversations(f.contact_dir)[0]
    assert not record.get('group_operation') and not record['group_session']['needsRekey']
    if stale in ('superseded', 'lost_ack'):
        assert posted == [] and result['current_epoch'] == source + 1
    elif stale == 'exact':
        assert posted == [encoded_wire(original, 0)] and result['current_epoch'] == source + 1
    else:
        assert len(posted) == 1 and posted[0] != encoded_wire(original, 0)
        assert deserialize_envelope(posted[0])['conv_epoch'] == source and result['current_epoch'] == source + 1
        assert captured[0]['kind'] == 'rekey' and 'origin' not in captured[0]
        assert captured[0]['superseded_operations'] == [{'kind': 'rekey', 'controls': original['controls'], 'welcomes': [],
                                                        'welcomes_sent': 0, 'delivery': 'unknown'}]
        if stale == 'roster_changed':
            assert result['members'] == 4
    assert owner.sync(f.cid)['group_session']['root'] == record['group_session']['root']
    f.command(f.contact_dir, 'send', f.cid, 'rotation settled')
    assert any(row.get('unsafe_body') == 'rotation settled' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


@pytest.mark.parametrize('barrier', ['sender_removed', 'recovery', 'evidence_limit'])
def test_stale_rotation_never_bypasses_current_authority_or_evidence_bounds(setup, monkeypatch, barrier):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    member, original = staged_rotation(f, monkeypatch, f.contact_dir, f.contact)
    expire_rekey(original, monkeypatch)
    monkeypatch.setattr(cli, '_http_send', f.send)
    if barrier == 'sender_removed':
        owner.change(f.cid, 'Colleague')
    elif barrier == 'recovery':
        records = cli._load_conversations(f.contact_dir)
        records[0]['group_session'] = require_group_recovery(records[0]['group_session'], records[0]['group_cursor'], 'missing_history')
        cli._save_conversations(f.contact_dir, records)
    else:
        monkeypatch.setattr('qntm.group_client.MAX_OPERATION_REVISIONS', 0)
    count = len(f.attempted)
    with pytest.raises(ValueError, match={'sender_removed': 'removed', 'recovery': 'incomplete', 'evidence_limit': 'limit'}[barrier]):
        member.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.contact_dir)[0]['group_operation'] == original


def test_cli_and_mcp_retry_finish_accepted_removal_and_stale_rotation(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, member_dir, member = add_member(f, owner, 'Helper')
    _, original = staged_rotation(f, monkeypatch, f.contact_dir, f.contact)
    expire_rekey(original, monkeypatch)
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.contact_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    rotated = mcp.group_retry(f.cid)
    assert rotated['current_epoch'] == 3 and not cli._load_conversations(f.contact_dir)[0].get('group_operation')
    member.sync(f.cid)
    removal = stage_removal(f, monkeypatch, owner)
    expire_rekey(removal, monkeypatch)
    with pytest.raises(SystemExit):
        f.command(f.owner_dir, 'send', f.cid, 'blocked while pending')
    finished = f.command(f.owner_dir, 'group', 'retry', f.cid)
    assert finished['current_epoch'] == 4 and finished['members'] == 2
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')
    f.command(member_dir, 'recv', f.cid)
    f.command(member_dir, 'send', f.cid, 'helper after CLI repair')
    assert any(row.get('unsafe_body') == 'helper after CLI repair' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])
    assert GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)['group_session']['removed']
