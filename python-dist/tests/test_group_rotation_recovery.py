"""A saved add's rotation can be completed without readmitting its recipient."""
import base64
import copy

import pytest

from qntm import (cli, create_group_control_message, create_group_remove_body, create_group_add_body, deserialize_envelope, generate_identity,
                  group_session_conversation, prepare_group_session_rekey, receive_group_event,
                  require_group_recovery, serialize_envelope)
from qntm.group_client import GroupClient, join
from test_group_client import setup
from test_group_operation_recovery import expire, opened


def partial(f, monkeypatch, *, expired=True):
    calls = 0
    def fail_rotation(url, cid, wire):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', fail_rotation)
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.add(f.cid, 'Colleague', 'ab' * 32)
    original = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    if expired:
        deadline = max(deserialize_envelope(base64.b64decode(encoded))['expiry_ts']
                       for encoded in [*original['controls'], *original['welcomes']])
        monkeypatch.setattr('time.time', lambda: deadline + 1)
    monkeypatch.setattr(cli, '_http_send', f.send)
    return owner, original


@pytest.mark.parametrize('expired', [False, True])
def test_pending_admission_survives_seen_eviction_and_retains_original_challenge(setup, monkeypatch, expired):
    f = setup
    owner, original = partial(f, monkeypatch, expired=expired)
    records = cli._load_conversations(f.owner_dir)
    records[0]['group_session']['seen'] = {}
    cli._save_conversations(f.owner_dir, records)
    before = len(f.attempted)
    result = owner.retry(f.cid)
    posted = f.attempted[before:]
    assert len(posted) == 2
    assert base64.b64decode(original['controls'][0]) not in posted
    welcome = opened(f, posted[1])
    assert welcome['purpose'] == ('renewal' if expired else 'addition')
    assert welcome['recovery_challenge'] == bytes.fromhex('ab' * 32)
    assert welcome['admissions'][f.contact['keyID'].hex()]['addId'] == deserialize_envelope(base64.b64decode(original['controls'][0]))['msg_id'].hex()
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


@pytest.mark.parametrize('accepted', [False, True])
def test_repair_restart_keeps_exact_unknown_wire_or_uses_accepted_completion(setup, monkeypatch, accepted):
    f = setup
    owner, original = partial(f, monkeypatch)
    repair = []
    def lose_ack(url, cid, wire):
        operation = cli._load_conversations(f.owner_dir)[0]['group_operation']
        assert operation['kind'] == 'addition_rekey'
        assert operation['origin']['controls'] == original['controls'] and 'expected' not in operation['origin']
        assert not operation['welcomes']
        repair.append(wire)
        if accepted:
            f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', lose_ack)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.retry(f.cid)
    assert len(repair) == 1
    seen_renewal = []
    def inspect(url, cid, wire):
        if deserialize_envelope(wire).get('kind') == 'group_welcome':
            journal = cli._load_conversations(f.owner_dir)[0]['group_operation']
            seen_renewal.append(journal)
            assert journal['rotation']['controls'] == [base64.b64encode(repair[0]).decode()]
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', inspect)
    restarted = GroupClient(f.owner_dir, f.owner, f.relay)
    if accepted:
        current = restarted.sync(f.cid)
        current['group_session']['seen'] = {}
        cli._save_conversations(f.owner_dir, [current])
    before = len(f.attempted)
    result = restarted.retry(f.cid)
    assert len(f.attempted[before:]) == (1 if accepted else 2)
    if not accepted:
        assert f.attempted[before] == repair[0]
    assert len(seen_renewal) == 1 and len(f.rows[f.cid]) == 4
    assert opened(f, f.attempted[-1])['purpose'] == 'renewal'
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


@pytest.mark.parametrize('when', ['before_post', 'after_post'])
def test_competing_completion_renews_current_winner_without_requiring_repair_acceptance(setup, monkeypatch, when):
    f = setup
    owner, _ = partial(f, monkeypatch)
    source = copy.deepcopy(owner.sync(f.cid)['group_session'])
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        competing = prepare_group_session_rekey(f.owner, source)['rekey']
    count = len(f.attempted)
    if when == 'before_post':
        release = owner._post_addition_rekey
        def race(cid, operation):
            f.send(f.relay, f.cid, serialize_envelope(competing))
            owner.sync(cid)
            release(cid, operation)
        monkeypatch.setattr(owner, '_post_addition_rekey', race)
    else:
        def race(url, cid, wire):
            receipt = f.send(url, cid, wire)
            if deserialize_envelope(wire).get('kind') != 'group_welcome':
                f.send(url, cid, serialize_envelope(competing))
            return receipt
        monkeypatch.setattr(cli, '_http_send', race)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xf0' * 16)
        result = owner.retry(f.cid)
    assert len(f.attempted[count:]) == (2 if when == 'before_post' else 3)
    welcome = opened(f, f.attempted[-1])
    assert welcome['admissions'][f.contact['keyID'].hex()]['completion']['rekeyId'] == competing['msg_id'].hex()
    assert welcome['conversation']['keys']['root'].hex() == owner.sync(f.cid)['group_session']['root']
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


@pytest.mark.parametrize('barrier', ['target_removed', 'recovery', 'sender_removed', 'journal_changed'])
def test_repair_rechecks_barriers_and_intent_between_stage_and_post(setup, monkeypatch, barrier):
    f = setup
    owner, _ = partial(f, monkeypatch)
    release = owner._post_addition_rekey
    def change(cid, operation):
        records = cli._load_conversations(f.owner_dir)
        state = records[0]['group_session']
        if barrier == 'target_removed':
            removal = create_group_control_message(f.owner, group_session_conversation(state), 'group_remove',
                                                   create_group_remove_body([f.contact['keyID']]))
            records[0]['group_session'] = receive_group_event(f.owner, removal, state)['state']
        elif barrier == 'recovery':
            records[0]['group_session'] = require_group_recovery(state, records[0]['group_cursor'], 'missing_history')
        elif barrier == 'sender_removed':
            state['removed'] = True
        else:
            records[0]['group_operation']['recovery_challenge'] = 'cd' * 32
        cli._save_conversations(f.owner_dir, records)
        release(cid, operation)
    monkeypatch.setattr(owner, '_post_addition_rekey', change)
    before = len(f.attempted)
    with pytest.raises(ValueError):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation']['kind'] == 'addition_rekey'


def test_same_epoch_target_removal_with_seen_evicted_never_reposts_old_add(setup, monkeypatch):
    f = setup
    owner, original = partial(f, monkeypatch, expired=False)
    current = owner.sync(f.cid)
    removal = create_group_control_message(f.owner, group_session_conversation(current['group_session']), 'group_remove',
                                           create_group_remove_body([f.contact['keyID']]))
    f.send(f.relay, f.cid, serialize_envelope(removal))
    current = owner.sync(f.cid)
    current['group_session']['seen'] = {}
    cli._save_conversations(f.owner_dir, [current])
    before = len(f.attempted)
    with pytest.raises(ValueError, match='no longer'):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_rotation_ack_without_replay_never_installs_predicted_state_or_releases_keys(setup, monkeypatch):
    f = setup
    owner, _ = partial(f, monkeypatch)
    def missing(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] != 3], head
    monkeypatch.setattr(cli, '_recv_once', missing)
    before = len(f.attempted)
    with pytest.raises(ValueError):
        owner.retry(f.cid)
    assert len(f.attempted) == before + 1
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_session']['epoch'] == 0 and record['group_session']['recovery']
    assert record['group_operation']['kind'] == 'addition_rekey'
    assert 3 not in record.get('group_delivery_receipts', [])


@pytest.mark.parametrize('after_stage', [False, True])
def test_repair_uses_current_roster_and_blocks_roster_change_after_staging(setup, monkeypatch, after_stage):
    f = setup
    owner, original = partial(f, monkeypatch, expired=False)
    third = generate_identity()
    def add_third():
        record = owner.sync(f.cid)
        envelope = create_group_control_message(f.owner, group_session_conversation(record['group_session']), 'group_add',
                                                create_group_add_body(f.owner, [third['publicKey']]))
        f.send(f.relay, f.cid, serialize_envelope(envelope))
        owner.sync(f.cid)
    if after_stage:
        expire(original, monkeypatch)
        release = owner._post_addition_rekey
        def race(cid, operation):
            add_third()
            release(cid, operation)
        monkeypatch.setattr(owner, '_post_addition_rekey', race)
        count = len(f.attempted)
        with pytest.raises(ValueError):
            owner.retry(f.cid)
        assert len(f.attempted) == count + 1  # Only the competing add, never stale wrapped keys.
        assert cli._load_conversations(f.owner_dir)[0]['group_operation']['kind'] == 'addition_rekey'
    else:
        add_third()
        count = len(f.attempted)
        owner.retry(f.cid)
        assert len(f.attempted) == count + 2
        welcome = opened(f, f.attempted[-1])
        assert welcome['purpose'] == 'renewal'
        assert set(welcome['admissions']) == {f.contact['keyID'].hex(), third['keyID'].hex()}
        assert all(value['completion'] for value in welcome['admissions'].values())


def test_failed_rotation_staging_keeps_original_intent_and_sends_nothing(setup, monkeypatch):
    f = setup
    owner, original = partial(f, monkeypatch)
    save = cli._save_conversations
    def fail(config, records):
        if records[0].get('group_operation', {}).get('kind') == 'addition_rekey':
            raise OSError('simulated atomic write failure')
        save(config, records)
    monkeypatch.setattr(cli, '_save_conversations', fail)
    before = len(f.attempted)
    with pytest.raises(OSError, match='atomic write'):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_resident_removal_after_reconciliation_blocks_stale_original_add_post(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    def unposted(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', unposted)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.add(f.cid, 'Colleague')
    monkeypatch.setattr(cli, '_http_send', f.send)
    original = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    reconcile = owner._reconcile_addition
    def race(cid, operation):
        stale = reconcile(cid, operation)
        f.send(f.relay, f.cid, base64.b64decode(original['controls'][0]))
        current = owner.sync(cid)
        removal = create_group_control_message(f.owner, group_session_conversation(current['group_session']), 'group_remove',
                                               create_group_remove_body([f.contact['keyID']]))
        f.send(f.relay, f.cid, serialize_envelope(removal))
        current = owner.sync(cid)
        current['group_session']['seen'] = {}
        cli._save_conversations(f.owner_dir, [current])
        return stale
    monkeypatch.setattr(owner, '_reconcile_addition', race)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='no longer'):
        owner.retry(f.cid)
    assert len(f.attempted) == before + 2  # Delayed accepted add and removal only.
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_second_expired_uncertain_rotation_preserves_evidence_and_completes_current_admission(setup, monkeypatch):
    f = setup
    owner, _ = partial(f, monkeypatch)
    def unposted(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', unposted)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.retry(f.cid)
    repair = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert repair['kind'] == 'addition_rekey'
    deadline = deserialize_envelope(base64.b64decode(repair['controls'][0]))['expiry_ts']
    monkeypatch.setattr('time.time', lambda: deadline + 1)
    monkeypatch.setattr(cli, '_http_send', f.send)
    count = len(f.attempted)
    renewal_journals = []
    def inspect(url, cid, wire):
        if deserialize_envelope(wire).get('kind') == 'group_welcome':
            renewal_journals.append(copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation']))
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', inspect)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert len(f.attempted) == count + 2
    assert renewal_journals[0]['superseded_operations'][0]['controls'] == repair['controls']
    assert 'expected' not in renewal_journals[0]['superseded_operations'][0]
    assert renewal_journals[0]['origin'] == repair['origin']
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1
