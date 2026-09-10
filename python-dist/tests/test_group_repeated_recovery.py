"""Repeated delivery-window misses reconcile the same admitted member safely."""
import base64
import copy

import pytest

from qntm import (cli, create_group_control_message, create_group_remove_body, deserialize_envelope,
                  group_session_conversation, prepare_group_session_rekey, serialize_envelope,
                  require_group_recovery)
from qntm.group_client import GroupClient, join
from test_group_client import setup
from test_group_operation_recovery import expire, opened, pending
from test_group_rotation_recovery import partial


def saved_renewal(f, monkeypatch, *, direct=False):
    if direct:
        owner = GroupClient(f.owner_dir, f.owner, f.relay)
        owner.add(f.cid, 'Colleague')
    else:
        owner, addition = pending(f, monkeypatch, 'cd' * 32)
        expire(addition, monkeypatch)
    def unposted(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', unposted)
    with pytest.raises(cli.SendDeliveryUnknown):
        if direct:
            owner.refresh(f.cid, 'Colleague', 'cd' * 32)
        else:
            owner.retry(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    return owner, copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])


@pytest.mark.parametrize('direct,stale', [(False, 'expired'), (True, 'expired'),
                                        (False, 'later_rotation'), (True, 'later_rotation'),
                                        (True, 'competing_completion')])
def test_repeated_renewal_reconciles_current_proof_and_preserves_exact_prior_ciphertext(setup, monkeypatch, direct, stale):
    f = setup
    owner, original = saved_renewal(f, monkeypatch, direct=direct)
    if stale == 'expired':
        expire(original, monkeypatch)
    else:
        state = owner.sync(f.cid)['group_session']
        if stale == 'competing_completion':
            frame = state['rekeys'][0]
            state = {**state, 'epoch': frame['epoch'], 'root': frame['root'], 'snapshot': frame['snapshot'],
                     'rekeys': [], 'seen': {}, 'admissions': copy.deepcopy(frame['admissions']), 'needsRekey': True}
        with monkeypatch.context() as fixed:
            fixed.setattr('qntm.message.generate_message_id', lambda: b'\x00' * 16)
            rotation = prepare_group_session_rekey(f.owner, state)['rekey']
        f.send(f.relay, f.cid, serialize_envelope(rotation))
        owner.sync(f.cid)
    before = owner.sync(f.cid)
    saved = []
    def lose_ack(url, cid, wire):
        saved.append(copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation']))
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', lose_ack)
    count = len(f.attempted)
    with pytest.raises(cli.SendDeliveryUnknown):
        GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert len(f.attempted) == count + 1
    operation = saved[0]
    assert operation['superseded_operations'][0]['welcomes'] == original['welcomes']
    assert 'expected' not in operation['superseded_operations'][0]
    assert operation.get('origin') == original.get('origin')
    welcome = opened(f, f.attempted[-1])
    assert welcome['purpose'] == 'renewal' and welcome['recovery_challenge'] == bytes.fromhex('cd' * 32)
    assert welcome['admissions'] == before['group_session']['admissions']
    assert welcome['conversation']['keys']['root'].hex() == before['group_session']['root']
    exact = f.attempted[-1]
    monkeypatch.setattr(cli, '_http_send', f.send)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert f.attempted[-1] == exact
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == before['current_epoch']


@pytest.mark.parametrize('barrier', ['removed', 'recovery', 'different_admission'])
def test_stale_renewal_never_bypasses_current_authority_barriers(setup, monkeypatch, barrier):
    f = setup
    owner, original = saved_renewal(f, monkeypatch)
    expire(original, monkeypatch)
    records = cli._load_conversations(f.owner_dir)
    state = records[0]['group_session']
    if barrier == 'removed':
        removal = create_group_control_message(f.owner, group_session_conversation(state), 'group_remove',
                                               create_group_remove_body([f.contact['keyID']]))
        f.send(f.relay, f.cid, serialize_envelope(removal))
        owner.sync(f.cid)
    else:
        if barrier == 'recovery':
            records[0]['group_session'] = require_group_recovery(state, records[0]['group_cursor'], 'missing_history')
        else:
            state['admissions'][f.contact['keyID'].hex()]['addId'] = '01' * 16
        cli._save_conversations(f.owner_dir, records)
    count = len(f.attempted)
    with pytest.raises(ValueError):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


@pytest.mark.parametrize('phase', ['renewal', 'rotation'])
@pytest.mark.parametrize('bound', ['revisions', 'bytes'])
def test_recovery_evidence_bounds_preserve_current_journal_and_send_nothing(setup, monkeypatch, phase, bound):
    f = setup
    if phase == 'renewal':
        owner, original = saved_renewal(f, monkeypatch)
        expire(original, monkeypatch)
    else:
        owner, _ = partial(f, monkeypatch)
        def unposted(url, cid, wire):
            raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
        monkeypatch.setattr(cli, '_http_send', unposted)
        with pytest.raises(cli.SendDeliveryUnknown):
            owner.retry(f.cid)
        original = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
        deadline = deserialize_envelope(base64.b64decode(original['controls'][0]))['expiry_ts']
        monkeypatch.setattr('time.time', lambda: deadline + 1)
        monkeypatch.setattr(cli, '_http_send', f.send)
    if bound == 'revisions':
        monkeypatch.setattr('qntm.group_client.MAX_OPERATION_REVISIONS', 0)
    else:
        monkeypatch.setattr('qntm.group_client.MAX_OPERATION_EVIDENCE_BYTES', 1)
    count = len(f.attempted)
    with pytest.raises(ValueError, match='limit'):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_failed_stale_renewal_staging_preserves_previous_evidence_and_sends_nothing(setup, monkeypatch):
    f = setup
    owner, original = saved_renewal(f, monkeypatch)
    expire(original, monkeypatch)
    save = cli._save_conversations
    def fail(config, records):
        if records[0].get('group_operation', {}).get('superseded_operations'):
            raise OSError('atomic renewal write failed')
        save(config, records)
    monkeypatch.setattr(cli, '_save_conversations', fail)
    count = len(f.attempted)
    with pytest.raises(OSError, match='atomic'):
        owner.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_three_replacements_keep_evidence_order_flat_and_original_intent_unchanged(setup, monkeypatch):
    f = setup
    owner, original = saved_renewal(f, monkeypatch)
    operation = original
    previous_welcomes = []
    def unposted(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', unposted)
    for _ in range(3):
        previous_welcomes.append(operation['welcomes'])
        expire(operation, monkeypatch)
        with pytest.raises(cli.SendDeliveryUnknown):
            owner.retry(f.cid)
        operation = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
        evidence = operation['superseded_operations']
        assert [entry['welcomes'] for entry in evidence] == previous_welcomes
        assert all(set(entry) == {'kind', 'controls', 'welcomes', 'welcomes_sent', 'delivery'} for entry in evidence)
        assert operation['origin'] == original['origin']


def test_competing_branch_that_requires_expired_control_replay_stays_in_recovery(setup, monkeypatch):
    f = setup
    owner, original = saved_renewal(f, monkeypatch)
    state = owner.sync(f.cid)['group_session']
    frame = state['rekeys'][0]
    source = {**state, 'epoch': frame['epoch'], 'root': frame['root'], 'snapshot': frame['snapshot'],
              'rekeys': [], 'seen': {}, 'admissions': copy.deepcopy(frame['admissions']), 'needsRekey': True}
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x00' * 16)
        rotation = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(rotation))
    count = len(f.attempted)
    with pytest.raises(ValueError, match='incomplete'):
        owner.retry(f.cid)
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_session']['recovery']
    assert record['group_operation'] == original
    assert len(f.attempted) == count
