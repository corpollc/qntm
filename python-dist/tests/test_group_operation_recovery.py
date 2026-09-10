"""Explicit retry reconciles accepted admission, never repeats obsolete controls."""
import base64
import contextlib
import copy
import time

import pytest

from qntm import (
    cli, serialize_envelope, deserialize_envelope, prepare_group_session_rekey, open_group_welcome,
    create_group_control_message, create_group_remove_body, group_session_conversation,
    prepare_group_session_addition, require_group_recovery, generate_identity,
)
from qntm.group_client import GroupClient, join, set_contact
from test_group_client import setup


def pending(f, monkeypatch, challenge=''):
    def fail(url, cid, wire):
        if deserialize_envelope(wire).get('kind') == 'group_welcome':
            raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', fail)
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.add(f.cid, 'Colleague', challenge)
    monkeypatch.setattr(cli, '_http_send', f.send)
    return owner, copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])


def expire(operation, monkeypatch):
    at = deserialize_envelope(base64.b64decode(operation['welcomes'][0]))['expiry_ts'] + 1
    monkeypatch.setattr(time, 'time', lambda: at)


def opened(f, wire):
    return open_group_welcome(f.contact, wire, conversation_id=bytes.fromhex(f.cid), inviter_public_key=f.owner['publicKey'])


def test_expired_welcome_retry_posts_only_a_new_renewal_and_survives_lost_ack(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    expire(original, monkeypatch)
    sent = []
    def lose_ack(url, cid, wire):
        record = cli._load_conversations(f.owner_dir)[0]
        assert record['group_operation']['kind'] == 'renewal'
        assert record['group_operation']['origin']['controls'] == original['controls']
        assert 'expected' not in record['group_operation']['origin']
        sent.append(wire)
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', lose_ack)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.retry(f.cid)
    assert len(sent) == 1 and opened(f, sent[0])['purpose'] == 'renewal'
    saved = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert saved['welcomes_sent'] == 0
    monkeypatch.setattr(cli, '_http_send', f.send)
    before = len(f.attempted)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert f.attempted[before:] == sent
    assert len(f.rows[f.cid]) == 4  # One genesis/add/rekey/renewal, despite uncertain POST.
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


@pytest.mark.parametrize('competing', [False, True])
def test_retry_uses_canonical_provenance_after_rotation_or_competing_rekey(setup, monkeypatch, competing):
    f = setup
    with monkeypatch.context() as fixed:
        ids = iter([b'\x80' * 16, b'\xf0' * 16])
        fixed.setattr('qntm.message.generate_message_id', lambda: next(ids))
        owner, original = pending(f, fixed)
    state = owner.sync(f.cid)['group_session']
    source = copy.deepcopy(state)
    if competing:
        frame = state['rekeys'][0]
        source.update(epoch=frame['epoch'], root=frame['root'], snapshot=frame['snapshot'],
                      rekeys=[], seen={}, admissions=copy.deepcopy(frame['admissions']), needsRekey=True)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        rotation = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(rotation))
    current = owner.sync(f.cid)
    current['group_session']['seen'] = {}  # Bounded cache has evicted the original controls.
    cli._save_conversations(f.owner_dir, [current])
    before = len(f.attempted)
    result = owner.retry(f.cid)
    assert len(f.attempted[before:]) == 1
    welcome = opened(f, f.attempted[-1])
    assert welcome['purpose'] == 'renewal'
    assert welcome['conversation']['keys']['root'].hex() == current['group_session']['root']
    assert welcome['replay_from_sequence'] == current['group_cursor']
    assert welcome['admissions'][f.contact['keyID'].hex()]['addId'] == deserialize_envelope(base64.b64decode(original['controls'][0]))['msg_id'].hex()
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == current['current_epoch']


@pytest.mark.parametrize('legacy_journal', [False, True])
def test_reconciliation_preserves_the_original_optional_recovery_challenge(setup, monkeypatch, legacy_journal):
    f = setup
    challenge = '42' * 32
    owner, original = pending(f, monkeypatch, challenge)
    if legacy_journal:
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_operation'].pop('recovery_challenge')
        cli._save_conversations(f.owner_dir, records)
    expire(original, monkeypatch)
    owner.retry(f.cid)
    assert opened(f, f.attempted[-1])['recovery_challenge'] == bytes.fromhex(challenge)


def test_valid_exact_retry_keeps_ciphertext_even_after_seen_eviction(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    records = cli._load_conversations(f.owner_dir)
    records[0]['group_session']['seen'] = {}
    cli._save_conversations(f.owner_dir, records)
    before = len(f.attempted)
    owner.retry(f.cid)
    assert f.attempted[before:] == [base64.b64decode(original['welcomes'][0])]


def test_acknowledged_welcome_cleanup_does_not_replay_old_controls(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    f.send(f.relay, f.cid, base64.b64decode(original['welcomes'][0]))
    records = cli._load_conversations(f.owner_dir)
    records[0]['group_operation']['welcomes_sent'] = 1  # Durable ACK saved, then process killed before cleanup.
    records[0]['group_session']['seen'] = {}
    records[0]['group_session']['removed'] = True
    cli._save_conversations(f.owner_dir, records)
    before = len(f.attempted)
    owner.retry(f.cid)
    assert len(f.attempted) == before and not cli._load_conversations(f.owner_dir)[0].get('group_operation')


@pytest.mark.parametrize('readmit', [False, True])
def test_removed_or_different_admission_never_releases_the_saved_welcome(setup, monkeypatch, readmit):
    f = setup
    owner, original = pending(f, monkeypatch)
    state = owner.sync(f.cid)['group_session']
    removal = create_group_control_message(f.owner, group_session_conversation(state), 'group_remove', create_group_remove_body([f.contact['keyID']]))
    f.send(f.relay, f.cid, serialize_envelope(removal))
    state = owner.sync(f.cid)['group_session']
    f.send(f.relay, f.cid, serialize_envelope(prepare_group_session_rekey(f.owner, state)['rekey']))
    state = owner.sync(f.cid)['group_session']
    if readmit:
        addition = prepare_group_session_addition(f.owner, state, [f.contact['publicKey']])
        for envelope in (addition['addition'], addition['rekey'], *addition['welcomes']):
            f.send(f.relay, f.cid, serialize_envelope(envelope))
        owner.sync(f.cid)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='no longer'):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_new_recovery_barrier_between_reconciliation_and_release_blocks_post(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    expire(original, monkeypatch)
    reconcile = owner._reconcile_addition
    def new_gap(cid, operation):
        result = reconcile(cid, operation)
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_session'] = require_group_recovery(records[0]['group_session'], records[0]['group_cursor'], 'missing_history')
        cli._save_conversations(f.owner_dir, records)
        return result
    monkeypatch.setattr(owner, '_reconcile_addition', new_gap)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='incomplete'):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation']['kind'] == 'renewal' and record['group_session']['recovery']


def test_pending_operation_changed_after_sync_is_not_overwritten(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    expire(original, monkeypatch)
    reconcile = owner._reconcile_addition
    def changed(cid, operation):
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_operation']['recovery_challenge'] = 'ab' * 32
        cli._save_conversations(f.owner_dir, records)
        return reconcile(cid, operation)
    monkeypatch.setattr(owner, '_reconcile_addition', changed)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='changed'):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation']['recovery_challenge'] == 'ab' * 32


def test_partial_add_with_expired_rekey_finishes_rotation_without_new_admission(setup, monkeypatch):
    f = setup
    count = 0
    def partial(url, cid, wire):
        nonlocal count
        count += 1
        if count == 2:
            raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', partial)
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.add(f.cid, 'Colleague')
    original = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    expire(original, monkeypatch)
    monkeypatch.setattr(cli, '_http_send', f.send)
    before = len(f.attempted)
    result = owner.retry(f.cid)
    assert len(f.attempted) == before + 2
    assert opened(f, f.attempted[-1])['purpose'] == 'renewal'
    assert all(wire not in [base64.b64decode(value) for value in original['controls']] for wire in f.attempted[before:])
    record = cli._load_conversations(f.owner_dir)[0]
    assert not record.get('group_operation') and not record['group_session']['needsRekey']
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


def test_removed_sender_cannot_renew_a_contact_it_previously_added(setup, monkeypatch):
    f = setup
    creator = GroupClient(f.owner_dir, f.owner, f.relay)
    link = creator.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    third = generate_identity()
    g = copy.copy(f)
    g.owner, g.contact, g.owner_dir, g.contact_dir = f.contact, third, f.contact_dir, f.contact_dir + '-third'
    cli._save_identity(g.contact_dir, third)
    set_contact(g.owner_dir, 'Colleague', third['publicKey'].hex())
    sender, original = pending(g, monkeypatch)
    creator.change(f.cid, 'Colleague')
    before = len(f.attempted)
    with pytest.raises(ValueError, match='removed'):
        sender.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(g.owner_dir)[0]['group_operation'] == original


def test_initial_welcome_expiring_while_waiting_for_release_lock_is_not_posted(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    expiry = deserialize_envelope(base64.b64decode(original['welcomes'][0]))['expiry_ts']
    clock = [expiry - 1]
    monkeypatch.setattr(time, 'time', lambda: clock[0])
    lock = owner._lock
    @contextlib.contextmanager
    def delayed_lock():
        with lock():
            clock[0] = expiry + 1
            yield
    monkeypatch.setattr(owner, '_lock', delayed_lock)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='expired'):
        owner._resume(f.cid)  # Initial-send path, without reconciliation.
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_failed_renewal_staging_preserves_original_intent_and_posts_nothing(setup, monkeypatch):
    f = setup
    owner, original = pending(f, monkeypatch)
    expire(original, monkeypatch)
    save = cli._save_conversations
    def fail_staging(directory, records):
        if records[0].get('group_operation', {}).get('kind') == 'renewal':
            raise OSError('disk write failed before atomic replacement')
        return save(directory, records)
    monkeypatch.setattr(cli, '_save_conversations', fail_staging)
    before = len(f.attempted)
    with pytest.raises(OSError):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original


def test_tampered_legacy_welcome_challenge_does_not_replace_pending_journal(setup, monkeypatch):
    from qntm import unmarshal, marshal_canonical
    from qntm.gate import open_secret, seal_secret
    f = setup
    owner, original = pending(f, monkeypatch, '42' * 32)
    records = cli._load_conversations(f.owner_dir)
    operation = records[0]['group_operation']
    operation.pop('recovery_challenge')
    envelope = deserialize_envelope(base64.b64decode(operation['welcomes'][0]))
    signed = unmarshal(open_secret(f.owner['privateKey'], f.contact['publicKey'], envelope['ciphertext']))
    signed['payload']['recovery_challenge'] = bytes(32)  # Box creator cannot alter the sender's signed payload.
    envelope['ciphertext'] = seal_secret(f.owner['privateKey'], f.contact['publicKey'], marshal_canonical(signed))
    operation['welcomes'][0] = base64.b64encode(serialize_envelope(envelope)).decode()
    cli._save_conversations(f.owner_dir, records)
    original = copy.deepcopy(operation)
    expire(original, monkeypatch)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='challenge binding'):
        owner.retry(f.cid)
    assert len(f.attempted) == before
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original
