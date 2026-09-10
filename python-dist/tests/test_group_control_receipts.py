"""Pending control delivery proof outlives the bounded replay cache."""
import base64
import copy

import pytest

from qntm import (cli, create_message, deserialize_envelope, group_session_conversation,
                  prepare_group_session_rekey, serialize_envelope)
from qntm.group_client import GroupClient, _control_accepted, join
from test_group_client import setup


def accepted_pending_rekey(f, monkeypatch):
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    source = copy.deepcopy(owner.sync(f.cid)['group_session'])

    def lose_ack(url, cid, wire):
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', lose_ack)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xf0' * 16)
        with pytest.raises(cli.SendDeliveryUnknown):
            owner.change(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    record = owner.sync(f.cid)
    return owner, source, copy.deepcopy(record['group_operation'])


def evict_with_authenticated_traffic(f, owner, monkeypatch):
    record = owner.sync(f.cid)
    # Exercise the real eviction algorithm with a small legal bound, rather
    # than deleting replay state or producing thousands of crypto-only clones.
    monkeypatch.setattr('qntm.group_session._MAX_SEEN', max(8, len(record['group_session']['seen'])))
    for index in range(16):
        message = create_message(f.contact, group_session_conversation(record['group_session']), 'text', f'cache pressure {index}'.encode())
        f.send(f.relay, f.cid, serialize_envelope(message))
    return owner.sync(f.cid)


@pytest.mark.parametrize('later_rotation', [False, True])
def test_exact_control_history_finishes_retry_after_real_cache_eviction(setup, monkeypatch, later_rotation):
    f = setup
    owner, _, operation = accepted_pending_rekey(f, monkeypatch)
    wire = base64.b64decode(operation['controls'][0])
    mid = deserialize_envelope(wire)['msg_id'].hex()
    record = evict_with_authenticated_traffic(f, owner, monkeypatch)
    assert mid not in record['group_session']['seen']
    assert _control_accepted(record, wire)
    if later_rotation:
        rotation = prepare_group_session_rekey(f.contact, GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)['group_session'])
        f.send(f.relay, f.cid, serialize_envelope(rotation['rekey']))
    before = len(f.attempted)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert result['current_epoch'] == (3 if later_rotation else 2)
    assert len(f.attempted) == before
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')


def test_losing_rekey_history_overrides_its_retained_seen_marker(setup, monkeypatch):
    f = setup
    owner, source, operation = accepted_pending_rekey(f, monkeypatch)
    wire = base64.b64decode(operation['controls'][0])
    mid = deserialize_envelope(wire)['msg_id'].hex()
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        competing = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(competing))
    record = owner.sync(f.cid)
    assert mid in record['group_session']['seen']
    assert not _control_accepted(record, wire)
    assert any(row['msg_id'] == mid and row['receive_binding']['valid'] is False for row in record['group_history'])
    before = len(f.attempted)
    # The losing rotation is never republished; the verified competitor already
    # rotated keys away from the intent's source epoch, which fulfils it.
    assert owner.retry(f.cid)['current_epoch'] == record['group_session']['epoch']
    assert len(f.attempted) == before
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')


def test_losing_descendant_control_history_does_not_finish_retry(setup, monkeypatch):
    f = setup
    owner, source, _ = accepted_pending_rekey(f, monkeypatch)
    GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')

    def lose_ack(url, cid, wire):
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', lose_ack)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xf1' * 16)
        with pytest.raises(cli.SendDeliveryUnknown):
            GroupClient(f.owner_dir, f.owner, f.relay).change(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    descendant = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    wire = base64.b64decode(descendant['controls'][0])
    mid = deserialize_envelope(wire)['msg_id'].hex()
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    owner.sync(f.cid)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        competing = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(competing))
    record = owner.sync(f.cid)
    assert mid not in record['group_session']['seen']
    row = next(row for row in record['group_history'] if row['msg_id'] == mid)
    assert row['verified'] is True and row['receive_binding']['valid'] is False
    assert row['sequence'] > 0 and row['receive_binding']['epoch'] == deserialize_envelope(wire)['conv_epoch']
    assert not _control_accepted(record, wire)
    assert record['group_session']['epoch'] == deserialize_envelope(wire)['conv_epoch']
    before = len(f.attempted)
    # Invalidated history never finishes the descendant. Its source epoch is
    # current again on the winning branch, so a fresh current-roster rotation
    # replaces the unusable exact bytes instead of republishing them.
    result = owner.retry(f.cid)
    assert result['current_epoch'] == record['group_session']['epoch'] + 1
    assert f.attempted[before:] != [wire] and len(f.attempted[before:]) == 1
    assert deserialize_envelope(f.attempted[-1])['conv_epoch'] == record['group_session']['epoch']
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')
    assert GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)['group_session']['root'] == cli._load_conversations(f.owner_dir)[0]['group_session']['root']


def test_challenged_welcome_replacement_does_not_keep_earlier_control_proof(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    with monkeypatch.context() as fixed:
        ids = iter([b'\x80' * 16, b'\xf0' * 16])
        fixed.setattr('qntm.message.generate_message_id', lambda: next(ids))
        link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    member = GroupClient(f.contact_dir, f.contact, f.relay)
    saved = owner.sync(f.cid)['group_session']

    def lose_ack(url, cid, wire):
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', lose_ack)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xee' * 16)
        with pytest.raises(cli.SendDeliveryUnknown):
            member.change(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    operation = copy.deepcopy(cli._load_conversations(f.contact_dir)[0]['group_operation'])
    wire = base64.b64decode(operation['controls'][0])
    mid = deserialize_envelope(wire)['msg_id'].hex()
    assert _control_accepted(member.sync(f.cid), wire)

    source = copy.deepcopy(saved)
    frame = source['rekeys'][0]
    source.update(epoch=frame['epoch'], root=frame['root'], snapshot=frame['snapshot'], rekeys=[], seen={},
                  admissions=copy.deepcopy(frame['admissions']), needsRekey=True)
    with monkeypatch.context() as fixed:
        # Higher ID than the admitted rekey: owner treats it as superseded; the
        # member has no epoch-0 frame and must pause for a challenged welcome.
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xff' * 16)
        unverifiable = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(unverifiable))
    blocked = member.sync(f.cid)['group_session']
    assert blocked['recovery']
    owner.refresh(f.cid, 'Colleague', blocked['recovery']['challenge'])
    join(f.contact_dir, f.contact, link)
    record = cli._load_conversations(f.contact_dir)[0]
    assert record.get('group_operation') == operation
    row = next(row for row in record['group_history'] if row['msg_id'] == mid)
    assert row['verified'] is True and row['receive_binding']['valid'] is False
    assert not _control_accepted(record, wire)
    assert record['group_session']['epoch'] > deserialize_envelope(wire)['conv_epoch']
    before = len(f.attempted)
    # The replaced checkpoint attests a later epoch; the old rotation intent is
    # fulfilled without claiming its own delivery or republishing old bytes.
    assert GroupClient(f.contact_dir, f.contact, f.relay).retry(f.cid)['current_epoch'] == record['group_session']['epoch']
    assert len(f.attempted) == before
    assert not cli._load_conversations(f.contact_dir)[0].get('group_operation')


@pytest.mark.parametrize('evidence', ['missing', 'wrong_digest', 'wrong_epoch', 'unverified', 'future_sequence', 'invalidated'])
def test_invalid_or_missing_history_does_not_invent_delivery_after_eviction(setup, monkeypatch, evidence):
    f = setup
    owner, _, operation = accepted_pending_rekey(f, monkeypatch)
    wire = base64.b64decode(operation['controls'][0])
    mid = deserialize_envelope(wire)['msg_id'].hex()
    record = evict_with_authenticated_traffic(f, owner, monkeypatch)
    row = next(row for row in record['group_history'] if row['msg_id'] == mid)
    if evidence == 'missing':
        record['group_history'].remove(row)
    elif evidence == 'wrong_digest':
        row['receive_binding']['digest'] = '00' * 32
    elif evidence == 'wrong_epoch':
        row['receive_binding']['epoch'] += 1
    elif evidence == 'unverified':
        row['verified'] = False
    elif evidence == 'future_sequence':
        row['sequence'] = record['group_cursor'] + 1
    else:
        row['receive_binding']['valid'] = False
    assert not _control_accepted(record, wire)
    cli._save_conversations(f.owner_dir, [record])
    before = len(f.attempted)
    # No delivery is invented: the exact bytes are never republished into an
    # obsolete epoch, and the verified later epoch alone fulfils a rotation intent.
    assert owner.retry(f.cid)['current_epoch'] == record['group_session']['epoch']
    assert len(f.attempted) == before
    assert not cli._load_conversations(f.owner_dir)[0].get('group_operation')
    if evidence == 'missing':
        # Contrast: an accepted removal awaiting its rotation needs real proof.
        assert not _control_accepted(record, wire)
