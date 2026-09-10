"""A resident receiver can invalidate a producer's earlier replay snapshot."""
import base64
import copy
import contextlib

import pytest

from qntm import cli, deserialize_envelope, require_group_recovery, receive_group_event
from qntm.group_client import GroupClient, join
from test_group_client import setup


def staged_member_rekey(f, monkeypatch):
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    member = GroupClient(f.contact_dir, f.contact, f.relay)
    def unposted(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', unposted)
    with monkeypatch.context() as ids:
        ids.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        with pytest.raises(cli.SendDeliveryUnknown):
            member.change(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    original = copy.deepcopy(cli._load_conversations(f.contact_dir)[0]['group_operation'])
    return owner, member, original


def test_resident_removal_after_producer_sync_blocks_saved_rekey_post(setup, monkeypatch):
    f = setup
    owner, member, original = staged_member_rekey(f, monkeypatch)
    sync = member.sync
    injected = False
    def race(cid):
        nonlocal injected
        stale = sync(cid)
        if not injected:
            injected = True
            owner.change(cid, 'Colleague')
            assert sync(cid)['group_session']['removed']
        return stale
    monkeypatch.setattr(member, 'sync', race)
    before = len(f.attempted)
    with pytest.raises(ValueError, match='removed'):
        member.retry(f.cid)
    old_wire = base64.b64decode(original['controls'][0])
    assert old_wire not in f.attempted[before:]
    assert cli._load_conversations(f.contact_dir)[0]['group_operation'] == original


@pytest.mark.parametrize('change', ['recovery', 'new_epoch', 'journal', 'expiry'])
def test_control_release_reloads_latest_authority_journal_and_clock(setup, monkeypatch, change):
    f = setup
    owner, member, original = staged_member_rekey(f, monkeypatch)
    release = member._post_group_control
    def race(cid, operation, wire):
        records = cli._load_conversations(f.contact_dir)
        if change == 'recovery':
            records[0]['group_session'] = require_group_recovery(records[0]['group_session'], records[0]['group_cursor'], 'missing_history')
            cli._save_conversations(f.contact_dir, records)
        elif change == 'new_epoch':
            with monkeypatch.context() as ids:
                ids.setattr('qntm.message.generate_message_id', lambda: b'\xf0' * 16)
                owner.change(cid)
            current = member.sync(cid)
            # Receiver competition remains legal; a producer that has learned
            # the newer epoch must not intentionally POST its old proposal.
            assert receive_group_event(f.contact, deserialize_envelope(wire), current['group_session'])['state']['root'] != current['group_session']['root']
        elif change == 'journal':
            records[0]['group_operation']['welcomes_sent'] = 1
            cli._save_conversations(f.contact_dir, records)
        else:
            expiry = deserialize_envelope(wire)['expiry_ts']
            monkeypatch.setattr('time.time', lambda: expiry + 1)
        release(cid, operation, wire)
    monkeypatch.setattr(member, '_post_group_control', race)
    before = len(f.attempted)
    with pytest.raises(ValueError):
        member.retry(f.cid)
    assert base64.b64decode(original['controls'][0]) not in f.attempted[before:]
    assert cli._load_conversations(f.contact_dir)[0].get('group_operation')


def test_control_post_and_acknowledgement_keep_the_receive_lock(setup, monkeypatch):
    f = setup
    _, member, _ = staged_member_rekey(f, monkeypatch)
    lock = member._lock
    held = False
    @contextlib.contextmanager
    def tracked():
        nonlocal held
        with lock():
            held = True
            try:
                yield
            finally:
                held = False
    monkeypatch.setattr(member, '_lock', tracked)
    calls = []
    def checked(url, cid, wire):
        assert held
        calls.append(wire)
        return f.send(url, cid, wire)
    monkeypatch.setattr(cli, '_http_send', checked)
    member.retry(f.cid)
    assert len(calls) == 1
    assert not cli._load_conversations(f.contact_dir)[0].get('group_operation')
