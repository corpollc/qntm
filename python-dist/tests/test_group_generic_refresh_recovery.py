"""Generic refresh retries retain recipient intent without becoming readmission."""
import base64
import copy

import pytest

from qntm import (cli, create_group_session, deserialize_envelope, open_group_welcome,
                  prepare_group_welcome_refresh, require_group_recovery, serialize_envelope)
from qntm.group_client import GroupClient, join
from test_group_client import setup
from test_group_operation_recovery import expire


def pending_refresh(f, monkeypatch, *, legacy=False, challenge='ab' * 32):
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    sender = GroupClient(f.contact_dir, f.contact, f.relay)

    def unknown(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', unknown)
    with pytest.raises(cli.SendDeliveryUnknown):
        sender.refresh(f.cid, f.owner['publicKey'].hex(), challenge)
    monkeypatch.setattr(cli, '_http_send', f.send)
    records = cli._load_conversations(f.contact_dir)
    if legacy:
        records[0]['group_operation'].pop('recipient')
        records[0]['group_operation'].pop('recovery_challenge')
        cli._save_conversations(f.contact_dir, records)
    return sender, copy.deepcopy(records[0]['group_operation'])


@pytest.mark.parametrize('legacy', [False, True])
@pytest.mark.parametrize('stale', ['expired', 'rotated', 'current'])
def test_refresh_retry_authenticates_founder_and_preserves_generic_delivery(setup, monkeypatch, legacy, stale):
    f = setup
    sender, original = pending_refresh(f, monkeypatch, legacy=legacy)
    if stale == 'expired':
        expire(original, monkeypatch)
    elif stale == 'rotated':
        GroupClient(f.owner_dir, f.owner, f.relay).change(f.cid)
    before = sender.sync(f.cid)
    observed = []

    def lose_ack(url, cid, wire):
        observed.append(copy.deepcopy(cli._load_conversations(f.contact_dir)[0]['group_operation']))
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', lose_ack)
    count = len(f.attempted)
    with pytest.raises(cli.SendDeliveryUnknown):
        GroupClient(f.contact_dir, f.contact, f.relay).retry(f.cid)
    assert len(f.attempted) == count + 1
    saved = observed[0]
    assert saved['kind'] == 'refresh' and saved['controls'] == []
    welcome = open_group_welcome(f.owner, f.attempted[-1], conversation_id=bytes.fromhex(f.cid), inviter_public_key=f.contact['publicKey'])
    assert welcome['purpose'] == 'refresh' and welcome['recovery_challenge'] == bytes.fromhex('ab' * 32)
    assert welcome['conversation']['keys']['root'].hex() == before['group_session']['root']
    if stale == 'current':
        assert saved == original
        assert f.attempted[-1] == base64.b64decode(original['welcomes'][0])
    else:
        assert welcome['replay_from_sequence'] == before['group_cursor']
        assert saved['recipient'] == f.owner['publicKey'].hex()
        assert saved['superseded_operations'] == [{key: original[key] for key in ('kind', 'controls', 'welcomes', 'welcomes_sent')} | {'delivery': 'unknown'}]
        assert saved['expected']['rekeys'] == []
    exact = f.attempted[-1]
    monkeypatch.setattr(cli, '_http_send', f.send)
    GroupClient(f.contact_dir, f.contact, f.relay).retry(f.cid)
    assert f.attempted[-1] == exact
    assert not cli._load_conversations(f.contact_dir)[0].get('group_operation')


@pytest.mark.parametrize('barrier', ['sender_removed', 'recovery', 'recipient_metadata', 'challenge_metadata', 'tampered_box'])
def test_invalid_refresh_intent_or_current_authority_keeps_journal_and_posts_nothing(setup, monkeypatch, barrier):
    f = setup
    sender, original = pending_refresh(f, monkeypatch)
    expire(original, monkeypatch)
    if barrier == 'sender_removed':
        GroupClient(f.owner_dir, f.owner, f.relay).change(f.cid, 'Colleague')
    records = cli._load_conversations(f.contact_dir)
    operation = records[0]['group_operation']
    if barrier == 'recovery':
        records[0]['group_session'] = require_group_recovery(records[0]['group_session'], records[0]['group_cursor'], 'missing_history')
    elif barrier == 'recipient_metadata':
        operation['recipient'] = f.contact['publicKey'].hex()
    elif barrier == 'challenge_metadata':
        operation['recovery_challenge'] = None
    elif barrier == 'tampered_box':
        value = deserialize_envelope(base64.b64decode(operation['welcomes'][0]))
        value['ciphertext'] = value['ciphertext'][:-1] + bytes([value['ciphertext'][-1] ^ 1])
        operation['welcomes'][0] = base64.b64encode(serialize_envelope(value)).decode()
    cli._save_conversations(f.contact_dir, records)
    saved = copy.deepcopy(operation)
    count = len(f.attempted)
    with pytest.raises(ValueError):
        sender.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.contact_dir)[0]['group_operation'] == saved


def test_repeated_generic_expiry_keeps_flat_evidence_and_enforces_bounds(setup, monkeypatch):
    f = setup
    sender, operation = pending_refresh(f, monkeypatch, challenge='')
    previous = []

    def unknown(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', unknown)
    for _ in range(3):
        previous.append(operation['welcomes'])
        expire(operation, monkeypatch)
        with pytest.raises(cli.SendDeliveryUnknown):
            sender.retry(f.cid)
        operation = copy.deepcopy(cli._load_conversations(f.contact_dir)[0]['group_operation'])
        assert [entry['welcomes'] for entry in operation['superseded_operations']] == previous
        assert all(set(entry) == {'kind', 'controls', 'welcomes', 'welcomes_sent', 'delivery'} for entry in operation['superseded_operations'])
        assert operation['recovery_challenge'] is None
    expire(operation, monkeypatch)
    monkeypatch.setattr('qntm.group_client.MAX_OPERATION_REVISIONS', 3)
    with pytest.raises(ValueError, match='limit'):
        sender.retry(f.cid)
    assert cli._load_conversations(f.contact_dir)[0]['group_operation'] == operation


@pytest.mark.parametrize('current', ['known_admission', 'removed', 'readmitted'])
def test_generic_refresh_does_not_upgrade_to_readmission_or_release_to_removed_recipient(setup, monkeypatch, current):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    state = owner.sync(f.cid)['group_session']
    refresh = prepare_group_welcome_refresh(f.owner, state, [f.contact['publicKey']], ttl=1)
    original = {'kind': 'refresh', 'controls': [], 'welcomes_sent': 0,
                'welcomes': [base64.b64encode(serialize_envelope(refresh['welcomes'][0])).decode()],
                'expected': create_group_session(f.owner, refresh['conversation'], refresh['state'],
                                                signed_epoch=state['signedEpoch'], admissions=state['admissions'])}
    if current != 'known_admission':
        owner.change(f.cid, 'Colleague')
        GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)
        if current == 'readmitted':
            owner.add(f.cid, 'Colleague')
    owner._save_operation(f.cid, original)
    expire(original, monkeypatch)
    count = len(f.attempted)
    if current == 'removed':
        with pytest.raises(ValueError, match='no longer a member'):
            owner.retry(f.cid)
        assert len(f.attempted) == count
        assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original
        return
    owner.retry(f.cid)
    wire = f.attempted[-1]
    welcome = open_group_welcome(f.contact, wire, conversation_id=bytes.fromhex(f.cid), inviter_public_key=f.owner['publicKey'])
    assert welcome['purpose'] == 'refresh'
    if current == 'readmitted':
        # Observe only the generic replacement, never the newer addition welcome.
        from qntm import group_session_from_welcome
        saved = cli._load_conversations(f.contact_dir)[0]['group_session']
        assert saved['removed']
        with pytest.raises(ValueError, match='removal'):
            group_session_from_welcome(f.contact, welcome, len(f.rows[f.cid]), saved)


def test_refresh_staging_failure_preserves_exact_previous_ciphertext(setup, monkeypatch):
    f = setup
    sender, original = pending_refresh(f, monkeypatch)
    expire(original, monkeypatch)
    save = cli._save_conversations

    def fail(config, records):
        if records[0].get('group_operation', {}).get('superseded_operations'):
            raise OSError('atomic refresh write failed')
        save(config, records)

    monkeypatch.setattr(cli, '_save_conversations', fail)
    count = len(f.attempted)
    with pytest.raises(OSError, match='atomic'):
        sender.retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.contact_dir)[0]['group_operation'] == original
