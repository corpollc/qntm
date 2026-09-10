"""Existing CLI/MCP refresh chooses proven admission renewal without readmitting."""
import base64
import copy

import pytest

from qntm import cli, deserialize_envelope, open_group_welcome, prepare_group_session_addition, serialize_envelope
from qntm.group_client import GroupClient, join
from test_group_client import setup


@pytest.mark.parametrize('host', ['cli', 'mcp'])
def test_refresh_recovers_expired_later_readmission_without_excluded_roots(setup, monkeypatch, host):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    owner.change(f.cid, 'Colleague')
    GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)
    f.command(f.owner_dir, 'send', f.cid, 'during exclusion')
    current = owner.sync(f.cid)
    excluded_root = current['group_session']['root']
    addition = prepare_group_session_addition(f.owner, current['group_session'], [f.contact['publicKey']], ttl=1,
                                              replay_from_sequence=current['group_cursor'])
    for envelope in (addition['addition'], addition['rekey'], *addition['welcomes']):
        f.send(f.relay, f.cid, serialize_envelope(envelope))
    owner.sync(f.cid)
    monkeypatch.setattr('time.time', lambda: addition['welcomes'][0]['expiry_ts'] + 1)
    owner.change(f.cid)
    before = owner.sync(f.cid)
    count = len(f.attempted)
    if host == 'cli':
        result = f.command(f.owner_dir, 'group', 'refresh', f.cid, 'Colleague')
    else:
        from qntm import mcp_server as mcp
        monkeypatch.setenv('QNTM_CONFIG_DIR', f.owner_dir)
        monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
        result = mcp.group_refresh(f.cid, 'Colleague')
    assert result['group_link'] == link
    assert len(f.attempted) == count + 1
    opened = open_group_welcome(f.contact, f.attempted[-1], conversation_id=bytes.fromhex(f.cid), inviter_public_key=f.owner['publicKey'])
    assert opened['purpose'] == 'renewal'
    assert opened['admissions'] == before['group_session']['admissions']
    assert opened['replay_from_sequence'] == before['group_cursor']
    after = owner.sync(f.cid)
    assert after['keys'] == before['keys'] and after['participants'] == before['participants']
    assert join(f.contact_dir, f.contact, link)['current_epoch'] == 4
    restored = cli._load_conversations(f.contact_dir)[0]['group_session']
    assert restored['removedAtEpoch'] == 1 and restored['rekeys'] == []
    assert restored['root'] != excluded_root and not restored['removed']
    assert all(row.get('unsafe_body') != 'during exclusion' for row in cli._load_history(f.contact_dir, f.cid))
    f.command(f.contact_dir, 'send', f.cid, 'renewed after removal')
    assert any(row.get('unsafe_body') == 'renewed after removal' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


@pytest.mark.parametrize('target', ['founder', 'unknown'])
def test_refresh_without_complete_admission_keeps_generic_domain(setup, target):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    owner.add(f.cid, 'Colleague')
    if target == 'unknown':
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_session']['admissions'] = {}
        cli._save_conversations(f.owner_dir, records)
    recipient = f.owner if target == 'founder' else f.contact
    owner.refresh(f.cid, recipient['publicKey'].hex())
    opened = open_group_welcome(recipient, f.attempted[-1], conversation_id=bytes.fromhex(f.cid), inviter_public_key=f.owner['publicKey'])
    assert opened['purpose'] == 'refresh'


def test_refresh_journal_binds_provenance_and_challenge_and_rechecks_before_release(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    owner.add(f.cid, 'Colleague')
    def uncertain(url, cid, wire):
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
    monkeypatch.setattr(cli, '_http_send', uncertain)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.refresh(f.cid, 'Colleague', 'ad' * 32)
    original = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert original['kind'] == 'renewal' and 'origin' not in original
    assert original['recipient'] == f.contact['publicKey'].hex()
    assert original['admission'] == original['expected']['admissions'][f.contact['keyID'].hex()]
    opened = open_group_welcome(f.contact, base64.b64decode(original['welcomes'][0]),
                                conversation_id=bytes.fromhex(f.cid), inviter_public_key=f.owner['publicKey'])
    assert opened['recovery_challenge'] == bytes.fromhex('ad' * 32)
    records = cli._load_conversations(f.owner_dir)
    records[0]['group_session']['admissions'][f.contact['keyID'].hex()]['addDigest'] = '01' * 32
    cli._save_conversations(f.owner_dir, records)
    monkeypatch.setattr(cli, '_http_send', f.send)
    count = len(f.attempted)
    with pytest.raises(ValueError, match='admission|provenance'):
        GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert len(f.attempted) == count
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == original
