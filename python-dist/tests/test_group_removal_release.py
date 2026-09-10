"""Explicit local release of a stale, unproven saved removal: no POST, no acceptance claim, evidence kept."""
import copy

import pytest

from qntm import (cli, create_group_add_body, create_group_remove_body, deserialize_envelope, generate_identity,
                  marshal_canonical, prepare_group_session_rekey, require_group_recovery, serialize_envelope)
from qntm.group_client import GroupClient, _control_accepted, join, set_contact
from test_group_client import setup
from test_group_removal_recovery import add_member, craft, encoded_wire, expire_rekey, stage_removal


def stage_unposted_removal(f, owner, *, ttl=60, target='Colleague', config_dir=None):
    """Save a removal whose controls were never posted; both controls expire after ttl."""
    config_dir = config_dir or f.owner_dir
    with owner._operation_lock(f.cid):
        record = owner.sync(f.cid)
        owner._save_operation(f.cid, owner.prepare_change(record, target, 'unposted removal', ttl=ttl, removal_ttl=ttl))
    return copy.deepcopy(cli._load_conversations(config_dir)[0]['group_operation'])


def expire_removal(operation, monkeypatch):
    deadline = deserialize_envelope(encoded_wire(operation, 0))['expiry_ts']
    monkeypatch.setattr('time.time', lambda: deadline + 1)


def released(record):
    return record.get('released_group_operations', [])


@pytest.mark.parametrize('journal', ['pinned', 'legacy'])
def test_release_expired_unposted_removal_keeps_evidence_and_restores_sending(setup, monkeypatch, journal):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_unposted_removal(f, owner)
    if journal == 'legacy':
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_operation'].pop('target')
        cli._save_conversations(f.owner_dir, records)
        original = copy.deepcopy(records[0]['group_operation'])
    expire_removal(original, monkeypatch)
    count = len(f.attempted)
    with pytest.raises(ValueError, match='expired before its acceptance'):
        owner.retry(f.cid)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid, release_unproven=True)
    assert result == {'conversation_id': f.cid, 'released': True, 'reason': 'expired', 'current_epoch': 1, 'members': 2,
                      'removed': False, 'needs_rekey': False, 'released_operations': 1}
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert 'group_operation' not in record
    archive = released(record)
    assert len(archive) == 1 and 'expected' not in archive[0]
    assert archive[0] == {'kind': 'remove', 'controls': original['controls'], 'welcomes': [], 'welcomes_sent': 0,
                          **({'target': original['target']} if journal == 'pinned' else {}),
                          'delivery': 'unknown', 'released_reason': 'expired', 'released_at': archive[0]['released_at']}
    assert f.contact['keyID'].hex() in record['participants'] and not record['group_session']['needsRekey']
    # Nothing was excluded: the contact still reads and replies on the same keys.
    f.command(f.owner_dir, 'send', f.cid, 'after release')
    assert any(row.get('unsafe_body') == 'after release' for row in f.command(f.contact_dir, 'recv', f.cid)['messages'])
    f.command(f.contact_dir, 'send', f.cid, 'contact still present')
    assert any(row.get('unsafe_body') == 'contact still present' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])
    # A later explicit removal is a fresh current-epoch decision with its own pin.
    fresh = owner.change(f.cid, 'Colleague')
    assert fresh['current_epoch'] == 2 and fresh['members'] == 1
    assert GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)['group_session']['removed']
    assert released(cli._load_conversations(f.owner_dir)[0]) == archive


def test_release_refuses_a_verified_removal(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_removal(f, monkeypatch, owner)
    assert _control_accepted(owner.sync(f.cid), encoded_wire(original, 0))
    expire_rekey(original, monkeypatch)
    count = len(f.attempted)
    with pytest.raises(ValueError, match='verified in current history; use group retry'):
        owner.retry(f.cid, release_unproven=True)
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation'] == original and not released(record)
    # Plain retry still owns the proven case and completes it.
    assert owner.retry(f.cid)['current_epoch'] == 2


def test_release_refuses_a_still_exact_removal(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_unposted_removal(f, owner)
    count = len(f.attempted)
    with pytest.raises(ValueError, match='still exact-retryable'):
        owner.retry(f.cid, release_unproven=True)
    assert len(f.attempted) == count and cli._load_conversations(f.owner_dir)[0]['group_operation'] == original
    # Plain retry publishes the exact bytes.
    assert owner.retry(f.cid)['current_epoch'] == 2
    assert f.attempted[count:] == [encoded_wire(original, 0), encoded_wire(original, 1)]


@pytest.mark.parametrize('kind', ['refresh', 'rekey', 'add'])
def test_release_refuses_other_operation_kinds(setup, monkeypatch, kind):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    if kind != 'add':
        join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    monkeypatch.setattr(cli, '_http_send', lambda url, cid, wire: (_ for _ in ()).throw(cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())))
    with pytest.raises(cli.SendDeliveryUnknown):
        {'refresh': lambda: owner.refresh(f.cid, 'Colleague'), 'rekey': lambda: owner.change(f.cid), 'add': lambda: owner.add(f.cid, 'Colleague')}[kind]()
    monkeypatch.setattr(cli, '_http_send', f.send)
    pending = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    with pytest.raises(ValueError, match='not an unproven removal'):
        owner.retry(f.cid, release_unproven=True)
    assert cli._load_conversations(f.owner_dir)[0]['group_operation'] == pending


def test_release_refuses_without_pending_operation_or_with_incomplete_history(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    with pytest.raises(ValueError, match='No pending group operation'):
        owner.retry(f.cid, release_unproven=True)
    original = stage_unposted_removal(f, owner)
    expire_removal(original, monkeypatch)
    records = cli._load_conversations(f.owner_dir)
    records[0]['group_session'] = require_group_recovery(records[0]['group_session'], records[0]['group_cursor'], 'missing_history')
    cli._save_conversations(f.owner_dir, records)
    with pytest.raises(ValueError, match='incomplete'):
        owner.retry(f.cid, release_unproven=True)
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation'] == original and record['group_session']['recovery'] and not released(record)


@pytest.mark.parametrize('stale', ['superseded', 'wrong_branch'])
def test_release_superseded_or_wrong_branch_removal_without_exclusion(setup, monkeypatch, stale):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, _, helper = add_member(f, owner, 'Helper')
    original = stage_unposted_removal(f, owner)
    helper.sync(f.cid)
    if stale == 'superseded':
        helper.change(f.cid)
    else:
        state = owner.sync(f.cid)['group_session']
        frame = state['rekeys'][-1]
        branch = {**state, 'epoch': frame['epoch'], 'root': frame['root'], 'snapshot': frame['snapshot'],
                  'rekeys': [], 'seen': {}, 'admissions': copy.deepcopy(frame['admissions']), 'needsRekey': True}
        with monkeypatch.context() as fixed:
            fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
            f.send(f.relay, f.cid, serialize_envelope(prepare_group_session_rekey(f.owner, branch)['rekey']))
    count = len(f.attempted)
    with pytest.raises(ValueError):
        owner.retry(f.cid)
    result = owner.retry(f.cid, release_unproven=True)
    assert result['released'] and result['reason'] == stale and result['members'] == 3
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert 'group_operation' not in record and released(record)[0]['controls'] == original['controls']
    assert f.contact['keyID'].hex() in record['participants']
    f.command(f.owner_dir, 'send', f.cid, 'everyone still here')
    assert any(row.get('unsafe_body') == 'everyone still here' for row in f.command(f.contact_dir, 'recv', f.cid)['messages'])


@pytest.mark.parametrize('journal', ['pinned', 'legacy'])
def test_release_changed_incarnation_never_re_removes_the_readmitted_target(setup, monkeypatch, journal):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, _, helper = add_member(f, owner, 'Helper')
    original = stage_unposted_removal(f, owner)
    if journal == 'legacy':
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_operation'].pop('target')
        cli._save_conversations(f.owner_dir, records)
        original = copy.deepcopy(records[0]['group_operation'])
    state = helper.sync(f.cid)['group_session']
    f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_remove', create_group_remove_body([f.contact['keyID']]))))
    f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_add', create_group_add_body(helper_identity, [f.contact['publicKey']]))))
    count = len(f.attempted)
    with pytest.raises(ValueError, match='later admission|original admission'):
        owner.retry(f.cid)
    result = owner.retry(f.cid, release_unproven=True)
    assert result['reason'] == ('incarnation_changed' if journal == 'pinned' else 'legacy_same_epoch_admission')
    assert result['needs_rekey'] is True and result['removed'] is False
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert f.contact['keyID'].hex() in record['participants'] and record['group_session']['needsRekey']
    assert released(record)[0]['controls'] == original['controls']
    # The received membership change still needs its rotation; sends stay blocked.
    with pytest.raises(SystemExit):
        f.command(f.owner_dir, 'send', f.cid, 'blocked until rotation')
    assert owner.change(f.cid)['current_epoch'] == 3
    assert f.contact['keyID'].hex() in cli._load_conversations(f.owner_dir)[0]['participants']


def test_release_absent_target_claims_nothing(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, _, helper = add_member(f, owner, 'Helper')
    original = stage_unposted_removal(f, owner)
    state = helper.sync(f.cid)['group_session']
    f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_remove', create_group_remove_body([f.contact['keyID']]))))
    count = len(f.attempted)
    result = owner.retry(f.cid, release_unproven=True)
    assert result['reason'] == 'target_absent' and result['needs_rekey'] is True
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert f.contact['keyID'].hex() not in record['participants']
    assert not _control_accepted(record, encoded_wire(original, 0))
    assert released(record)[0]['released_reason'] == 'target_absent'


def test_release_removal_rekey_whose_origin_proof_was_invalidated(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    add_member(f, owner, 'Helper')
    original = stage_removal(f, monkeypatch, owner)
    expire_rekey(original, monkeypatch)
    monkeypatch.setattr(cli, '_http_send', lambda url, cid, wire: (_ for _ in ()).throw(cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())))
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.retry(f.cid)
    monkeypatch.setattr(cli, '_http_send', f.send)
    repair = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert repair['kind'] == 'removal_rekey'
    state = owner.sync(f.cid)['group_session']
    frame = state['rekeys'][-1]
    branch = {**state, 'epoch': frame['epoch'], 'root': frame['root'], 'snapshot': frame['snapshot'],
              'rekeys': [], 'seen': {}, 'admissions': copy.deepcopy(frame['admissions']), 'needsRekey': True}
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        f.send(f.relay, f.cid, serialize_envelope(prepare_group_session_rekey(f.owner, branch)['rekey']))
    current = owner.sync(f.cid)
    assert not _control_accepted(current, encoded_wire(original, 0))
    with pytest.raises(ValueError, match='no longer verified'):
        owner.retry(f.cid)
    count = len(f.attempted)
    result = owner.retry(f.cid, release_unproven=True)
    assert result['reason'] == 'wrong_branch' and result['members'] == 3
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    row = released(record)[0]
    assert row['kind'] == 'removal_rekey' and row['controls'] == repair['controls'] and row['origin'] == repair['origin']
    assert 'expected' not in row and f.contact['keyID'].hex() in record['participants']


@pytest.mark.parametrize('barrier', ['removed', 'needs_rekey'])
def test_release_keeps_received_barriers(setup, monkeypatch, barrier):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    helper_identity, helper_dir, helper = add_member(f, owner, 'Helper')
    member = GroupClient(f.contact_dir, f.contact, f.relay)
    set_contact(f.contact_dir, 'Helper', helper_identity['publicKey'].hex())
    member.sync(f.cid)
    original = stage_unposted_removal(f, member, target='Helper', config_dir=f.contact_dir)
    if barrier == 'removed':
        owner.change(f.cid, 'Colleague')
    else:
        state = helper.sync(f.cid)['group_session']
        f.send(f.relay, f.cid, serialize_envelope(craft(helper_identity, state, 'group_add', create_group_add_body(helper_identity, [generate_identity()['publicKey']]))))
        expire_removal(original, monkeypatch)
    count = len(f.attempted)
    with pytest.raises(ValueError):
        member.retry(f.cid)
    result = member.retry(f.cid, release_unproven=True)
    assert result['released'] and result['removed'] is (barrier == 'removed') and result['needs_rekey'] is (barrier == 'needs_rekey')
    assert len(f.attempted) == count
    record = cli._load_conversations(f.contact_dir)[0]
    assert 'group_operation' not in record and released(record)[0]['controls'] == original['controls']
    with pytest.raises(SystemExit):
        f.command(f.contact_dir, 'send', f.cid, 'still barred')
    with pytest.raises(ValueError):
        member.change(f.cid, 'Helper')
    assert helper_identity['keyID'].hex() in record['participants']


def test_release_refuses_when_the_journal_changes_after_replay(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_unposted_removal(f, owner)
    expire_removal(original, monkeypatch)
    sync = owner.sync
    def race(cid):
        result = sync(cid)
        records = cli._load_conversations(f.owner_dir)
        records[0]['group_operation']['welcomes_sent'] = 1
        cli._save_conversations(f.owner_dir, records)
        return result
    monkeypatch.setattr(owner, 'sync', race)
    with pytest.raises(ValueError, match='changed before release'):
        owner.retry(f.cid, release_unproven=True)
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation']['welcomes_sent'] == 1 and not released(record)


@pytest.mark.parametrize('bound', ['revisions', 'bytes', 'malformed'])
def test_release_refuses_unchanged_when_the_archive_cannot_retain_evidence(setup, monkeypatch, bound):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    first = stage_unposted_removal(f, owner)
    expire_removal(first, monkeypatch)
    assert owner.retry(f.cid, release_unproven=True)['released']
    archive = copy.deepcopy(released(cli._load_conversations(f.owner_dir)[0]))
    second = stage_unposted_removal(f, owner)
    expire_removal(second, monkeypatch)
    if bound == 'revisions':
        monkeypatch.setattr('qntm.group_client.MAX_OPERATION_REVISIONS', 1)
    elif bound == 'bytes':
        monkeypatch.setattr('qntm.group_client.MAX_OPERATION_EVIDENCE_BYTES', len(marshal_canonical(archive)))
    else:
        records = cli._load_conversations(f.owner_dir)
        records[0]['released_group_operations'][0]['delivery'] = 'accepted'
        cli._save_conversations(f.owner_dir, records)
        archive = copy.deepcopy(records[0]['released_group_operations'])
    count = len(f.attempted)
    with pytest.raises(ValueError, match='limit' if bound != 'malformed' else 'Invalid saved release archive'):
        owner.retry(f.cid, release_unproven=True)
    assert len(f.attempted) == count
    record = cli._load_conversations(f.owner_dir)[0]
    assert record['group_operation'] == second and released(record) == archive


def test_release_archive_survives_restart_and_welcome_replacement(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, _, helper = add_member(f, owner, 'Helper')
    member = GroupClient(f.contact_dir, f.contact, f.relay)
    member.sync(f.cid)
    original = stage_unposted_removal(f, member, target=helper.identity['keyID'].hex(), config_dir=f.contact_dir)
    expire_removal(original, monkeypatch)
    assert GroupClient(f.contact_dir, f.contact, f.relay).retry(f.cid, release_unproven=True)['reason'] == 'expired'
    archive = copy.deepcopy(released(cli._load_conversations(f.contact_dir)[0]))
    assert released(GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)) == archive
    # A challenged welcome replaces the member's checkpoint but not its private archive.
    records = cli._load_conversations(f.contact_dir)
    records[0]['group_session'] = require_group_recovery(records[0]['group_session'], records[0]['group_cursor'], 'missing_history')
    cli._save_conversations(f.contact_dir, records)
    link = owner.refresh(f.cid, 'Colleague', records[0]['group_session']['recovery']['challenge'])['group_link']
    assert join(f.contact_dir, f.contact, link)['current_epoch'] == 2
    record = cli._load_conversations(f.contact_dir)[0]
    assert released(record) == archive and 'group_operation' not in record and record['group_session']['recovery'] is None


def test_release_then_late_authenticated_original_ciphertext_uses_normal_receive(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    _, _, helper = add_member(f, owner, 'Helper')
    original = stage_unposted_removal(f, owner)
    expire_removal(original, monkeypatch)
    owner.retry(f.cid, release_unproven=True)
    # The old expired control later reaches the relay: ordinary receive treats it
    # like any expired authenticated control at the current epoch.
    f.send(f.relay, f.cid, encoded_wire(original, 0))
    current = owner.sync(f.cid)
    assert current['group_session']['recovery']['reason'] == 'expired_control'
    assert f.contact['keyID'].hex() in current['participants']
    assert released(current)[0]['controls'] == original['controls']
    assert helper.sync(f.cid)['group_session']['recovery']['reason'] == 'expired_control'


def test_cli_and_mcp_release_unproven_removal(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    original = stage_unposted_removal(f, owner)
    expire_removal(original, monkeypatch)
    with pytest.raises(SystemExit):
        f.command(f.owner_dir, 'group', 'retry', f.cid)
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.owner_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    assert 'expired before its acceptance' in mcp.group_retry(f.cid)['error']
    count = len(f.attempted)
    released_by_cli = f.command(f.owner_dir, 'group', 'retry', f.cid, '--release-unproven')
    assert released_by_cli['released'] is True and released_by_cli['reason'] == 'expired'
    assert len(f.attempted) == count
    assert 'error' in mcp.group_retry(f.cid, release_unproven=True)  # nothing pending any more
    second = stage_unposted_removal(f, owner)
    expire_removal(second, monkeypatch)
    result = mcp.group_retry(f.cid, release_unproven=True)
    assert result['released'] is True and result['released_operations'] == 2
    assert len(f.attempted) == count
    assert 'group_operation' not in cli._load_conversations(f.owner_dir)[0]
