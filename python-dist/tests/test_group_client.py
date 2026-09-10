"""Actual CLI commands with a deterministic ciphertext-only transport."""
import base64
import contextlib
import copy
import io
import json
from types import SimpleNamespace

import pytest

from qntm import cli, generate_identity, deserialize_envelope, create_message, serialize_envelope
from qntm.group_client import GroupClient, public_key, set_contact, join, receive_batch
from qntm.group_session import group_session_conversation, create_group_control_message, receive_group_event
from qntm.group import create_rekey, apply_rekey
from qntm.watch import delivery_events


@pytest.fixture
def setup(tmp_path, monkeypatch):
    owner, contact = generate_identity(), generate_identity()
    owner_dir, contact_dir = str(tmp_path / 'owner'), str(tmp_path / 'contact')
    cli._save_identity(owner_dir, owner)
    cli._save_identity(contact_dir, contact)
    rows, attempted = {}, []
    relay = 'http://relay.test'

    def send(url, cid, wire):
        assert url == relay
        attempted.append(wire)
        items = rows.setdefault(cid, [])
        for index, existing in enumerate(items):
            if existing == wire:
                return {'seq': index + 1}
        items.append(wire)
        return {'seq': len(items)}

    def receive(url, cid, cursor):
        assert url == relay
        items = rows.get(cid, [])
        return ([{'seq': index + 1, 'envelope_b64': base64.b64encode(wire).decode()}
                 for index, wire in enumerate(items) if index + 1 > cursor], len(items))

    monkeypatch.setattr(cli, '_http_send', send)
    monkeypatch.setattr(cli, '_recv_once', receive)

    def command(config_dir, *args):
        output = io.StringIO()
        monkeypatch.setattr('sys.argv', ['qntm', '--config-dir', config_dir, *args])
        with contextlib.redirect_stdout(output):
            cli.main()
        return json.loads(output.getvalue())['data']

    created = command(owner_dir, '--dropbox-url', relay, 'group', 'create', 'Team')
    cid = created['conversation_id']
    command(owner_dir, 'contact', 'add', 'Colleague', contact['publicKey'].hex())
    return SimpleNamespace(owner=owner, contact=contact, owner_dir=owner_dir, contact_dir=contact_dir,
                           cid=cid, relay=relay, rows=rows, attempted=attempted, send=send, receive=receive, command=command)


def test_contact_add_open_send_restart_remove_and_readmission(setup):
    f = setup
    f.command(f.owner_dir, '--dropbox-url', f.relay, 'send', f.cid, 'before admission')
    added = f.command(f.owner_dir, '--dropbox-url', f.relay, 'group', 'add', f.cid, 'Colleague')
    assert added['current_epoch'] == 1 and '#group=' in added['group_link']
    assert deserialize_envelope(f.rows[f.cid][-1])['kind'] == 'group_welcome'
    opened = f.command(f.contact_dir, 'group', 'join', added['group_link'])
    assert opened['current_epoch'] == 1 and not opened['removed']
    assert not cli._load_history(f.contact_dir, f.cid)
    # No relay flag: send and receive must use the relay pinned by the link.
    f.command(f.contact_dir, 'send', f.cid, 'hello after restart')
    received = f.command(f.owner_dir, 'recv', f.cid)
    assert any(row.get('unsafe_body') == 'hello after restart' for row in received['messages'])
    assert cli._load_conversations(f.contact_dir)[0]['group_session']['rekeys'] == []
    removed = f.command(f.owner_dir, 'group', 'remove', f.cid, 'Colleague')
    assert removed['current_epoch'] == 2
    f.command(f.contact_dir, 'recv', f.cid)
    checkpoint = cli._load_conversations(f.contact_dir)[0]
    assert checkpoint['group_session']['removed']
    before = len(f.attempted)
    with pytest.raises((ValueError, SystemExit)):
        f.command(f.contact_dir, 'send', f.cid, 'should not send')
    assert len(f.attempted) == before
    with pytest.raises(ValueError, match='removal'):
        join(f.contact_dir, f.contact, added['group_link'])
    f.command(f.owner_dir, 'send', f.cid, 'while removed')
    again = f.command(f.owner_dir, 'group', 'add', f.cid, 'Colleague')
    assert again['current_epoch'] == 3
    reopened = f.command(f.contact_dir, 'convo', 'join', again['group_link'])
    assert reopened['current_epoch'] == 3 and not reopened['removed']
    assert all(entry.get('unsafe_body') != 'while removed' for entry in cli._load_history(f.contact_dir, f.cid))
    f.command(f.contact_dir, 'send', f.cid, 'back after readmission')


@pytest.mark.parametrize('readmission', [False, True])
def test_cli_opens_library_renewal_after_original_delivery_is_gone(setup, monkeypatch, readmission):
    import time
    from qntm import prepare_group_admission_renewal, prepare_group_session_addition, prepare_group_welcome_refresh
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    if readmission:
        join(f.contact_dir, f.contact, link)
        owner.change(f.cid, 'Colleague')
        GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)
        current = owner.sync(f.cid)
        addition = prepare_group_session_addition(f.owner, current['group_session'], [f.contact['publicKey']], ttl=1,
                                                  replay_from_sequence=current['group_cursor'])
        for envelope in (addition['addition'], addition['rekey'], *addition['welcomes']):
            f.send(f.relay, f.cid, serialize_envelope(envelope))
        owner.sync(f.cid)
        later = time.time() + 2
        monkeypatch.setattr(time, 'time', lambda: later)
    owner.change(f.cid)
    record = owner.sync(f.cid)
    state = record['group_session']
    admission = state['admissions'][f.contact['keyID'].hex()]
    renewal = prepare_group_admission_renewal(f.owner, state, f.contact['publicKey'],
                                             {key: admission[key] for key in ('addId', 'addDigest')},
                                             replay_from_sequence=record['group_cursor'])
    renewal_wire = serialize_envelope(renewal['welcomes'][0])
    f.send(f.relay, f.cid, renewal_wire)
    retained = {renewal_wire}
    if readmission:
        # A newer generic refresh must not hide a valid readmission renewal.
        generic = prepare_group_welcome_refresh(f.owner, state, [f.contact['publicKey']],
                                                replay_from_sequence=record['group_cursor'])
        wire = serialize_envelope(generic['welcomes'][0])
        f.send(f.relay, f.cid, wire)
        retained.add(wire)

    def receive(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if readmission or deserialize_envelope(base64.b64decode(row['envelope_b64'])).get('kind') != 'group_welcome'
                or base64.b64decode(row['envelope_b64']) in retained], head

    monkeypatch.setattr(cli, '_recv_once', receive)
    result = join(f.contact_dir, f.contact, link)
    assert not result['removed'] and not result['recovery_required']
    joined = cli._load_conversations(f.contact_dir)[0]['group_session']
    assert joined['epoch'] == state['epoch'] and joined['admissions'] == state['admissions']
    if readmission:
        assert joined['removedAtEpoch'] == 1
    f.command(f.contact_dir, 'send', f.cid, 'opened renewed delivery')
    assert any(row.get('unsafe_body') == 'opened renewed delivery' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


@pytest.mark.parametrize('failure_index', [1, 2, 3])
def test_retry_reuses_exact_ciphertext_after_lost_response(setup, monkeypatch, failure_index):
    f = setup
    calls = []

    def uncertain(url, cid, wire):
        calls.append(wire)
        result = f.send(url, cid, wire)
        if len(calls) == failure_index:
            raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
        return result

    monkeypatch.setattr(cli, '_http_send', uncertain)
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    with pytest.raises(cli.SendDeliveryUnknown):
        client.add(f.cid, 'Colleague')
    saved = copy.deepcopy(cli._load_conversations(f.owner_dir)[0]['group_operation'])
    assert saved
    # Simulate a new CLI process: only files and relay ciphertext survive.
    monkeypatch.setattr(cli, '_http_send', f.send)
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(f.cid)
    assert result['current_epoch'] == 1
    assert 'group_operation' not in cli._load_conversations(f.owner_dir)[0]
    assert len(f.rows[f.cid]) == 4  # genesis, add, rekey, welcome; no duplicated operation
    prepared = [base64.b64decode(wire) for wire in saved['controls'] + saved['welcomes']]
    assert f.rows[f.cid][1:] == prepared
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


def test_failure_to_persist_receive_does_not_advance_cursor_or_release_welcome(setup, monkeypatch):
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    client.enable(f.cid)
    original_save = cli._save_conversations

    def fail_after_add(path, records):
        record = records[0]
        if record.get('group_session', {}).get('needsRekey'):
            raise OSError('disk unavailable')
        original_save(path, records)

    monkeypatch.setattr(cli, '_save_conversations', fail_after_add)
    with pytest.raises(OSError):
        client.add(f.cid, 'Colleague')
    saved = cli._load_conversations(f.owner_dir)[0]
    assert saved['group_cursor'] == 1 and not saved['group_session']['needsRekey']
    assert all(deserialize_envelope(wire).get('kind') != 'group_welcome' for wire in f.rows[f.cid])
    monkeypatch.setattr(cli, '_save_conversations', original_save)
    assert client.retry(f.cid)['current_epoch'] == 1


def test_contact_pins_and_wrong_recipient(setup):
    f = setup
    assert public_key(f.contact['publicKey'].hex()) == f.contact['publicKey']
    with pytest.raises(ValueError, match='another key'):
        set_contact(f.owner_dir, 'Colleague', f.owner['publicKey'].hex())
    added = GroupClient(f.owner_dir, f.owner, f.relay).add(f.cid, 'Colleague')
    stranger = generate_identity()
    with pytest.raises(ValueError, match='No current welcome'):
        join(f.contact_dir, stranger, added['group_link'])


def test_contacts_can_open_links_in_reverse_addition_order(setup):
    f = setup
    bob = generate_identity()
    bob_dir = f.contact_dir + '-bob'
    cli._save_identity(bob_dir, bob)
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    alice_link = client.add(f.cid, 'Colleague')['group_link']
    f.command(f.owner_dir, 'send', f.cid, 'after Alice, before Bob')
    set_contact(f.owner_dir, 'Bob', bob['publicKey'].hex())
    bob_link = client.add(f.cid, 'Bob')['group_link']
    f.command(f.owner_dir, 'send', f.cid, 'after both additions')

    assert join(bob_dir, bob, bob_link)['current_epoch'] == 2
    f.command(bob_dir, 'send', f.cid, 'Bob opened first')
    assert join(f.contact_dir, f.contact, alice_link)['current_epoch'] == 2
    alice_history = cli._load_history(f.contact_dir, f.cid)
    bob_history = cli._load_history(bob_dir, f.cid)
    assert any(row.get('unsafe_body') == 'after Alice, before Bob' for row in alice_history)
    assert not any(row.get('unsafe_body') == 'after Alice, before Bob' for row in bob_history)
    assert any(row.get('unsafe_body') == 'Bob opened first' for row in alice_history)
    f.command(f.contact_dir, 'send', f.cid, 'Alice caught up')
    assert any(row.get('unsafe_body') == 'Alice caught up'
               for row in f.command(bob_dir, 'recv', f.cid)['messages'])


def test_pending_ciphertext_replays_after_lower_rekey_without_losing_hook_delivery(setup, monkeypatch):
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    record = client.enable(f.cid)
    from qntm.group_client import _group
    group, source = _group(record['group_session']), group_session_conversation(record['group_session'])

    def rotation(conversation):
        body, root = create_rekey(f.owner, conversation, group, conversation['id'])
        env = create_group_control_message(f.owner, conversation, 'group_rekey', body)
        following = copy.deepcopy(conversation)
        apply_rekey(following, root, conversation['currentEpoch'] + 1)
        return env, following

    (low, winner), (high, loser) = sorted([rotation(source), rotation(source)], key=lambda pair: pair[0]['msg_id'])
    f.send(f.relay, f.cid, serialize_envelope(high))
    with monkeypatch.context() as ids:
        ids.setattr('qntm.message.generate_message_id', lambda: bytes.fromhex('01' * 16))
        loser_child, _ = rotation(loser)
    f.send(f.relay, f.cid, serialize_envelope(loser_child))
    client.sync(f.cid)
    with monkeypatch.context() as ids:
        ids.setattr('qntm.message.generate_message_id', lambda: bytes.fromhex('fe' * 16))
        winner_child, winner2 = rotation(winner)
    f.send(f.relay, f.cid, serialize_envelope(winner_child))
    text = create_message(f.owner, winner2, 'text', b'late-decrypted message')
    text_seq = f.send(f.relay, f.cid, serialize_envelope(text))['seq']
    waiting = client.sync(f.cid)
    assert len(waiting['group_pending']) == 2
    delayed_seq = f.send(f.relay, f.cid, serialize_envelope(low))['seq']
    completed = client.sync(f.cid)
    assert completed['keys']['root'] == winner2['keys']['root'].hex()
    assert not completed['group_pending']
    order, event = next((order, event) for order, event in delivery_events(f.owner_dir, f.cid)
                        if event['data']['message'].get('unsafe_body') == 'late-decrypted message')
    assert event['data']['sequence'] == text_seq and order > delayed_seq
    assert completed['group_cursor'] == delayed_seq
    # Malformed relay metadata must not crash the catch-up error path when
    # a rekey archive exists. It conveys no authenticated group event.
    malformed = dict(text, conv_epoch='bad')
    cleaned, output = receive_batch(completed, f.owner, [
        {'seq': delayed_seq + 1, 'envelope_b64': base64.b64encode(serialize_envelope(malformed)).decode()}
    ], delayed_seq + 1)
    assert not output and not cleaned['group_pending']
    with pytest.raises(ValueError):
        receive_batch(completed, f.owner, [], -1)


def test_stale_metadata_writer_cannot_erase_group_progress(setup):
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    client.enable(f.cid)
    stale = cli._load_conversations(f.owner_dir)
    client.add(f.cid, 'Colleague')
    stale[0]['name'] = 'Stale rename'
    with pytest.raises(ValueError, match='state changed'):
        cli._save_conversations(f.owner_dir, stale)
    with pytest.raises(ValueError, match='state changed'):
        cli._save_conversations(f.owner_dir, [])
    assert cli._load_conversations(f.owner_dir)[0]['current_epoch'] == 1


def test_group_send_echo_preserves_history_and_reaches_include_self_hooks(setup):
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    client.add(f.cid, 'Colleague')
    sent = f.command(f.owner_dir, 'send', f.cid, 'own message')
    client.sync(f.cid)
    event = next(event for _, event in delivery_events(f.owner_dir, f.cid)
                 if event['data']['message'].get('unsafe_body') == 'own message')
    assert event['data']['sequence'] == sent['sequence']
    client.sync(f.cid)
    rows = [row for row in cli._load_history(f.owner_dir, f.cid) if row['msg_id'] == sent['message_id']]
    assert len(rows) == 1 and rows[0]['body'] == 'own message' and rows[0]['verified']


def test_mcp_and_cli_share_the_same_group_profile_and_removal_guards(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    added = GroupClient(f.owner_dir, f.owner, f.relay).add(f.cid, 'Colleague')
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.contact_dir)
    monkeypatch.delenv('QNTM_RELAY_URL', raising=False)
    monkeypatch.setattr(mcp, '_http_send', f.send)
    monkeypatch.setattr(mcp, '_recv_once', f.receive)
    assert mcp.conversation_join(added['group_link'])['current_epoch'] == 1
    assert 'error' not in mcp.send_message(f.cid, 'MCP reply')
    f.command(f.owner_dir, 'group', 'remove', f.cid, 'Colleague')
    assert 'error' not in mcp.receive_messages(f.cid)
    attempted = len(f.attempted)
    assert 'error' in mcp.send_message(f.cid, 'must remain excluded')
    assert len(f.attempted) == attempted


def test_mcp_contact_addition_and_local_pin_removal(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.owner_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    assert mcp.contact_add('MCP colleague', f.contact['publicKey'].hex())['public_key'] == f.contact['publicKey'].hex()
    assert 'error' in mcp.contact_add('MCP colleague', f.owner['publicKey'].hex())
    result = mcp.group_add_contact(f.cid, 'MCP colleague')
    assert result['current_epoch'] == 1
    assert mcp.group_link(f.cid)['group_link'] == result['group_link']
    assert mcp.contact_remove('MCP colleague') == {'removed': 'MCP colleague'}
    assert all(row['name'] != 'MCP colleague' for row in mcp.contact_list()['contacts'])
    assert join(f.contact_dir, f.contact, result['group_link'])['current_epoch'] == 1


def test_cli_refresh_after_delivery_expiry_does_not_add_or_rotate(setup, monkeypatch):
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    link = client.add(f.cid, 'Colleague')['group_link']
    before = cli._load_conversations(f.owner_dir)[0]
    expiry = deserialize_envelope(f.rows[f.cid][-1])['expiry_ts']
    monkeypatch.setattr('time.time', lambda: expiry + 1)
    with pytest.raises(ValueError, match='No current welcome'):
        join(f.contact_dir, f.contact, link)
    count = len(f.rows[f.cid])
    refreshed = f.command(f.owner_dir, 'group', 'refresh', f.cid, 'Colleague')
    assert refreshed['group_link'] == link and refreshed['current_epoch'] == 1
    assert len(f.rows[f.cid]) == count + 1
    after = cli._load_conversations(f.owner_dir)[0]
    assert after['keys'] == before['keys'] and after['participants'] == before['participants']
    assert join(f.contact_dir, f.contact, link)['current_epoch'] == 1
    f.command(f.contact_dir, 'send', f.cid, 'recovered after expiry')
    assert any(row.get('unsafe_body') == 'recovered after expiry'
               for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


def test_mcp_refresh_exact_retry_and_removed_recipient_guard(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    result = client.add(f.cid, 'Colleague')
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.owner_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    sent = []

    def uncertain(url, cid, wire):
        sent.append(wire)
        f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', uncertain)
    assert mcp.group_refresh(f.cid, 'Colleague')['delivery'] == 'unknown'
    assert len(sent) == 1
    monkeypatch.setattr(cli, '_http_send', f.send)
    assert mcp.group_retry(f.cid)['current_epoch'] == 1
    assert f.attempted[-1] == sent[0] and len(f.rows[f.cid]) == 5
    join(f.contact_dir, f.contact, result['group_link'])
    client.change(f.cid, 'Colleague')
    f.command(f.contact_dir, 'recv', f.cid)
    count = len(f.attempted)
    assert 'error' in mcp.group_refresh(f.cid, 'Colleague')
    assert len(f.attempted) == count
    with pytest.raises(ValueError, match='cannot undo saved removal'):
        join(f.contact_dir, f.contact, result['group_link'])


def test_admission_welcome_still_allows_readmission_when_a_refresh_also_exists(setup):
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    link = client.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    client.change(f.cid, 'Colleague')
    f.command(f.contact_dir, 'recv', f.cid)
    client.add(f.cid, 'Colleague')
    client.refresh(f.cid, 'Colleague')
    assert join(f.contact_dir, f.contact, link)['current_epoch'] == 3


def test_cli_member_can_finish_partial_rotation_and_refresh_the_new_contact(setup):
    from qntm import prepare_group_session_addition
    f = setup
    client = GroupClient(f.owner_dir, f.owner, f.relay)
    link = client.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    newcomer = generate_identity()
    new_dir = f.contact_dir + '-newcomer'
    cli._save_identity(new_dir, newcomer)
    owner_state = cli._load_conversations(f.owner_dir)[0]['group_session']
    operation = prepare_group_session_addition(f.owner, owner_state, [newcomer['publicKey']])
    # The creator disappears after publishing only the addition.
    f.send(f.relay, f.cid, serialize_envelope(operation['addition']))
    f.command(f.contact_dir, 'recv', f.cid)
    with pytest.raises(SystemExit):
        f.command(f.contact_dir, 'send', f.cid, 'must await rotation')
    assert f.command(f.contact_dir, 'group', 'rekey', f.cid)['current_epoch'] == 2
    refreshed = f.command(f.contact_dir, 'group', 'refresh', f.cid, newcomer['publicKey'].hex())
    assert join(new_dir, newcomer, refreshed['group_link'])['current_epoch'] == 2
    f.command(new_dir, 'send', f.cid, 'recovered after interrupted rotation')
    assert any(row.get('unsafe_body') == 'recovered after interrupted rotation'
               for row in f.command(f.contact_dir, 'recv', f.cid)['messages'])


def test_missing_membership_history_blocks_all_sends_and_hooks_until_fresh_welcome(setup, monkeypatch):
    from qntm import guidance, mcp_server as mcp
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    f.command(f.owner_dir, 'send', f.cid, 'saved before gap')
    f.command(f.contact_dir, 'recv', f.cid)
    assert delivery_events(f.contact_dir, f.cid)
    guidance.pin_contact(f.contact_dir, f.relay, 'advisor', 'ethical', 'Advisor', 'agent', f.cid, f.owner['keyID'].hex())
    review = guidance.prepare_request(f.contact_dir, f.relay, 'advisor', 'Please advise')
    missing = len(f.rows[f.cid]) + 1
    owner.add(f.cid, generate_identity()['publicKey'].hex())

    def receive(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] != missing], head

    monkeypatch.setattr(cli, '_recv_once', receive)
    result = f.command(f.contact_dir, 'recv', f.cid)
    assert result['recovery_required'] and result['recovery']['afterSequence'] == missing
    assert not delivery_events(f.contact_dir, f.cid)
    attempted = len(f.attempted)
    for args in [('send', f.cid, 'must not send'), ('group', 'rekey', f.cid),
                 ('group', 'refresh', f.cid, f.owner['publicKey'].hex())]:
        with pytest.raises(SystemExit):
            f.command(f.contact_dir, *args)
    with pytest.raises(ValueError, match='incomplete'):
        guidance.send_request(f.contact_dir, f.relay, 'advisor', 'Please advise', '', review['review_token'])
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.contact_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    monkeypatch.setattr(mcp, '_http_send', f.send)
    assert 'error' in mcp.send_message(f.cid, 'MCP must not send')
    assert len(f.attempted) == attempted
    with pytest.raises(ValueError, match='challenge'):
        join(f.contact_dir, f.contact, link)
    refreshed = f.command(f.owner_dir, 'group', 'refresh', f.cid, 'Colleague', '--challenge', result['recovery']['challenge'])
    assert join(f.contact_dir, f.contact, refreshed['group_link'])['current_epoch'] == 2
    assert cli._load_conversations(f.contact_dir)[0]['group_session']['recovery'] is None
    # A replacement checkpoint cannot vouch for previously queued plaintext.
    assert not delivery_events(f.contact_dir, f.cid)
    f.command(f.owner_dir, 'send', f.cid, 'fresh after recovery')
    f.command(f.contact_dir, 'recv', f.cid)
    assert [event['data']['message']['unsafe_body'] for _, event in delivery_events(f.contact_dir, f.cid)] == ['fresh after recovery']
    f.command(f.contact_dir, 'send', f.cid, 'recovered safely')
    assert any(row.get('unsafe_body') == 'recovered safely' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


def test_a_missing_removal_does_not_allow_old_welcome_or_refresh_to_restore_access(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    missing = len(f.rows[f.cid]) + 1
    owner.change(f.cid, 'Colleague')

    def receive(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] != missing], head

    monkeypatch.setattr(cli, '_recv_once', receive)
    status = f.command(f.contact_dir, 'recv', f.cid)
    assert status['recovery_required']
    with pytest.raises(SystemExit):
        f.command(f.contact_dir, 'send', f.cid, 'must remain excluded')
    with pytest.raises(ValueError, match='challenge'):
        join(f.contact_dir, f.contact, link)
    with pytest.raises(ValueError, match='current member'):
        owner.refresh(f.cid, 'Colleague')
    # A later explicit addition remains an admission, distinct from recovery.
    f.command(f.owner_dir, 'group', 'add', f.cid, 'Colleague', '--challenge', status['recovery']['challenge'])
    assert join(f.contact_dir, f.contact, link)['current_epoch'] == 3


def test_known_own_receipts_cover_expired_welcome_and_text_without_masking_other_holes(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    expired_welcome_sequence = len(f.rows[f.cid])

    def receive(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] != expired_welcome_sequence], head

    monkeypatch.setattr(cli, '_recv_once', receive)
    assert owner.refresh(f.cid, 'Colleague')['group_link'] == link
    f.command(f.owner_dir, 'send', f.cid, 'own text')
    expired_text_sequence = len(f.rows[f.cid])

    def receive_after_text(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] not in (expired_welcome_sequence, expired_text_sequence)], head

    monkeypatch.setattr(cli, '_recv_once', receive_after_text)
    assert owner.sync(f.cid)['group_session']['recovery'] is None
    stranger = generate_identity()
    f.send(f.relay, f.cid, serialize_envelope(create_message(stranger, group_session_conversation(owner.sync(f.cid)['group_session']), 'text', b'unknown')))
    missing = len(f.rows[f.cid])
    monkeypatch.setattr(cli, '_recv_once', lambda url, cid, cursor: ([], missing))
    assert owner.sync(f.cid)['group_session']['recovery']['afterSequence'] == missing


def test_expired_removal_is_visible_as_recovery_required_without_stale_send(setup, monkeypatch):
    from qntm import create_group_remove_body
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    record = owner.sync(f.cid)
    removal = create_group_control_message(f.owner, group_session_conversation(record['group_session']), 'group_remove',
                                          create_group_remove_body([f.contact['keyID']]), 1)
    f.send(f.relay, f.cid, serialize_envelope(removal))
    owner.change(f.cid)
    at = removal['expiry_ts'] + 1
    monkeypatch.setattr('time.time', lambda: at)
    result = f.command(f.contact_dir, 'recv', f.cid)
    assert result['recovery_required'] and result['recovery']['reason'] == 'expired_control'
    before = len(f.attempted)
    with pytest.raises(SystemExit):
        f.command(f.contact_dir, 'send', f.cid, 'stale send refused')
    assert len(f.attempted) == before


def test_expired_future_control_is_rechecked_when_the_parent_key_arrives(setup, monkeypatch):
    from qntm import create_group_remove_body, prepare_group_session_rekey
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    record = owner.sync(f.cid)
    rotation = prepare_group_session_rekey(f.owner, record['group_session'])
    removal = create_group_control_message(f.owner, rotation['conversation'], 'group_remove',
                                           create_group_remove_body([f.contact['keyID']]), 1)
    f.send(f.relay, f.cid, serialize_envelope(removal))
    monkeypatch.setattr('time.time', lambda: removal['expiry_ts'] + 2)
    f.command(f.contact_dir, 'recv', f.cid)
    pending = cli._load_conversations(f.contact_dir)[0]
    assert pending['group_pending'] and pending['group_session']['recovery'] is None
    f.send(f.relay, f.cid, serialize_envelope(rotation['rekey']))
    received = f.command(f.contact_dir, 'recv', f.cid)
    assert received['recovery_required'] and received['recovery']['reason'] == 'expired_control'
    assert not cli._load_conversations(f.contact_dir)[0]['group_session']['removed']


def test_mcp_challenge_refresh_recovers_and_invalid_challenges_send_nothing(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    f.command(f.owner_dir, 'send', f.cid, 'missing text')
    missing = len(f.rows[f.cid])

    def receive(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] != missing], head

    monkeypatch.setattr(cli, '_recv_once', receive)
    status = f.command(f.contact_dir, 'recv', f.cid)
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.owner_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    monkeypatch.setattr(mcp, '_http_send', f.send)
    before = len(f.attempted)
    assert 'error' in mcp.group_refresh(f.cid, 'Colleague', 'not hex')
    assert 'error' in mcp.group_add_contact(f.cid, 'Colleague', '00')
    assert len(f.attempted) == before
    refreshed = mcp.group_refresh(f.cid, 'Colleague', status['recovery']['challenge'])
    assert refreshed['group_link'] == link
    assert not join(f.contact_dir, f.contact, link)['recovery_required']


def test_contact_group_creation_is_durable_and_has_no_bearer_invite(setup):
    f = setup
    created = f.command(f.owner_dir, '--dropbox-url', f.relay, 'group', 'create', 'New contact group', '--contact')
    cid = created['conversation_id']
    assert '#group=' in created['group_link'] and 'invite_token' not in created
    record = cli._find_conversation(cli._load_conversations(f.owner_dir), cid)
    assert record['group_session']['signedEpoch'] and record['current_epoch'] == 0
    assert record['group_cursor'] == 1 and 'group_operation' not in record and 'invite_token' not in record
    assert len(record['group_session']['seen']) == 1
    sent = len(f.attempted)
    with pytest.raises(SystemExit):
        f.command(f.owner_dir, 'gate-promote', '-c', cid, '--gateway-url', 'http://gateway.test')
    assert len(f.attempted) == sent
    f.command(f.owner_dir, 'send', cid, 'before anyone is added')
    added = f.command(f.owner_dir, 'group', 'add', cid, 'Colleague')
    join(f.contact_dir, f.contact, added['group_link'])
    assert all(row.get('unsafe_body') != 'before anyone is added' for row in cli._load_history(f.contact_dir, cid))
    f.command(f.contact_dir, 'send', cid, 'first contact reply')
    assert any(row.get('unsafe_body') == 'first contact reply' for row in f.command(f.owner_dir, 'recv', cid)['messages'])


@pytest.mark.parametrize('accepted', [False, True])
def test_contact_creation_retries_exact_genesis_after_uncertain_delivery(setup, monkeypatch, accepted):
    f = setup
    attempted = []

    def uncertain(url, cid, wire):
        record = cli._find_conversation(cli._load_conversations(f.owner_dir), cid)
        assert record['group_operation']['kind'] == 'create'
        assert record['group_operation']['controls'] == [base64.b64encode(wire).decode()]
        attempted.append(wire)
        if accepted:
            f.send(url, cid, wire)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())

    monkeypatch.setattr(cli, '_http_send', uncertain)
    with pytest.raises(cli.SendDeliveryUnknown) as failed:
        GroupClient(f.owner_dir, f.owner, f.relay).create('Uncertain creation')
    cid = failed.value.conversation_id
    monkeypatch.setattr(cli, '_http_send', f.send)
    with pytest.raises(SystemExit):
        f.command(f.owner_dir, 'send', cid, 'must wait for genesis completion')
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(cid)
    assert result['current_epoch'] == 0 and f.rows[cid] == attempted
    assert 'group_operation' not in cli._find_conversation(cli._load_conversations(f.owner_dir), cid)


def test_contact_creation_does_not_post_when_its_atomic_save_fails(setup, monkeypatch):
    f = setup
    before = len(f.attempted)

    def fail(*args):
        raise OSError('disk full')

    monkeypatch.setattr(cli, '_save_conversations', fail)
    with pytest.raises(OSError):
        GroupClient(f.owner_dir, f.owner, f.relay).create('Cannot persist')
    assert len(f.attempted) == before


def test_mcp_creates_contact_group_with_shared_cli_state(setup, monkeypatch):
    from qntm import mcp_server as mcp
    f = setup
    monkeypatch.setenv('QNTM_CONFIG_DIR', f.owner_dir)
    monkeypatch.setenv('QNTM_RELAY_URL', f.relay)
    result = mcp.group_create('MCP contacts')
    assert result['name'] == 'MCP contacts' and 'invite_token' not in result
    record = cli._find_conversation(cli._load_conversations(f.owner_dir), result['conversation_id'])
    assert record['group_session'] and not record.get('group_operation')


def test_contact_creation_requires_exact_replay_after_a_post_acknowledgement(setup, monkeypatch):
    f = setup
    hidden = True

    def receive(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return ([] if hidden else rows), head

    monkeypatch.setattr(cli, '_recv_once', receive)
    with pytest.raises(ValueError, match='not yet verified'):
        GroupClient(f.owner_dir, f.owner, f.relay).create('Withheld genesis')
    record = next(record for record in cli._load_conversations(f.owner_dir) if record['name'] == 'Withheld genesis')
    assert record['group_operation']['kind'] == 'create' and not record['group_session']['seen']
    assert record['group_session']['recovery'] is None  # Its own ACK accounts for that row, not its acceptance.
    attempted = len(f.attempted)
    hidden = False
    result = GroupClient(f.owner_dir, f.owner, f.relay).retry(record['id'])
    assert result['current_epoch'] == 0 and len(f.attempted) == attempted
    assert 'group_operation' not in cli._find_conversation(cli._load_conversations(f.owner_dir), record['id'])


def test_retry_renews_delivery_without_posting_the_expired_admission_welcome(setup, monkeypatch):
    f = setup

    def withhold_welcome(url, cid, wire):
        if deserialize_envelope(wire).get('kind') == 'group_welcome':
            raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), OSError())
        return f.send(url, cid, wire)

    monkeypatch.setattr(cli, '_http_send', withhold_welcome)
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    with pytest.raises(cli.SendDeliveryUnknown):
        owner.add(f.cid, 'Colleague')
    saved = cli._load_conversations(f.owner_dir)[0]['group_operation']
    expiry = deserialize_envelope(base64.b64decode(saved['welcomes'][0]))['expiry_ts']
    monkeypatch.setattr('time.time', lambda: expiry + 1)
    monkeypatch.setattr(cli, '_http_send', f.send)
    before = len(f.attempted)
    owner.retry(f.cid)
    assert len(f.attempted) == before + 1
    assert f.attempted[-1] != base64.b64decode(saved['welcomes'][0])
    assert deserialize_envelope(f.attempted[-1])['expiry_ts'] > expiry + 1
    assert 'group_operation' not in cli._load_conversations(f.owner_dir)[0]


@pytest.mark.parametrize('delivery', ['retained', 'expired', 'missing'])
def test_join_replays_a_rekey_that_raced_before_welcome_publication(setup, monkeypatch, delivery):
    from qntm import prepare_group_session_rekey
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    racing = []

    def race(url, cid, wire):
        if deserialize_envelope(wire).get('kind') == 'group_welcome' and not racing:
            record = cli._find_conversation(cli._load_conversations(f.owner_dir), cid)
            rekey = prepare_group_session_rekey(f.owner, record['group_session'], ttl=1 if delivery == 'expired' else 3600)['rekey']
            racing.append(rekey)
            f.send(url, cid, serialize_envelope(rekey))
        return f.send(url, cid, wire)

    monkeypatch.setattr(cli, '_http_send', race)
    link = owner.add(f.cid, 'Colleague')['group_link']
    assert owner.sync(f.cid)['current_epoch'] == 2
    if delivery == 'expired':
        monkeypatch.setattr('time.time', lambda: racing[0]['expiry_ts'] + 1)
    if delivery == 'missing':
        def retained(url, cid, cursor):
            rows, head = f.receive(url, cid, cursor)
            return [row for row in rows if deserialize_envelope(base64.b64decode(row['envelope_b64']))['msg_id'] != racing[0]['msg_id']], head
        monkeypatch.setattr(cli, '_recv_once', retained)
    result = join(f.contact_dir, f.contact, link)
    if delivery != 'retained':
        assert result['recovery_required']
        recovery = cli._find_conversation(cli._load_conversations(f.contact_dir), f.cid)['group_session']['recovery']
        assert recovery['reason'] == ('expired_control' if delivery == 'expired' else 'missing_history')
        owner.refresh(f.cid, 'Colleague', recovery['challenge'])
        result = join(f.contact_dir, f.contact, link)
    assert not result['recovery_required'] and result['current_epoch'] == 2
    f.command(f.contact_dir, 'send', f.cid, 'joined after the racing rekey')
    assert any(row.get('unsafe_body') == 'joined after the racing rekey' for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


def test_join_does_not_require_history_before_the_senders_signed_anchor(setup, monkeypatch):
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    def retained(url, cid, cursor):
        rows, head = f.receive(url, cid, cursor)
        return [row for row in rows if row['seq'] > 1], head  # Old genesis predates the admitted state.
    monkeypatch.setattr(cli, '_recv_once', retained)
    result = join(f.contact_dir, f.contact, link)
    assert not result['recovery_required'] and result['current_epoch'] == 1


@pytest.mark.parametrize('timing', ['before', 'after'])
def test_first_join_blocks_competing_source_rekey_and_recovers_same_epoch(setup, monkeypatch, timing):
    from qntm import prepare_group_session_rekey, assert_group_can_send
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    injected = []

    def race(url, cid, wire):
        if deserialize_envelope(wire).get('kind') == 'group_welcome' and not injected:
            record = cli._find_conversation(cli._load_conversations(f.owner_dir), cid)
            # The recipient was included in this authenticated source roster,
            # but must never be given its pre-admission epoch0 root.
            source = copy.deepcopy(record['group_session'])
            frame = source['rekeys'][0]
            source.update(epoch=frame['epoch'], root=frame['root'], snapshot=frame['snapshot'], rekeys=[], seen={},
                          admissions=copy.deepcopy(frame['admissions']), needsRekey=True)
            with monkeypatch.context() as nested:
                nested.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
                competing = prepare_group_session_rekey(f.owner, source)['rekey']
            assert competing['msg_id'].hex() < frame['messageId']
            injected.append(competing)
            if timing == 'before':
                f.send(url, cid, serialize_envelope(competing))
        return f.send(url, cid, wire)

    monkeypatch.setattr(cli, '_http_send', race)
    with monkeypatch.context() as fixed_ids:
        ids = iter([b'\x80' * 16, b'\xf0' * 16])
        fixed_ids.setattr('qntm.message.generate_message_id', lambda: next(ids))
        link = owner.add(f.cid, 'Colleague')['group_link']

    result = join(f.contact_dir, f.contact, link)
    if timing == 'after':
        assert not result['recovery_required']
        sender = cli._find_conversation(cli._load_conversations(f.owner_dir), f.cid)['group_session']
        f.send(f.relay, f.cid, serialize_envelope(create_message(f.owner, group_session_conversation(sender), 'text', b'losing branch trigger')))
        f.send(f.relay, f.cid, serialize_envelope(injected[0]))
        result = f.command(f.contact_dir, 'recv', f.cid)
        assert not result['messages']
        assert not any(row.get('unsafe_body') == 'losing branch trigger' for row in cli._load_history(f.contact_dir, f.cid))
    initial = cli._find_conversation(cli._load_conversations(f.contact_dir), f.cid)['group_session']
    winning = owner.sync(f.cid)['group_session']
    assert initial['epoch'] == winning['epoch'] == 1
    assert initial['root'] != winning['root']
    assert initial['rekeys'] == []
    # Coverage alone is insufficient: the newcomer cannot authenticate the older source.
    assert result['recovery_required']
    with pytest.raises(ValueError, match='history|recovery'):
        assert_group_can_send(f.contact, initial)

    # A current participant can attest the winning SAME epoch with a fresh
    # challenge. The fix must permit this narrow root replacement while
    # preserving removal and pre-admission-history exclusion.
    owner.refresh(f.cid, 'Colleague', initial['recovery']['challenge'])
    recovered = join(f.contact_dir, f.contact, link)
    final = cli._find_conversation(cli._load_conversations(f.contact_dir), f.cid)['group_session']
    assert not recovered['recovery_required']
    assert final['epoch'] == 1 and final['root'] == winning['root']
    assert final['rekeys'] == []
    f.command(f.contact_dir, 'send', f.cid, 'recovered the winning branch')
    assert any(row.get('unsafe_body') == 'recovered the winning branch'
               for row in f.command(f.owner_dir, 'recv', f.cid)['messages'])


@pytest.mark.parametrize('mode', ['complete', 'reconnect', 'message_bound', 'byte_bound'])
def test_watch_does_not_dispatch_incomplete_subscription_replay(setup, monkeypatch, mode):
    import threading
    from qntm import prepare_group_session_rekey, watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    saved = owner.sync(f.cid)['group_session']
    source = copy.deepcopy(saved)
    frame = source['rekeys'][0]
    source.update(epoch=frame['epoch'], root=frame['root'], snapshot=frame['snapshot'], rekeys=[], seen={},
                          admissions=copy.deepcopy(frame['admissions']), needsRekey=True)
    competing = prepare_group_session_rekey(f.owner, source)['rekey']
    text = create_message(f.owner, group_session_conversation(saved), 'text', b'text before replay is validated')
    f.send(f.relay, f.cid, serialize_envelope(text))
    f.send(f.relay, f.cid, serialize_envelope(competing))
    cursor = cli._load_conversations(f.contact_dir)[0]['group_cursor']
    rows, head = f.receive(f.relay, f.cid, cursor)
    replay = [dict(row, type='message') for row in rows] + [{'type': 'ready', 'head_seq': head}]
    stop = threading.Event()
    ready = threading.Event()
    delivered, connections = [], []
    before = cli._load_conversations(f.contact_dir)
    if mode == 'message_bound':
        monkeypatch.setattr(watch, 'MAX_GROUP_REPLAY_MESSAGES', 1)
    if mode == 'byte_bound':
        monkeypatch.setattr(watch, 'MAX_GROUP_REPLAY_BYTES', 1)
    monkeypatch.setattr(stop, 'wait', lambda *_: stop.is_set())

    class Socket:
        def __init__(self, interrupted):
            self.frames = iter(replay[:1] if interrupted else replay)

        def recv(self, timeout):
            try:
                frame = next(self.frames)
            except StopIteration:
                assert cli._load_conversations(f.contact_dir) == before
                assert not delivered and not ready.is_set()
                raise watch.WebSocketException('interrupted before ready')
            assert not ready.is_set()
            if frame['type'] == 'ready':
                stop.set()
            return json.dumps(frame)

    @contextlib.contextmanager
    def subscription(url, options):
        connections.append(url)
        assert f'from_seq={cursor}' in url
        yield Socket(mode == 'reconnect' and len(connections) == 1)

    monkeypatch.setattr(watch, 'subscription', subscription)
    monkeypatch.setattr(watch, 'status', lambda *args, **kwargs: None)

    class Wake:
        def set(self):
            # Deterministically exercise a consumer scheduled immediately after
            # the receiver wakes it, before the next network frame is read.
            delivered.extend(watch.delivery_events(f.contact_dir, f.cid))

    def receive():
        watch.receive(f.contact_dir, f.relay, f.cid, f.contact, stop, [SimpleNamespace(wake=Wake())], ready)

    if mode.endswith('_bound'):
        with pytest.raises(watch.WatchError, match='local bound'):
            receive()
        assert cli._load_conversations(f.contact_dir) == before
    else:
        receive()
        state = cli._load_conversations(f.contact_dir)[0]['group_session']
        assert state['recovery']
    assert len(connections) == (2 if mode == 'reconnect' else 1)
    assert not ready.is_set()
    assert not delivered, 'Watch dispatched application text before validating the complete ready/head replay'


@pytest.mark.parametrize('invalidation', ['removed', 'needsRekey', 'group_operation', 'binding'])
def test_watch_rechecks_queued_events_before_each_delivery(setup, monkeypatch, invalidation):
    import threading
    from pathlib import Path
    from qntm import watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    f.command(f.owner_dir, 'send', f.cid, 'first')
    f.command(f.owner_dir, 'send', f.cid, 'second')
    f.command(f.contact_dir, 'recv', f.cid)
    assert len(delivery_events(f.contact_dir, f.cid)) == 2
    target = watch.Target('exec', ('adapter',))
    state = watch.ConsumerState(Path(f.contact_dir) / 'test-watch.json', f.relay, [target], 0)
    stop, ready = threading.Event(), threading.Event()
    consumer = watch.Consumer(target, state, f.contact_dir, f.cid, f.contact['keyID'].hex(), 1, stop, ready)
    delivered, waits = [], []

    def deliver(target, event, timeout):
        delivered.append(event['data']['message']['unsafe_body'])
        assert ready.is_set()
        records = cli._load_conversations(f.contact_dir)
        if invalidation == 'group_operation':
            records[0]['group_operation'] = {'kind': 'refresh'}
        elif invalidation == 'binding':
            for entry in records[0]['group_history']:
                entry['receive_binding']['valid'] = False
        else:
            records[0]['group_session'][invalidation] = True
        cli._save_conversations(f.contact_dir, records)

    def wait(timeout):
        waits.append(timeout)
        if len(waits) == 1:
            assert not delivered  # Even an existing queue waits for first ready.
            ready.set()
        else:
            stop.set()

    monkeypatch.setattr(watch, 'deliver', deliver)
    monkeypatch.setattr(consumer.wake, 'wait', wait)
    consumer.run()
    assert consumer.error is None
    assert delivered == ['first']
    assert not delivery_events(f.contact_dir, f.cid)


def test_watch_pauses_cached_queue_during_reconnect(setup, monkeypatch):
    import threading
    from pathlib import Path
    from qntm import watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    f.command(f.owner_dir, 'send', f.cid, 'first')
    f.command(f.owner_dir, 'send', f.cid, 'second')
    f.command(f.contact_dir, 'recv', f.cid)
    target = watch.Target('exec', ('adapter',))
    state = watch.ConsumerState(Path(f.contact_dir) / 'test-watch.json', f.relay, [target], 0)
    stop, ready = threading.Event(), threading.Event()
    ready.set()
    consumer = watch.Consumer(target, state, f.contact_dir, f.cid, f.contact['keyID'].hex(), 1, stop, ready)
    delivered, waits = [], []

    def deliver(target, event, timeout):
        delivered.append(event['data']['message']['unsafe_body'])
        assert ready.is_set()
        if len(delivered) == 1:
            ready.clear()  # Receiver detects disconnect while this sink runs.
        else:
            stop.set()

    def wait(timeout):
        if stop.is_set():
            return
        waits.append(timeout)
        assert delivered == ['first']
        if len(waits) == 2:
            ready.set()  # Only a completed reconnect replay releases the rest.

    monkeypatch.setattr(watch, 'deliver', deliver)
    monkeypatch.setattr(consumer.wake, 'wait', wait)
    consumer.run()
    assert consumer.error is None
    assert delivered == ['first', 'second']
    assert len(waits) == 2


def test_reused_id_does_not_resurrect_losing_branch_queued_plaintext(setup, monkeypatch):
    from qntm import prepare_group_session_rekey, watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    member = GroupClient(f.contact_dir, f.contact, f.relay)
    with monkeypatch.context() as fixed:
        ids = iter([b'\x80' * 16, b'\xf0' * 16])
        fixed.setattr('qntm.message.generate_message_id', lambda: next(ids))
        link = owner.add(f.cid, 'Colleague')['group_link']
    join(f.contact_dir, f.contact, link)
    saved = owner.sync(f.cid)['group_session']
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xaa' * 16)
        old = create_message(f.owner, group_session_conversation(saved), 'text', b'old losing branch plaintext')
    f.send(f.relay, f.cid, serialize_envelope(old))
    member.sync(f.cid)
    assert any(event['data']['message'].get('unsafe_body') == 'old losing branch plaintext'
               for _, event in watch.delivery_events(f.contact_dir, f.cid))

    source = copy.deepcopy(saved)
    frame = source['rekeys'][0]
    source.update(epoch=frame['epoch'], root=frame['root'], snapshot=frame['snapshot'], rekeys=[], seen={},
                          admissions=copy.deepcopy(frame['admissions']), needsRekey=True)
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\x01' * 16)
        competing = prepare_group_session_rekey(f.owner, source)['rekey']
    f.send(f.relay, f.cid, serialize_envelope(competing))
    blocked = member.sync(f.cid)['group_session']
    assert blocked['recovery']
    winning = owner.sync(f.cid)['group_session']
    assert winning['root'] != saved['root']
    owner.refresh(f.cid, 'Colleague', blocked['recovery']['challenge'])
    join(f.contact_dir, f.contact, link)
    assert not watch.delivery_events(f.contact_dir, f.cid)

    # Reusing a message ID after replacement does not mean the old ciphertext
    # digest (and its saved plaintext event) belongs to the accepted branch.
    with monkeypatch.context() as fixed:
        fixed.setattr('qntm.message.generate_message_id', lambda: b'\xaa' * 16)
        fresh = create_message(f.owner, group_session_conversation(winning), 'text', b'fresh winning branch plaintext')
    f.send(f.relay, f.cid, serialize_envelope(fresh))
    member.sync(f.cid)
    bodies = [event['data']['message'].get('unsafe_body') for _, event in watch.delivery_events(f.contact_dir, f.cid)]
    assert 'old losing branch plaintext' not in bodies
    assert 'fresh winning branch plaintext' in bodies


def test_valid_undelivered_history_survives_replay_cache_eviction(setup, monkeypatch):
    from qntm import prepare_group_session_rekey, watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    source = owner.sync(f.cid)['group_session']
    monkeypatch.setattr('qntm.group_session._MAX_SEEN', 4)
    ids = []
    for index in range(8):
        message = create_message(f.owner, group_session_conversation(source), 'text', f'queued {index}'.encode())
        ids.append(message['msg_id'].hex())
        f.send(f.relay, f.cid, serialize_envelope(message))
    GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)
    saved = cli._load_conversations(f.contact_dir)[0]
    assert len(saved['group_session']['seen']) == 4
    assert ids[0] not in saved['group_session']['seen']
    assert len(saved['group_history']) == 8
    delivered = watch.delivery_events(f.contact_dir, f.cid)
    assert [event['data']['message']['unsafe_body'] for _, event in delivered] == [f'queued {i}' for i in range(8)]


@pytest.mark.parametrize('split_replay', [False, True])
def test_watch_invalidates_superseded_history_but_preserves_source_events(setup, monkeypatch, split_replay):
    from qntm import prepare_group_session_rekey, watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    source = owner.sync(f.cid)['group_session']

    def text(state, body):
        f.send(f.relay, f.cid, serialize_envelope(create_message(
            f.owner, group_session_conversation(state), 'text', body.encode())))

    def rekey(state, mid):
        with monkeypatch.context() as fixed:
            fixed.setattr('qntm.message.generate_message_id', lambda: bytes([mid]) * 16)
            envelope = prepare_group_session_rekey(f.owner, state)['rekey']
        f.send(f.relay, f.cid, serialize_envelope(envelope))
        return receive_group_event(f.owner, envelope, state)['state']

    text(source, 'valid source message')
    losing = rekey(source, 240)
    text(losing, 'losing branch message')
    descendant = rekey(losing, 128)
    text(descendant, 'losing descendant message')
    if split_replay:
        f.command(f.contact_dir, 'recv', f.cid)
        assert any(event['data']['message'].get('unsafe_body') == 'losing branch message'
                   for _, event in watch.delivery_events(f.contact_dir, f.cid))
    winner = rekey(source, 1)
    text(winner, 'winning branch message')
    result = f.command(f.contact_dir, 'recv', f.cid)
    assert not result.get('recovery_required')
    assert all(row.get('unsafe_body') not in {'losing branch message', 'losing descendant message'}
               for row in result['messages'])
    # Ordinary dedup eviction must not revive invalidated rows or discard valid
    # pending hook deliveries, even across a fresh process/checkpoint load.
    monkeypatch.setattr('qntm.group_session._MAX_SEEN', 4)
    for index in range(8):
        text(winner, f'later {index}')
    GroupClient(f.contact_dir, f.contact, f.relay).sync(f.cid)
    bodies = [event['data']['message'].get('unsafe_body')
              for _, event in watch.delivery_events(f.contact_dir, f.cid)]
    assert 'valid source message' in bodies
    assert 'winning branch message' in bodies
    assert 'losing branch message' not in bodies
    assert 'losing descendant message' not in bodies
    assert all(f'later {index}' in bodies for index in range(8))


def test_new_watch_target_baseline_ignores_temporary_delivery_pause(setup, monkeypatch):
    from qntm import watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    f.command(f.owner_dir, 'send', f.cid, 'already in local history')
    f.command(f.contact_dir, 'recv', f.cid)
    records = cli._load_conversations(f.contact_dir)
    expected = records[0]['group_history'][-1]['receive_order']
    records[0]['group_operation'] = {'kind': 'refresh'}
    cli._save_conversations(f.contact_dir, records)
    assert not watch.delivery_events(f.contact_dir, f.cid)
    targets = []

    def receive(config_dir, relay, cid, identity, stop, consumers, ready):
        for consumer in consumers:
            targets.append(consumer.target)
            assert consumer.state.cursor(consumer.target) == expected
            assert consumer.replay_ready is ready and not ready.is_set()
        stop.set()

    monkeypatch.setattr(watch, 'receive', receive)
    monkeypatch.setattr(watch.Consumer, 'start', lambda self: None)
    monkeypatch.setattr(watch.Consumer, 'join', lambda self: None)
    watch.watch(SimpleNamespace(config_dir=f.contact_dir, conversation=f.cid, dropbox_url=f.relay,
                                webhook=[], on_receive=[], include_self=False, hook_timeout=1))
    assert len(targets) == 1


def test_watch_gates_live_group_commit_before_waking_consumers(setup, monkeypatch):
    import threading
    from qntm import watch
    f = setup
    owner = GroupClient(f.owner_dir, f.owner, f.relay)
    join(f.contact_dir, f.contact, owner.add(f.cid, 'Colleague')['group_link'])
    cursor = cli._load_conversations(f.contact_dir)[0]['group_cursor']
    f.command(f.owner_dir, 'send', f.cid, 'live message')
    rows, _ = f.receive(f.relay, f.cid, cursor)
    frames = iter([{'type': 'ready', 'head_seq': cursor}, dict(rows[0], type='message')])
    stop, ready = threading.Event(), threading.Event()
    processed, delivered = [], []
    original = cli._process_received_messages

    def process(*args):
        assert not ready.is_set(), 'Consumers must wait while a newly received group batch is checked'
        processed.append(args[-1])
        return original(*args)

    class Socket:
        def recv(self, timeout):
            frame = next(frames)
            if frame['type'] == 'message':
                assert ready.is_set()
                stop.set()
            return json.dumps(frame)

    @contextlib.contextmanager
    def subscription(*args):
        yield Socket()

    class Wake:
        def set(self):
            assert ready.is_set()
            delivered.extend(watch.delivery_events(f.contact_dir, f.cid))

    monkeypatch.setattr(watch, 'subscription', subscription)
    monkeypatch.setattr(cli, '_process_received_messages', process)
    watch.receive(f.contact_dir, f.relay, f.cid, f.contact, stop, [SimpleNamespace(wake=Wake())], ready)
    assert processed == [cursor, cursor + 1]
    assert [event['data']['message']['unsafe_body'] for _, event in delivered] == ['live message']
    assert not ready.is_set()
