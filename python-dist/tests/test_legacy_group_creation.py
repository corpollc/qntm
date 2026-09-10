"""Legacy genesis recovery keeps original ciphertext and gateway-compatible state."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest

from qntm import cli, legacy_group
from qntm.gate import open_secret
from qntm.group_client import GroupClient
from qntm.identity import generate_identity, base64url_encode, base64url_decode
from qntm.message import deserialize_envelope, decrypt_message, create_message, serialize_envelope

RELAY = 'https://relay.example'


@pytest.fixture
def profile(tmp_path):
    identity = generate_identity()
    cli._save_identity(str(tmp_path), identity)
    return str(tmp_path), identity


def journal(config_dir, cid):
    return json.loads(Path(config_dir, 'groups', cid + '.creation.json').read_text())


def pending(profile, monkeypatch):
    config_dir, identity = profile
    def fail(relay, cid, wire):
        assert journal(config_dir, cid)['envelope_b64'] == base64.b64encode(wire).decode()
        assert cli._load_group_state(config_dir, cid).creator == identity['keyID']
        assert cli._find_conversation(cli._load_conversations(config_dir), cid)
        raise cli.SendDeliveryUnknown(cid, deserialize_envelope(wire)['msg_id'].hex(), TimeoutError())
    monkeypatch.setattr(cli, '_http_send', fail)
    with pytest.raises(legacy_group.LegacyCreationError) as error:
        legacy_group.create(config_dir, identity, RELAY, 'Legacy', 'Gateway-capable group')
    assert error.value.data['delivery'] == 'unknown'
    cid = error.value.data['conversation_id']
    return cid, base64.b64decode(journal(config_dir, cid)['envelope_b64'])


def test_lost_ack_reconciles_exact_ciphertext_before_retry(profile, monkeypatch):
    cid, wire = pending(profile, monkeypatch)
    find = Mock(return_value=7)
    monkeypatch.setattr(cli, '_find_sent_envelope', find)
    post = Mock(side_effect=AssertionError('must not post an accepted genesis again'))
    monkeypatch.setattr(cli, '_http_send', post)
    result = GroupClient(*profile, RELAY).retry(cid)
    assert result['delivery'] == 'accepted' and result['evidence'] == 'exact_replay' and result['seq'] == 7
    find.assert_called_once_with(RELAY, cid, wire)
    assert journal(profile[0], cid)['receipt'] == {'seq': 7, 'evidence': 'exact_replay'}
    assert 'group_session' not in cli._load_conversations(profile[0])[0]
    post.assert_not_called()


def test_unconfirmed_retry_posts_original_bytes_and_keeps_receipt(profile, monkeypatch):
    cid, wire = pending(profile, monkeypatch)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=None))
    post = Mock(return_value={'seq': 4})
    monkeypatch.setattr(cli, '_http_send', post)
    result = GroupClient(*profile, RELAY).retry(cid)
    post.assert_called_once_with(RELAY, cid, wire)
    assert result['evidence'] == 'relay_acknowledgement'
    # A restart after the ACK was saved but before stdout must not send again,
    # even if normal legacy use has subsequently advanced group keys.
    records = cli._load_conversations(profile[0])
    records[0]['current_epoch'] = 1
    records[0]['keys']['root'] = 'ff' * 32
    cli._save_conversations(profile[0], records)
    assert GroupClient(*profile, RELAY).retry(cid)['message_id'] == result['message_id']
    assert post.call_count == 1
    assert cli._load_conversations(profile[0])[0]['current_epoch'] == 1


@pytest.mark.parametrize('alteration', ['identity', 'relay', 'mode'])
def test_pending_creation_cannot_change_identity_relay_or_silently_enable_contacts(profile, monkeypatch, alteration):
    cid, wire = pending(profile, monkeypatch)
    post, find = Mock(), Mock()
    monkeypatch.setattr(cli, '_http_send', post)
    monkeypatch.setattr(cli, '_find_sent_envelope', find)
    if alteration == 'mode':
        with pytest.raises(ValueError, match='genesis delivery is pending'):
            GroupClient(*profile, RELAY).add(cid, generate_identity()['publicKey'].hex())
    else:
        identity = generate_identity() if alteration == 'identity' else profile[1]
        relay = 'https://different.example' if alteration == 'relay' else RELAY
        with pytest.raises(legacy_group.LegacyCreationError, match='original ' + alteration):
            GroupClient(profile[0], identity, relay).retry(cid)
    post.assert_not_called()
    find.assert_not_called()
    assert base64.b64decode(journal(profile[0], cid)['envelope_b64']) == wire
    assert 'group_session' not in cli._load_conversations(profile[0])[0]


@pytest.mark.parametrize('replayed', [True, False])
def test_expired_original_is_completed_only_with_exact_receipt(profile, monkeypatch, replayed):
    cid, wire = pending(profile, monkeypatch)
    expired_at = deserialize_envelope(wire)['expiry_ts'] + 1
    monkeypatch.setattr('qntm.message.time.time', lambda: expired_at)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=8 if replayed else None))
    post = Mock()
    monkeypatch.setattr(cli, '_http_send', post)
    if replayed:
        assert GroupClient(*profile, RELAY).retry(cid)['seq'] == 8
    else:
        with pytest.raises(legacy_group.LegacyCreationError, match='expired'):
            GroupClient(*profile, RELAY).retry(cid)
        assert 'receipt' not in journal(profile[0], cid)
    post.assert_not_called()
    assert base64.b64decode(journal(profile[0], cid)['envelope_b64']) == wire


def test_pending_genesis_cannot_be_reposted_after_membership_changed(profile, monkeypatch):
    cid, wire = pending(profile, monkeypatch)
    records = cli._load_conversations(profile[0])
    records[0]['current_epoch'] = 1
    cli._save_conversations(profile[0], records)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=None))
    post = Mock()
    monkeypatch.setattr(cli, '_http_send', post)
    with pytest.raises(legacy_group.LegacyCreationError, match='keys changed'):
        GroupClient(*profile, RELAY).retry(cid)
    post.assert_not_called()
    assert base64.b64decode(journal(profile[0], cid)['envelope_b64']) == wire


def test_ack_persistence_failure_keeps_original_and_reconciles(profile, monkeypatch):
    save = cli._save_json
    def fail_receipt(path, value):
        if str(path).endswith('.creation.json') and 'receipt' in value:
            raise OSError('disk full')
        return save(path, value)
    monkeypatch.setattr(cli, '_save_json', fail_receipt)
    post = Mock(return_value={'seq': 9})
    monkeypatch.setattr(cli, '_http_send', post)
    with pytest.raises(legacy_group.LegacyCreationError) as error:
        legacy_group.create(*profile, RELAY, 'Legacy')
    assert error.value.data['delivery'] == 'accepted'
    cid = error.value.data['conversation_id']
    assert 'receipt' not in journal(profile[0], cid)
    monkeypatch.setattr(cli, '_save_json', save)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=9))
    assert GroupClient(*profile, RELAY).retry(cid)['seq'] == 9
    assert post.call_count == 1


def test_partial_local_preparation_never_posts_and_retry_restores_missing_state(profile, monkeypatch):
    save = cli._save_group_state
    monkeypatch.setattr(cli, '_save_group_state', Mock(side_effect=OSError('disk full')))
    post = Mock(return_value={'seq': 1})
    monkeypatch.setattr(cli, '_http_send', post)
    with pytest.raises(legacy_group.LegacyCreationError) as error:
        legacy_group.create(*profile, RELAY, 'Legacy')
    assert error.value.data['delivery'] == 'not_sent'
    post.assert_not_called()
    cid = error.value.data['conversation_id']
    monkeypatch.setattr(cli, '_save_group_state', save)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=None))
    assert GroupClient(*profile, RELAY).retry(cid)['members'] == 1
    assert cli._load_group_state(profile[0], cid).creator == profile[1]['keyID']


def test_mcp_retries_legacy_cli_creation_and_reports_rejection(profile, monkeypatch):
    from qntm import mcp_server
    cid, wire = pending(profile, monkeypatch)
    monkeypatch.setenv('QNTM_CONFIG_DIR', profile[0])
    monkeypatch.delenv('QNTM_RELAY_URL', raising=False)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=None))
    monkeypatch.setattr(cli, '_http_send', Mock(side_effect=HTTPError(RELAY, 403, 'private failure', {}, None)))
    error = mcp_server.group_retry(cid)
    assert error['conversation_id'] == cid and error['delivery'] == 'rejected'
    assert error['http_status'] == 403 and error['retry_tool'] == 'group_retry'
    assert 'private failure' not in error['error']
    monkeypatch.setattr(cli, '_http_send', Mock(return_value={'seq': 3}))
    result = mcp_server.group_retry(cid)
    assert result['conversation_id'] == cid and result['delivery'] == 'accepted'
    assert 'group_session' not in cli._load_conversations(profile[0])[0]


@pytest.mark.parametrize('failure', ['lost_ack', 'rejected', 'killed'])
def test_real_cli_process_restart_retries_exact_genesis(profile, failure):
    """Two actual CLI processes, local HTTP transport, and relay-style ID dedup.

    The fixture intentionally has no replay service: absence cannot authorize
    fresh bytes, so restart exercises the exact POST retry fallback.
    """
    requests, accepted = [], {}
    committed, release = threading.Event(), threading.Event()
    class Relay(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_POST(self):
            row = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append(row)
            if len(requests) == 1 and failure == 'rejected':
                self.send_error(403)
                return
            accepted.setdefault(row['msg_id'], (len(accepted) + 1, row['envelope_b64']))
            if len(requests) == 1:
                committed.set()
                if failure == 'killed':
                    release.wait(timeout=10)
                    return
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            seq, original = accepted[row['msg_id']]
            assert original == row['envelope_b64']
            body = json.dumps({'seq': seq}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Relay)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    relay = f'http://127.0.0.1:{server.server_port}'
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
    command = [sys.executable, '-m', 'qntm.cli', '--config-dir', profile[0]]
    process = None
    try:
        create = [*command, '--dropbox-url', relay, 'group', 'create', 'Legacy']
        if failure == 'killed':
            process = subprocess.Popen(create, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert committed.wait(timeout=10), 'child never posted its saved genesis'
            process.kill()
            stdout, _ = process.communicate(timeout=10)
            assert not stdout
            release.set()
            cid = cli._load_conversations(profile[0])[0]['id']
            message_id = requests[0]['msg_id']
        else:
            failed = subprocess.run(create, env=env, text=True, capture_output=True, timeout=30)
            assert failed.returncode == 1 and not failed.stdout
            error = json.loads(failed.stderr)
            assert error['code'] == 'legacy_group_creation_incomplete'
            assert error['data']['delivery'] == ('unknown' if failure == 'lost_ack' else 'rejected')
            cid, message_id = error['data']['conversation_id'], error['data']['message_id']
        saved = journal(profile[0], cid)
        # A fresh process uses the saved relay even without --dropbox-url.
        completed = subprocess.run([*command, 'group', 'retry', cid], env=env, text=True, capture_output=True, timeout=30)
        assert completed.returncode == 0, completed.stderr
        result = json.loads(completed.stdout)['data']
        assert result['delivery'] == 'accepted' and result['evidence'] == 'relay_acknowledgement'
        assert result['message_id'] == message_id
        assert len(requests) == 2 and requests[0] == requests[1]
        assert len(accepted) == 1
        assert saved['envelope_b64'] == requests[1]['envelope_b64']
        assert 'group_session' not in cli._load_conversations(profile[0])[0]
    finally:
        if process and process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_recovered_legacy_group_preserves_gateway_promotion_and_acceptance(profile, monkeypatch, capsys):
    cid, genesis = pending(profile, monkeypatch)
    monkeypatch.setattr(cli, '_find_sent_envelope', Mock(return_value=1))
    recovered = GroupClient(*profile, RELAY).retry(cid)
    records = cli._load_conversations(profile[0])
    original = cli._conv_to_crypto(records[0])
    assert decrypt_message(deserialize_envelope(genesis), original)['inner']['body_type'] == 'group_genesis'
    gateway = generate_identity()
    invitation = {'invitation_id': 'ab' * 16, 'inviter_public_key': base64url_encode(profile[1]['publicKey']),
                  'gateway_public_key': base64url_encode(gateway['publicKey']), 'gateway_kid': base64url_encode(gateway['keyID']),
                  'expires_at': int(cli.time.time()) + 600}
    sent, bootstraps = [], []
    class Gateway:
        def __init__(self, url):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def create_invitation(self, *args):
            return invitation
        def promote(self, request):
            bootstraps.append(request)
    monkeypatch.setattr(cli, 'GateClient', Gateway)
    monkeypatch.setattr(cli, '_http_send', lambda relay, conv_id, wire: sent.append(wire) or {'seq': 2})
    args = SimpleNamespace(config_dir=profile[0], dropbox_url=RELAY, conversation=cid, gateway_url='https://gateway.example', threshold=1)
    cli.cmd_gate_promote(args)
    assert json.loads(capsys.readouterr().out)['data']['status'] == 'waiting'
    promotion = decrypt_message(deserialize_envelope(sent[0]), original)
    assert promotion['inner']['body_type'] == 'gate.promote'
    bootstrap = json.loads(open_secret(gateway['privateKey'], profile[1]['publicKey'], base64url_decode(bootstraps[0]['sealed'])))
    assert bootstrap['conv_aead_key'] == base64url_encode(original['keys']['aeadKey'])
    assert bootstrap['invitation_seq'] == 2
    body = json.loads(promotion['inner']['body'])
    acceptance = {key: body[key] for key in ('invitation_id', 'conv_id', 'conv_epoch', 'gateway_kid', 'gateway_public_key')}
    acceptance.update(type='gate.accept', invitation_msg_id=promotion['envelope']['msg_id'].hex(),
                      invitation_hash=hashlib.sha256(promotion['inner']['body']).hexdigest())
    envelope = create_message(gateway, original, 'gate.accept', json.dumps(acceptance).encode())
    records = cli._load_conversations(profile[0])
    cli._process_received_messages(profile[0], profile[1], records, records[0],
                                   [{'seq': 3, 'envelope_b64': base64.b64encode(serialize_envelope(envelope)).decode()}], 3)
    record = cli._load_conversations(profile[0])[0]
    assert record['gateway']['status'] == 'active'
    assert 'group_session' not in record and record['invite_token'] == recovered['invite_token']
    assert cli._conv_for_send(profile[0], profile[1], record, RELAY)['keys'] == original['keys']
    assert GroupClient(*profile, RELAY).retry(cid)['seq'] == 1
    assert len(sent) == 1
