"""Loss of an HTTP acknowledgement must not cause a duplicate POST."""
import base64
import http.client
import json
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest
from qntm import cli
from qntm.identity import generate_identity
from qntm.invite import create_invite, derive_conversation_keys, create_conversation
from qntm.message import create_message, serialize_envelope, default_ttl


@pytest.fixture
def message():
    identity = generate_identity()
    invite = create_invite(identity)
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    envelope = create_message(identity, conversation, 'text', b'recovery test', None, default_ttl())
    return conversation['id'].hex(), envelope['msg_id'].hex(), serialize_envelope(envelope)


@pytest.mark.parametrize('error', [http.client.RemoteDisconnected('response lost'), TimeoutError(),
                                  http.client.IncompleteRead(b'{'), URLError('TLS failed')])
def test_response_loss_checks_exact_envelope_without_posting_again(message, monkeypatch, error):
    cid, mid, raw = message
    post = Mock(side_effect=error)
    find = Mock(return_value=42)
    monkeypatch.setattr(cli.urllib.request, 'urlopen', post)
    monkeypatch.setattr(cli, '_find_sent_envelope', find)
    assert cli._http_send('https://relay.example', cid, raw) == {'seq': 42, 'acknowledgement': 'reconciled'}
    assert post.call_count == 1
    find.assert_called_once_with('https://relay.example', cid, raw)
    assert json.loads(post.call_args.args[0].data)['msg_id'] == mid


@pytest.mark.parametrize('replay', [Mock(return_value=None), Mock(side_effect=TimeoutError())])
def test_unconfirmed_send_exposes_id_and_unknown_not_rejection(message, monkeypatch, replay):
    cid, mid, raw = message
    monkeypatch.setattr(cli.urllib.request, 'urlopen', Mock(side_effect=http.client.RemoteDisconnected()))
    monkeypatch.setattr(cli, '_find_sent_envelope', replay)
    with pytest.raises(cli.SendDeliveryUnknown) as raised:
        cli._http_send('https://relay.example', cid, raw)
    assert raised.value.message_id == mid
    assert raised.value.conversation_id == cid
    assert 'before resending' in str(raised.value)


def test_explicit_4xx_does_not_attempt_recovery(message, monkeypatch):
    cid, _, raw = message
    error = HTTPError('https://relay.example', 403, 'rejected', {}, None)
    monkeypatch.setattr(cli.urllib.request, 'urlopen', Mock(side_effect=error))
    find = Mock(); monkeypatch.setattr(cli, '_find_sent_envelope', find)
    with pytest.raises(HTTPError): cli._http_send('https://relay.example', cid, raw)
    find.assert_not_called()


@pytest.mark.parametrize('body', [b'{"seq":9}', b'{', b'{}'])
def test_acknowledgement_validation(message, monkeypatch, body):
    cid, _, raw = message
    from unittest.mock import MagicMock
    response = MagicMock(); response.__enter__.return_value.read.return_value = body
    monkeypatch.setattr(cli.urllib.request, 'urlopen', Mock(return_value=response))
    find = Mock(return_value=10); monkeypatch.setattr(cli, '_find_sent_envelope', find)
    result = cli._http_send('https://relay.example', cid, raw)
    assert result['seq'] == (9 if body == b'{"seq":9}' else 10)
    assert find.call_count == (0 if body == b'{"seq":9}' else 1)


def test_replay_compares_full_envelope_and_keeps_tls_enabled(message, monkeypatch):
    cid, mid, raw = message
    frames = [
        {'type': 'message', 'seq': 1, 'msg_id': mid, 'envelope_b64': base64.b64encode(b'forged').decode()},
        {'type': 'message', 'seq': 2, 'envelope_b64': '*invalid*'},
        {'type': 'message', 'seq': 3, 'envelope_b64': base64.b64encode(raw).decode()},
    ]
    from unittest.mock import MagicMock
    socket = MagicMock(); socket.__enter__.return_value.recv.side_effect = map(json.dumps, frames)
    connect = Mock(return_value=socket)
    monkeypatch.setattr('websockets.sync.client.connect', connect)
    assert cli._find_sent_envelope('https://relay.example', cid, raw) == 3
    assert connect.call_args.kwargs['ssl'] is cli._ssl_context
    assert connect.call_args.args[0].startswith('wss://relay.example/v1/subscribe?')


def test_replay_bounds_and_absence_are_unknown(message, monkeypatch):
    cid, _, raw = message
    from unittest.mock import MagicMock
    socket = MagicMock(); socket.__enter__.return_value.recv.return_value = '{"type":"message","seq":1,"envelope_b64":"eA=="}'
    monkeypatch.setattr('websockets.sync.client.connect', Mock(return_value=socket))
    assert cli._find_sent_envelope('https://relay.example', cid, raw) is None
    assert socket.__enter__.return_value.recv.call_count == 1000
    socket.__enter__.return_value.recv.return_value = '{"type":"ready","head_seq":1}'
    assert cli._find_sent_envelope('https://relay.example', cid, raw) is None


@pytest.mark.parametrize('error,code', [(cli.SendDeliveryUnknown('a'*32, 'b'*32, TimeoutError()), 'send_delivery_unknown'),
                                      (URLError('https://secret:password@relay.example'), 'network_error')])
def test_cli_boundary_returns_structured_error_without_traceback(monkeypatch, capsys, error, code):
    monkeypatch.setattr(cli, '_main', Mock(side_effect=error))
    with pytest.raises(SystemExit) as exited: cli.main()
    assert exited.value.code == 1
    captured = capsys.readouterr()
    result = json.loads(captured.err)
    assert result['ok'] is False and result['code'] == code
    assert 'Traceback' not in captured.err and 'password' not in captured.err
    if code == 'send_delivery_unknown': assert result['data']['message_id'] == 'b'*32
