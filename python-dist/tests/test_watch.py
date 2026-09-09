"""Resident receive, independent durable consumers, and real local hook I/O."""
import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import queue
import shlex
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from websockets.exceptions import WebSocketException
from websockets.sync.server import serve

from qntm import cli, watch
from qntm.storage import load_json, private_lock
from test_receive import conversation, wire, rotated


def args(path, record, **kwargs):
    return SimpleNamespace(config_dir=path, conversation=record["id"], dropbox_url="http://127.0.0.1:9999",
                           watch=True, webhook=[], on_receive=[], include_self=False, hook_timeout=2, **kwargs)


def ingest(conversation, frames):
    path, record, alice, _, _ = conversation
    return cli._process_received_messages(path, alice, [record], record, frames, frames[-1]["seq"])


def frame(sender, record, sequence, body=b"hello", body_type="text"):
    return {"type": "message", "seq": sequence, **wire(sender, record, body_type, body)}


def wait_for(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    pytest.fail("timed out waiting for condition")


@contextmanager
def http_endpoint(handler):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            code, headers = handler(self.path, json.loads(body), self.headers)
            self.send_response(code)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_watch_stays_after_ready_and_reconnects_from_durable_cursor(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    rekey, updated = rotated(record, alice)
    first = frame(bob, record, 1, rekey, "group_rekey")
    second = frame(bob, updated, 2, b"live after reconnect")
    stop = threading.Event()
    def finish(**_):
        stop.set()
        raise TimeoutError()
    socket1 = Mock()
    socket1.recv.side_effect = [json.dumps({"type": "ready", "head_seq": 0}), json.dumps(first),
                                WebSocketException("connection lost")]
    socket2 = Mock()
    socket2.recv.side_effect = [json.dumps(first), json.dumps({"type": "ready", "head_seq": 1}),
                                json.dumps(second), finish]
    # Mock side_effect doesn't invoke callables inside lists.
    frames = iter(socket2.recv.side_effect)
    def receive2(**kwargs):
        item = next(frames)
        return item(**kwargs) if callable(item) else item
    socket2.recv.side_effect = receive2
    connect = Mock(side_effect=[socket1, socket2])
    monkeypatch.setattr(watch, "connect", connect)
    monkeypatch.setattr(stop, "wait", lambda *_: stop.is_set())
    watch.receive(path, "https://relay.example", record["id"], alice, stop, [])
    assert connect.call_count == 2
    assert "from_seq=0" in connect.call_args_list[0].args[0]
    assert "from_seq=1" in connect.call_args_list[1].args[0]
    assert connect.call_args.kwargs["ssl"] is cli._ssl_context
    assert cli._load_cursors(path)[record["id"]] == 2
    assert cli._load_conversations(path)[0]["keys"] == updated["keys"]
    received = watch.events(path, record["id"])
    assert len(received) == 2
    assert received[-1]["data"]["message"]["unsafe_body"] == "live after reconnect"
    socket1.close.assert_called_once()
    socket2.close.assert_called_once()


def test_offline_connection_retries_but_disk_failure_stops(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    stop = threading.Event()
    monkeypatch.setattr(stop, "wait", lambda *_: stop.is_set())
    socket = Mock()
    socket.recv.return_value = json.dumps(frame(bob, record, 1))
    connect = Mock(side_effect=[OSError("network unreachable"), socket])
    monkeypatch.setattr(watch, "connect", connect)
    monkeypatch.setattr(cli, "_save_history", Mock(side_effect=OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        watch.receive(path, "http://relay.example", record["id"], alice, stop, [])
    assert connect.call_count == 2
    assert cli._load_cursors(path) == {}


def test_independent_hook_retry_survives_restart_and_one_shot_recv(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    destination = watch.Target("webhook", "http://localhost:1234/incoming")
    stdout = watch.Target("stdout", include_self=True)
    state_path = Path(path) / "watch" / "test.json"
    state = watch.ConsumerState(state_path, "relay", [destination, stdout], 0)
    # Ordinary recv commits to the inbox while the watch is offline.
    ingest(conversation, [frame(bob, record, 1)])
    sent = []
    stop = threading.Event()
    def fail(target, event, timeout):
        sent.append(event)
        stop.set()
        raise TimeoutError("private destination must not appear in logs")
    monkeypatch.setattr(watch, "deliver", fail)
    consumer = watch.Consumer(destination, state, path, record["id"], alice["keyID"].hex(), 1, stop)
    consumer.run()
    assert state.cursor(destination) == 0
    # Another sink can acknowledge independently.
    state.acknowledge(stdout, 1)
    reloaded = watch.ConsumerState(state_path, "relay", [destination, stdout], 1)
    assert reloaded.cursor(destination) == 0
    assert reloaded.cursor(stdout) == 1
    stop.clear()
    def succeed(target, event, timeout):
        sent.append(event)
        stop.set()
    monkeypatch.setattr(watch, "deliver", succeed)
    watch.Consumer(destination, reloaded, path, record["id"], alice["keyID"].hex(), 1, stop).run()
    assert reloaded.cursor(destination) == 1
    assert sent[0] == sent[1]
    assert sent[0]["data"]["message"]["verified"] is True


def test_acknowledgement_write_failure_retries_same_event(conversation, monkeypatch):
    path, record, alice, bob, _ = conversation
    target = watch.Target("exec", ("adapter",))
    state_path = Path(path) / "watch.json"
    state = watch.ConsumerState(state_path, "relay", [target], 0)
    ingest(conversation, [frame(bob, record, 1)])
    sent = []
    monkeypatch.setattr(watch, "deliver", lambda _, event, __: sent.append(event))
    save = watch.save_json
    monkeypatch.setattr(watch, "save_json", Mock(side_effect=OSError("disk full")))
    consumer = watch.Consumer(target, state, path, record["id"], alice["keyID"].hex(), 1, threading.Event())
    consumer.run()
    assert isinstance(consumer.error, OSError)
    assert state.cursor(target) == load_json(state_path)["consumers"][target.id] == 0
    monkeypatch.setattr(watch, "save_json", save)
    reloaded = watch.ConsumerState(state_path, "relay", [target], 1)
    stop = threading.Event()
    monkeypatch.setattr(watch, "deliver", lambda _, event, __: (sent.append(event), stop.set()))
    watch.Consumer(target, reloaded, path, record["id"], alice["keyID"].hex(), 1, stop).run()
    assert sent[0]["data"]["event_id"] == sent[1]["data"]["event_id"]


def test_self_messages_do_not_trigger_hook_but_stdout_receives_them(conversation, monkeypatch):
    path, record, alice, _, _ = conversation
    ingest(conversation, [frame(alice, record, 1)])
    for target, expected in [(watch.Target("exec", ("adapter",)), 0),
                             (watch.Target("exec", ("adapter",), True), 1),
                             (watch.Target("stdout", include_self=True), 1)]:
        state = watch.ConsumerState(Path(path) / (target.id.replace(":", "-") + ".json"), "relay", [target], 0)
        stop = threading.Event()
        calls = Mock()
        monkeypatch.setattr(watch, "deliver", calls)
        consumer = watch.Consumer(target, state, path, record["id"], alice["keyID"].hex(), 1, stop)
        consumer.start()
        try:
            wait_for(lambda: state.cursor(target) == 1)
        finally:
            stop.set(); consumer.wake.set(); consumer.join(2)
        assert calls.call_count == expected


def test_invalid_or_cross_conversation_messages_never_reach_hooks(conversation):
    path, record, _, bob, _ = conversation
    invalid = {"seq": 1, "envelope_b64": base64.b64encode(b"invalid").decode()}
    other = {**record, "id": "ab" * 16}
    ingest(conversation, [invalid, frame(bob, other, 2)])
    assert watch.events(path, record["id"]) == []


def test_stale_history_append_cannot_erase_received_event(conversation):
    path, record, _, bob, _ = conversation
    stale = cli._load_history(path, record["id"])
    ingest(conversation, [frame(bob, record, 1)])
    cli._save_history(path, record["id"], stale + [{"msg_id": "outgoing", "direction": "outgoing"}])
    assert len(watch.events(path, record["id"])) == 1
    assert len(cli._load_history(path, record["id"])) == 2


@pytest.mark.parametrize("url", ["ftp://host", "https://user:secret@host", "http://host/#fragment",
                                  "http://host:99999/", "http://host/path\nsecret"])
def test_invalid_webhook_fails_before_receiving(conversation, url):
    path, record, *_ = conversation
    options = args(path, record)
    options.webhook = [url]
    with pytest.raises(watch.WatchError, match="HTTP") as error:
        watch.watch(options)
    assert "secret" not in str(error.value)
    assert cli._load_cursors(path) == {}


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), 301])
def test_invalid_timeout(conversation, timeout):
    options = args(conversation[0], conversation[1])
    options.hook_timeout = timeout
    with pytest.raises(watch.WatchError, match="timeout"):
        watch.targets(options)


def test_real_webhook_acceptance_and_redirects(conversation):
    path, record, _, bob, _ = conversation
    ingest(conversation, [frame(bob, record, 1)])
    event = watch.events(path, record["id"])[0]
    received = []
    def handler(path, body, headers):
        received.append((path, body, headers["Idempotency-Key"]))
        return (302, {"Location": "/elsewhere"}) if path == "/redirect" else (204, {})
    with http_endpoint(handler) as url:
        watch.deliver(watch.Target("webhook", url + "/accept"), event, 2)
        with pytest.raises(watch.urllib.error.HTTPError):
            watch.deliver(watch.Target("webhook", url + "/redirect"), event, 2)
    assert [item[0] for item in received] == ["/accept", "/redirect"]
    assert received[0][1] == event
    assert received[0][2] == event["data"]["event_id"]


def test_executable_receives_json_without_shell_interpolation(conversation, tmp_path):
    path, record, _, bob, _ = conversation
    sentinel = tmp_path / "must-not-exist"
    text = f"$(touch {sentinel}); `touch {sentinel}`"
    ingest(conversation, [frame(bob, record, 1, text.encode())])
    event = watch.events(path, record["id"])[0]
    output = tmp_path / "adapter-output.json"
    adapter = tmp_path / "adapter.py"
    adapter.write_text("import pathlib, sys\npathlib.Path(sys.argv[1]).write_text(sys.stdin.read())\nprint('not JSONL')\n")
    options = args(path, record)
    options.on_receive = [shlex.join([sys.executable, str(adapter), str(output)])]
    target = watch.targets(options)[1]
    watch.deliver(target, event, 2)
    assert json.loads(output.read_text()) == event
    assert not sentinel.exists()
    with pytest.raises(watch.WatchError, match="unsuccessfully"):
        watch.deliver(watch.Target("exec", (sys.executable, "-c", "raise SystemExit(1)")), event, 2)
    with pytest.raises(subprocess.TimeoutExpired):
        watch.deliver(watch.Target("exec", (sys.executable, "-c", "import time; time.sleep(10)")), event, 0.1)


def test_single_watcher_lock_and_invalid_one_shot_hook(conversation, capsys):
    path, record, *_ = conversation
    with private_lock(Path(path) / "watch" / (record["id"] + ".lock")):
        with pytest.raises(watch.WatchError, match="already running"):
            watch.watch(args(path, record))
    options = args(path, record)
    options.watch = False
    options.webhook = ["http://localhost/receive"]
    with pytest.raises(SystemExit):
        cli.cmd_recv(options)
    assert json.loads(capsys.readouterr().err)["code"] == "invalid_arguments"


def test_real_cli_live_subscription_and_slow_hook_do_not_block_stdout(conversation):
    path, record, alice, bob, _ = conversation
    incoming = queue.Queue()
    hook_calls = []
    allow_hook = threading.Event()
    def handler(_path, event, _headers):
        hook_calls.append(event)
        allow_hook.wait(3)
        return 204, {}
    def relay(socket):
        socket.send('{"type":"ready","head_seq":0}')
        while True:
            message = incoming.get(timeout=10)
            if message is None:
                return
            socket.send(json.dumps(message))
    with http_endpoint(handler) as url, serve(relay, "127.0.0.1", 0) as server:
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        port = server.socket.getsockname()[1]
        process = subprocess.Popen([sys.executable, "-m", "qntm.cli", "--config-dir", path,
                                    "--dropbox-url", f"http://127.0.0.1:{port}", "recv", record["id"],
                                    "--watch", "--webhook", url, "--hook-timeout", "5"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = queue.Queue(), queue.Queue()
        def read(stream, output):
            for line in stream:
                output.put(json.loads(line))
        readers = [threading.Thread(target=read, args=(stream, output), daemon=True)
                   for stream, output in [(process.stdout, stdout), (process.stderr, stderr)]]
        for reader in readers:
            reader.start()
        try:
            assert stderr.get(timeout=5)["data"]["state"] == "connecting"
            assert stderr.get(timeout=5)["data"]["state"] == "ready"
            incoming.put(frame(bob, record, 1, b"first live message"))
            assert stdout.get(timeout=5)["data"]["sequence"] == 1
            wait_for(lambda: len(hook_calls) == 1)
            incoming.put(frame(bob, record, 2, b"while hook is busy"))
            assert stdout.get(timeout=2)["data"]["message"]["unsafe_body"] == "while hook is busy"
            allow_hook.set()
            wait_for(lambda: len(hook_calls) == 2)
            state_path = Path(path) / "watch" / (record["id"] + ".json")
            wait_for(lambda: all(value == 2 for value in load_json(state_path)["consumers"].values()))
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=5) == 0
            assert cli._load_cursors(path)[record["id"]] == 2
            assert stat_mode(state_path) == 0o600
        finally:
            allow_hook.set()
            incoming.put(None)
            if process.poll() is None:
                process.kill(); process.wait()
            for reader in readers:
                reader.join(2)
            process.stdout.close(); process.stderr.close()
            server.shutdown()
            server_thread.join(2)


def stat_mode(path):
    import stat
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe backpressure")
def test_stdout_backpressure_does_not_prevent_shutdown(monkeypatch):
    import select
    read_fd, write_fd = os.pipe()
    stop = threading.Event()
    stopped = []
    monkeypatch.setattr(watch.sys, "stdout", SimpleNamespace(fileno=lambda: write_fd))
    def write():
        try:
            watch._stdout(b"x" * (2 << 20), stop)
        except watch._Stopped:
            stopped.append(True)
    thread = threading.Thread(target=write)
    try:
        thread.start()
        assert select.select([read_fd], [], [], 2)[0]
        stop.set()
        thread.join(2)
        assert not thread.is_alive()
        assert stopped == [True]
        assert os.get_blocking(write_fd) is True
    finally:
        stop.set()
        thread.join(2)
        os.close(read_fd); os.close(write_fd)
