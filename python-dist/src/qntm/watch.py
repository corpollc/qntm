"""Resident receive with a durable inbox and independent hook acknowledgements.

History is persisted by CLI/MCP receive before their relay cursor advances.
Consumers read that history, so relay reconnection and hook retry are separate.
Only one watch per conversation/profile owns the consumer state at a time.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import random
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from websockets.exceptions import WebSocketException
from websockets.sync.client import connect

from . import cli
from .storage import load_json, private_lock, save_json


class WatchError(Exception):
    """Operator-facing error; must not contain hook configuration or plaintext."""


class _Stopped(Exception):
    pass


MAX_GROUP_REPLAY_MESSAGES = 8192
MAX_GROUP_REPLAY_BYTES = 16 << 20


def status(state, **details):
    print(json.dumps({"kind": "recv.status", "data": {"state": state, **details}},
                     separators=(",", ":")), file=sys.stderr, flush=True)


def events(config_dir, conversation_id):
    """Build the same versioned event for stdout and every hook from saved data."""
    return [event for _, event in delivery_events(config_dir, conversation_id)]


def _group_delivery_state(config_dir, conversation_id):
    record = cli._find_conversation(cli._load_conversations(config_dir), conversation_id)
    if not record:
        return False, None
    group = record.get('group_session')
    allowed = not group or not (group.get('recovery') or group.get('removed') or group.get('needsRekey') or record.get('group_operation'))
    return allowed, record


def _eligible_group_entry(entry, group):
    binding = entry.get('receive_binding')
    if not binding or not binding.get('valid'):
        return False
    seen = group['seen'].get(entry['msg_id'])
    return seen is None or seen['digest'] == binding['digest']


def delivery_events(config_dir, conversation_id):
    """Private delivery order can advance when an older relay item decrypts late."""
    allowed, record = _group_delivery_state(config_dir, conversation_id)
    if not allowed:
        return []
    result = []
    group = record.get('group_session')
    history = record.get('group_history', []) if group else cli._load_history(config_dir, conversation_id)
    for entry in history:
        event = entry.get("receive_event")
        if entry.get("direction") != "incoming" or event is None:
            continue
        if group and not _eligible_group_entry(entry, group):
            continue  # Never re-dispatch queued plaintext from a replaced branch.
        result.append((entry.get('receive_order', event['sequence']), {
            "ok": True, "kind": "recv.message", "rules": cli.AGENT_RULES,
            "system_warning": cli.SYSTEM_WARNING,
            "data": event,
        }))
    return sorted(result, key=lambda pair: pair[0])


@dataclass(frozen=True)
class Target:
    kind: str
    destination: str | tuple[str, ...] = ""
    include_self: bool = False

    @property
    def id(self):
        if self.kind == "stdout":
            return "stdout"
        config = json.dumps([self.kind, self.destination, self.include_self], separators=(",", ":"))
        return self.kind + ":" + hashlib.sha256(config.encode()).hexdigest()


def targets(args):
    timeout = getattr(args, "hook_timeout", 10)
    if not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise WatchError("--hook-timeout must be greater than zero and at most 300 seconds")
    result = [Target("stdout", include_self=True)]
    include_self = getattr(args, "include_self", False)
    for url in getattr(args, "webhook", []):
        try:
            parsed = urlsplit(url)
            valid = (parsed.scheme in ("http", "https") and parsed.hostname
                     and parsed.port != 0 and parsed.username is None and parsed.password is None
                     and not parsed.fragment and not any(char.isspace() or ord(char) < 32 for char in url))
        except ValueError:
            valid = False
        if not valid:
            raise WatchError("--webhook requires an HTTP(S) URL without userinfo, whitespace, or a fragment")
        result.append(Target("webhook", url, include_self))
    for command in getattr(args, "on_receive", []):
        try:
            argv = tuple(shlex.split(command))
        except ValueError:
            raise WatchError("--on-receive must contain a command with balanced quotes") from None
        if not argv or any("\0" in arg for arg in argv):
            raise WatchError("--on-receive requires an executable and optional arguments")
        result.append(Target("exec", argv, include_self))
    return list({target.id: target for target in result}.values())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Decrypted content is sent only to the configured destination.
        return None


def _stdout(body, stop):
    if stop is None or os.name == "nt":
        sys.stdout.write(body.decode())
        sys.stdout.flush()
        return
    # A harness may stop draining its pipe. Keep shutdown interruptible even
    # under backpressure; don't acknowledge a partially written JSON line.
    fd = sys.stdout.fileno()
    blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    try:
        pending = memoryview(body)
        while pending:
            if stop.is_set():
                raise _Stopped()
            try:
                pending = pending[os.write(fd, pending):]
            except BlockingIOError:
                stop.wait(0.1)
    finally:
        os.set_blocking(fd, blocking)


def deliver(target, event, timeout, *, stop=None):
    body = (json.dumps(event, separators=(",", ":")) + "\n").encode()
    if target.kind == "stdout":
        _stdout(body, stop)
    elif target.kind == "webhook":
        request = urllib.request.Request(target.destination, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "User-Agent": f"qntm-python/{cli.__version__}",
            "Idempotency-Key": event["data"]["event_id"],
        })
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=cli._ssl_context))
        with opener.open(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise WatchError("webhook did not accept the event")
    else:
        # Message content never becomes argv, shell syntax, or a destination.
        with subprocess.Popen(target.destination, stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=os.name != "nt") as process:
            try:
                process.communicate(input=body, timeout=timeout)
            except BaseException:
                if os.name != "nt":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
                process.wait()
                raise
            if process.returncode:
                raise WatchError("on-receive adapter exited unsuccessfully")


class ConsumerState:
    def __init__(self, path, relay, configured, baseline):
        self.path = path
        self.lock = threading.Lock()
        self.data = load_json(path, {"version": 1, "relay": relay, "consumers": {}})
        if (not isinstance(self.data, dict) or self.data.get("version") != 1 or self.data.get("relay") != relay
                or not isinstance(self.data.get("consumers"), dict)
                or any(type(value) is not int or value < 0 for value in self.data["consumers"].values())):
            raise WatchError("Watch state is incompatible; use a separate profile for a different relay")
        for target in configured:
            self.data["consumers"].setdefault(target.id, baseline)
        save_json(path, self.data)

    def cursor(self, target):
        with self.lock:
            return self.data["consumers"][target.id]

    def acknowledge(self, target, sequence):
        with self.lock:
            consumers = {**self.data["consumers"], target.id: sequence}
            updated = {**self.data, "consumers": consumers}
            save_json(self.path, updated)
            self.data = updated


class Consumer(threading.Thread):
    def __init__(self, target, state, config_dir, conversation_id, own_kid, timeout, stop, replay_ready=None):
        super().__init__(name="qntm-" + target.id[:20], daemon=True)
        self.target, self.state = target, state
        self.config_dir, self.conversation_id, self.own_kid = config_dir, conversation_id, own_kid
        self.timeout, self.stop = timeout, stop
        self.replay_ready = replay_ready
        self.wake = threading.Event()
        self.error = None

    def run(self):
        try:
            self.consume()
        except _Stopped:
            pass
        except BrokenPipeError:
            self.stop.set()
        except Exception as error:
            self.error = error
            self.stop.set()

    def consume(self):
        delay = 1
        while not self.stop.is_set():
            self.wake.clear()
            if self.replay_ready is not None and not self.replay_ready.is_set():
                self.wake.wait(1)
                continue
            pending = [(order, event) for order, event in delivery_events(self.config_dir, self.conversation_id)
                       if order > self.state.cursor(self.target)]
            for order, event in pending:
                if self.stop.is_set():
                    return
                allowed, record = _group_delivery_state(self.config_dir, self.conversation_id)
                if (self.replay_ready is not None and not self.replay_ready.is_set()) or not allowed:
                    break
                group = record.get('group_session')
                if group:
                    current = next((entry for entry in record.get('group_history', [])
                                    if entry.get('receive_order') == order
                                    and entry.get('receive_event') == event['data']), None)
                    if current is None or not _eligible_group_entry(current, group):
                        continue
                try:
                    if self.target.include_self or event["data"]["message"]["sender_kid"] != self.own_kid:
                        if self.target.kind == "stdout":
                            deliver(self.target, event, self.timeout, stop=self.stop)
                        else:
                            deliver(self.target, event, self.timeout)
                except Exception as error:
                    if self.target.kind == "stdout":
                        raise
                    status("hook_retry", consumer=self.target.id, event_id=event["data"]["event_id"],
                           cause=type(error).__name__, retry_in=delay)
                    self.stop.wait(delay)
                    delay = min(delay * 2, 30)
                    break
                self.state.acknowledge(self.target, order)
                delay = 1
            else:
                # Also notice receives committed by a one-shot CLI/MCP process.
                self.wake.wait(1)


@contextmanager
def subscription(url, options):
    try:
        websocket = connect(url, **options)
    except OSError as error:
        raise ConnectionError("subscription connection failed") from error
    try:
        yield websocket
    finally:
        websocket.close()


def receive(config_dir, relay, conversation_id, identity, stop, consumers, replay_ready=None):
    delay = 1
    while not stop.is_set():
        if replay_ready is not None:
            replay_ready.clear()
        cursor = cli._load_cursors(config_dir).get(conversation_id, 0)
        url = cli._subscribe_url(relay, conversation_id, cursor)
        options = {"open_timeout": 10, "close_timeout": 2, "max_size": 2 << 20,
                   "additional_headers": {"User-Agent": f"qntm-python/{cli.__version__}"}}
        if url.startswith("wss://"):
            options["ssl"] = cli._ssl_context
        try:
            with subscription(url, options) as websocket:
                connected_at = time.monotonic()
                last_ping = connected_at
                backlog, backlog_bytes, replaying = [], 0, True
                while not stop.is_set():
                    try:
                        raw = websocket.recv(timeout=1)
                    except TimeoutError:
                        # Works with websockets 13+, including releases whose
                        # synchronous client has no automatic keepalive.
                        if time.monotonic() - last_ping >= 20:
                            try:
                                if not websocket.ping().wait(timeout=5):
                                    raise ConnectionError("subscription heartbeat timed out")
                            except OSError as error:
                                raise ConnectionError("subscription heartbeat failed") from error
                            last_ping = time.monotonic()
                        continue
                    except OSError as error:
                        raise ConnectionError("subscription receive failed") from error
                    try:
                        frame = json.loads(raw)
                        kind = frame.get("type")
                        if kind == "pong":
                            continue
                        if kind not in ("message", "ready"):
                            raise ValueError("unsupported subscription frame")
                        sequence = frame.get("seq" if kind == "message" else "head_seq")
                        if type(sequence) is not int or sequence < (1 if kind == "message" else 0):
                            raise ValueError("invalid subscription sequence")
                    except (ValueError, AttributeError) as error:
                        raise WebSocketException("invalid subscription frame") from error
                    conversations = cli._load_conversations(config_dir)
                    record = cli._resolve_conversation(conversations, conversation_id)
                    if record is None:
                        raise WatchError("Conversation was removed while watching")
                    group = record.get('group_session')
                    if group and replaying and kind == 'message':
                        backlog_bytes += len(raw.encode('utf-8')) if isinstance(raw, str) else len(raw)
                        if len(backlog) >= MAX_GROUP_REPLAY_MESSAGES or backlog_bytes > MAX_GROUP_REPLAY_BYTES:
                            raise WatchError('Group subscription replay exceeds its local bound; receive progress was not advanced')
                        backlog.append(frame)
                        continue
                    if group and kind == 'ready' and (not replaying or sequence < max([cursor, *[row['seq'] for row in backlog]])):
                        raise WebSocketException('invalid group replay head')
                    # Local persistence errors are fatal: never retry them as
                    # network failures or move past data we couldn't save.
                    cli._process_received_messages(config_dir, identity, conversations, record,
                                                   [frame] if kind == "message" else backlog, sequence)
                    if kind == 'ready':
                        backlog, backlog_bytes, replaying = [], 0, False
                        if replay_ready is not None:
                            replay_ready.set()
                    for consumer in consumers:
                        consumer.wake.set()
                    if kind == "ready":
                        recovery = cli._group_recovery_status(config_dir, conversation_id)
                        status("recovery_required" if recovery else "ready", conversation_id=conversation_id,
                               head_sequence=sequence, **recovery)
                    if time.monotonic() - connected_at >= 30:
                        delay = 1
        except (WebSocketException, ConnectionError, TimeoutError, cli.ssl.SSLError, cli.socket.gaierror) as error:
            if replay_ready is not None:
                replay_ready.clear()
            if stop.is_set():
                break
            pause = min(delay * random.uniform(1, 1.25), 30)
            status("reconnecting", conversation_id=conversation_id, cause=type(error).__name__, retry_in=pause)
            stop.wait(pause)
            delay = min(delay * 2, 30)
        finally:
            if replay_ready is not None:
                replay_ready.clear()


def watch(args):
    configured = targets(args)
    config_dir, relay = cli._get_config_dir(args), cli._get_dropbox_url(args)
    identity = cli._load_identity(config_dir)
    if not identity:
        raise WatchError("No identity found; run 'qntm identity generate' first")
    record = cli._resolve_conversation(cli._load_conversations(config_dir), args.conversation)
    if not record:
        raise WatchError("Conversation not found")
    conversation_id = record["id"]
    relay = cli._conversation_relay(args, record)
    path = Path(config_dir) / "watch" / (conversation_id + ".json")
    stop = threading.Event()
    previous_handlers = {}
    consumers = []
    try:
        with private_lock(path.with_suffix(".lock"), blocking=False):
            # A newly configured target starts after saved history even when
            # current group recovery or an unfinished operation blocks delivery.
            existing = cli._load_history(config_dir, conversation_id)
            baseline = max((entry.get('receive_order', entry.get('sequence', 0))
                            for entry in existing if entry.get('receive_event')), default=0)
            state = ConsumerState(path, relay.rstrip("/"), configured, baseline)
            # A running legacy group can be upgraded by another local command.
            # Every consumer therefore waits for the current connection's head.
            replay_ready = threading.Event()
            consumers = [Consumer(target, state, config_dir, conversation_id, identity["keyID"].hex(),
                                  getattr(args, "hook_timeout", 10), stop, replay_ready) for target in configured]
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    previous_handlers[sig] = signal.signal(sig, lambda *_: stop.set())
            try:
                for consumer in consumers:
                    consumer.start()
                status("connecting", conversation_id=conversation_id)
                receive(config_dir, relay, conversation_id, identity, stop, consumers, replay_ready)
            finally:
                stop.set()
                for consumer in consumers:
                    consumer.wake.set()
                for consumer in consumers:
                    consumer.join()
            if any(consumer.error for consumer in consumers):
                raise WatchError("Could not persist or deliver receive events; pending events remain in local history")
    except BlockingIOError:
        raise WatchError("Another recv --watch is already running for this conversation and profile") from None
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
