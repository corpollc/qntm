#!/usr/bin/env python3
"""Private Prometheus exporter and bounded, encrypted external relay probe.

Uses the published qntm package. Each five-minute probe posts one synthetic
envelope, verifies live delivery, then reconnects and verifies persisted replay.
"""
import argparse
import base64
import json
import logging
import math
import os
from pathlib import Path
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlencode, urlsplit, urlunsplit

import certifi
import httpx
from websockets.sync.client import connect
from qntm.cbor import marshal_canonical, unmarshal
from qntm.crypto import QSP1Suite
from qntm.identity import generate_identity
from qntm.invite import create_invite, create_conversation, derive_conversation_keys
from qntm.message import create_message, decrypt_message, serialize_envelope, deserialize_envelope

TLS = ssl.create_default_context(cafile=certifi.where())


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with open(temporary, 'wb', opener=lambda name, flags: os.open(name, flags, 0o600)) as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def load_probe(path):
    path = Path(path)
    if path.exists():
        return unmarshal(path.read_bytes())
    sender, receiver = generate_identity(), generate_identity()
    invite = create_invite(sender, 'direct')
    state = {'sender': sender, 'receiver': receiver,
             'conversation': create_conversation(invite, derive_conversation_keys(invite)), 'cursor': 0}
    atomic_write(path, marshal_canonical(state))
    return state


def subscription_url(base, state, cursor):
    url = urlsplit(base)
    return urlunsplit(('wss' if url.scheme == 'https' else 'ws', url.netloc, '/v1/subscribe',
                      urlencode({'conv_id': state['conversation']['id'].hex(), 'from_seq': cursor,
                                 'pub_key': state['receiver']['publicKey'].hex()}), ''))


def open_subscription(base, state, cursor):
    url = subscription_url(base, state, cursor)
    options = {'open_timeout': 8, 'close_timeout': 1, 'max_size': 128 * 1024, 'max_queue': 16}
    if url.startswith('wss:'):
        options['ssl'] = TLS
    return connect(url, **options)


def next_frame(socket, state, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('relay probe deadline exceeded')
    frame = json.loads(socket.recv(timeout=remaining))
    if frame.get('type') == 'auth_challenge':
        challenge = bytes.fromhex(frame['challenge_hex'])
        if len(challenge) != 32:
            raise ValueError('invalid relay challenge')
        signature = QSP1Suite().sign(state['receiver']['privateKey'], challenge)
        socket.send(json.dumps({'type': 'auth_response', 'signature_hex': signature.hex()}))
    elif frame.get('type') == 'auth_failed':
        raise ValueError('relay authentication failed')
    return frame


def verify_probe_frame(frame, envelope, state, payload):
    received = deserialize_envelope(base64.b64decode(frame['envelope_b64'], validate=True))
    if received['msg_id'] != envelope['msg_id']:
        return False
    message = decrypt_message(received, state['conversation'])
    if (message['verified'] is not True or message['inner']['body'] != payload
            or message['inner']['sender_kid'] != state['sender']['keyID']):
        raise ValueError('probe message did not verify')
    return True


def probe(base, state, client):
    started = time.monotonic()
    # A ready frame establishes the live subscription before posting.
    with open_subscription(base, state, state['cursor']) as socket:
        deadline = time.monotonic() + 10
        for _ in range(4096):
            frame = next_frame(socket, state, deadline)
            if frame.get('type') == 'ready':
                state['cursor'] = int(frame['head_seq'])
                break
        else:
            raise ValueError('probe replay exceeded bound')
        payload = ('qntm synthetic availability probe ' + secrets.token_hex(16)).encode()
        envelope = create_message(state['sender'], state['conversation'], 'text', payload, ttl_seconds=600)
        response = client.post(base + '/v1/send', json={
            'conv_id': state['conversation']['id'].hex(), 'msg_id': envelope['msg_id'].hex(),
            'envelope_b64': base64.b64encode(serialize_envelope(envelope)).decode(),
        })
        if response.status_code != 201:
            raise ValueError('relay did not accept probe')
        sequence = response.json()['seq']
        if type(sequence) is not int or sequence <= state['cursor']:
            raise ValueError('invalid probe sequence')
        deadline = time.monotonic() + 10
        for _ in range(128):
            frame = next_frame(socket, state, deadline)
            if frame.get('type') == 'message' and frame.get('seq') == sequence:
                if not verify_probe_frame(frame, envelope, state, payload):
                    raise ValueError('unexpected probe envelope')
                break
        else:
            raise ValueError('live probe delivery missing')
    # Reconnect from the preceding cursor: this must replay the stored ciphertext.
    replayed = False
    with open_subscription(base, state, sequence - 1) as socket:
        deadline = time.monotonic() + 10
        for _ in range(128):
            frame = next_frame(socket, state, deadline)
            if frame.get('type') == 'message' and frame.get('seq') == sequence:
                replayed = verify_probe_frame(frame, envelope, state, payload)
            if frame.get('type') == 'ready':
                if not replayed or frame['head_seq'] < sequence:
                    raise ValueError('persisted replay missing')
                state['cursor'] = sequence
                return time.monotonic() - started
    raise ValueError('replay probe exceeded bound')


def snapshot_metrics(snapshot):
    def number(value):
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('invalid aggregate metric')
        return value
    measured = number(snapshot['measured_at']) / 1000
    if abs(time.time() - measured) > 120:
        raise ValueError('stale relay snapshot')
    metrics = {'qntm_relay_measurement_started_timestamp_seconds': number(snapshot['measurement_started_at']) / 1000}
    seen = set()
    for row in snapshot['traffic']:
        traffic = row['traffic']
        if traffic not in ('application', 'probe') or traffic in seen:
            raise ValueError('invalid traffic category')
        seen.add(traffic)
        metrics[f'qntm_relay_messages_total{{traffic="{traffic}"}}'] = number(row['messages'])
        metrics[f'qntm_relay_envelope_bytes_total{{traffic="{traffic}"}}'] = number(row['bytes'])
        for window in ('24h', '7d'):
            for name in ('messages', 'active_conversations'):
                metrics[f'qntm_relay_{name}{{traffic="{traffic}",window="{window}"}}'] = number(row[f'{name}_{window}'])
    if seen != {'application', 'probe'}:
        raise ValueError('missing traffic category')
    return metrics


def render_metrics(metrics):
    return ''.join(f'{name} {value}\n' for name, value in sorted(metrics.items()))


class Monitor:
    def __init__(self, config, state_dir):
        self.base = config['relay_url'].rstrip('/')
        url = urlsplit(self.base)
        if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
            raise ValueError('relay_url must be an HTTP(S) origin')
        self.token = config['metrics_read_token']
        if not isinstance(self.token, str) or len(self.token) < 20:
            raise ValueError('invalid metrics read token')
        self.interval = max(60, int(config.get('probe_interval_seconds', 300)))
        self.state_dir = Path(state_dir)
        self.probe_path = self.state_dir / 'probe.cbor'
        self.state = load_probe(self.probe_path)
        self.metrics_path = self.state_dir / 'metrics.json'
        self.metrics = json.loads(self.metrics_path.read_text()) if self.metrics_path.exists() else {}
        self.output = render_metrics(self.metrics)

    def collect(self):
        with httpx.Client(timeout=8, verify=TLS, trust_env=False) as client:
            now = time.time()
            try:
                response = client.get(self.base + '/v1/metrics', headers={'Authorization': 'Bearer ' + self.token})
                response.raise_for_status()
                self.metrics.update(snapshot_metrics(response.json()))
                self.metrics['qntm_relay_stats_scrape_success'] = 1
                self.metrics['qntm_relay_stats_last_success_timestamp_seconds'] = time.time()
            except Exception as error:
                self.metrics['qntm_relay_stats_scrape_success'] = 0
                logging.warning('Relay aggregate scrape failed: %s', type(error).__name__)
            if now - self.metrics.get('qntm_relay_probe_last_attempt_timestamp_seconds', 0) >= self.interval:
                self.metrics['qntm_relay_probe_last_attempt_timestamp_seconds'] = now
                try:
                    self.metrics['qntm_relay_probe_duration_seconds'] = probe(self.base, self.state, client)
                    self.metrics['qntm_relay_probe_success'] = 1
                    self.metrics['qntm_relay_probe_last_success_timestamp_seconds'] = time.time()
                except Exception as error:
                    self.metrics['qntm_relay_probe_success'] = 0
                    logging.warning('Relay encrypted probe failed: %s', type(error).__name__)
                atomic_write(self.probe_path, marshal_canonical(self.state))
        self.metrics['qntm_relay_monitor_last_run_timestamp_seconds'] = time.time()
        atomic_write(self.metrics_path, json.dumps(self.metrics).encode())
        self.output = render_metrics(self.metrics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/qntm-relay-monitor/config.json')
    parser.add_argument('--state-dir', default='/var/lib/qntm-relay-monitor')
    parser.add_argument('--port', type=int, default=9191)
    parser.add_argument('--init', action='store_true', help='Initialize private probe state and print only its conversation ID')
    parser.add_argument('--once', action='store_true', help='Collect once and print aggregate Prometheus metrics')
    args = parser.parse_args()
    if args.init:
        print(load_probe(Path(args.state_dir) / 'probe.cbor')['conversation']['id'].hex())
        return
    monitor = Monitor(json.loads(Path(args.config).read_text()), args.state_dir)
    if args.once:
        monitor.collect()
        print(monitor.output, end='')
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/metrics':
                self.send_error(404)
                return
            body = monitor.output.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    def run():
        while True:
            try:
                monitor.collect()
            except Exception as error:
                # A failing state disk must not leave an apparently current healthy snapshot.
                monitor.output = 'qntm_relay_stats_scrape_success 0\nqntm_relay_probe_success 0\n'
                logging.error('Relay monitor cycle failed: %s', type(error).__name__)
            time.sleep(60)

    threading.Thread(target=run, daemon=True).start()
    HTTPServer(('127.0.0.1', args.port), Handler).serve_forever()


if __name__ == '__main__':
    main()
