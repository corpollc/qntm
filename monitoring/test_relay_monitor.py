import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from relay_monitor import (
    MAX_REPLAY_FRAMES_PER_PASS,
    MAX_REPLAY_PASSES,
    Monitor,
    load_probe,
    probe as run_probe,
    snapshot_metrics,
)


def snapshot():
    return {'measured_at': time.time() * 1000, 'measurement_started_at': time.time() * 1000,
            'traffic': [dict(traffic=t, messages=7, bytes=700, messages_24h=4, messages_7d=7,
                             active_conversations_24h=2, active_conversations_7d=3)
                        for t in ('application', 'probe')]}


class MonitorTests(unittest.TestCase):
    def test_only_valid_fixed_aggregate_labels_are_exported(self):
        values = snapshot_metrics(snapshot())
        self.assertEqual(values['qntm_relay_messages{traffic="application",window="24h"}'], 4)
        bad = snapshot()
        bad['traffic'][0]['traffic'] = 'unexpected"label'
        with self.assertRaises(ValueError):
            snapshot_metrics(bad)
        for invalid in (float('nan'), float('inf'), -1, '3', True):
            bad = snapshot()
            bad['traffic'][0]['messages'] = invalid
            with self.assertRaises(ValueError):
                snapshot_metrics(bad)

    def test_stale_and_incomplete_snapshots_fail(self):
        bad = snapshot()
        bad['measured_at'] -= 180_000
        with self.assertRaisesRegex(ValueError, 'stale'):
            snapshot_metrics(bad)
        bad = snapshot()
        bad['traffic'].pop()
        with self.assertRaisesRegex(ValueError, 'missing'):
            snapshot_metrics(bad)

    def test_private_probe_identity_and_cursor_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'probe.cbor'
            first = load_probe(path)
            self.assertEqual(load_probe(path), first)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(first['sender']['keyID'], first['receiver']['keyID'])

    @patch('relay_monitor.probe')
    @patch('relay_monitor.httpx.Client')
    def test_failures_are_visible_and_restart_does_not_post_extra_probes(self, client, probe):
        http = MagicMock()
        client.return_value.__enter__.return_value = http
        http.get.return_value.json.side_effect = snapshot
        probe.return_value = 0.25
        config = {'relay_url': 'https://relay.example', 'metrics_read_token': 'test-only-token-not-a-real-secret'}
        with tempfile.TemporaryDirectory() as directory:
            monitor = Monitor(config, directory)
            monitor.collect()
            self.assertEqual(monitor.metrics['qntm_relay_probe_success'], 1)
            self.assertEqual(probe.call_count, 1)
            restarted = Monitor(config, directory)
            http.get.side_effect = TimeoutError('secret-url-must-not-be-logged')
            with self.assertLogs(level='WARNING') as logs:
                restarted.collect()
            self.assertNotIn('secret-url', ''.join(logs.output))
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(restarted.metrics['qntm_relay_stats_scrape_success'], 0)
            self.assertEqual(restarted.metrics['qntm_relay_probe_success'], 1)
            restarted.metrics['qntm_relay_probe_last_attempt_timestamp_seconds'] = 0
            probe.side_effect = ValueError('bad replay')
            with self.assertLogs(level='WARNING'):
                restarted.collect()
            self.assertEqual(restarted.metrics['qntm_relay_probe_success'], 0)
            stored = json.loads((Path(directory) / 'metrics.json').read_text())
            self.assertEqual(stored['qntm_relay_stats_scrape_success'], 0)

    @patch('relay_monitor.open_subscription')
    def test_probe_paginates_past_4096_frame_backlog_and_recovers(self, open_sub):
        with tempfile.TemporaryDirectory() as directory:
            state = load_probe(Path(directory) / 'probe.cbor')
            posted_envelope_b64 = {}
            observed_cursors = []

            class FakeSocket:
                def __init__(self, frames_fn):
                    self._frames = None
                    self._frames_fn = frames_fn

                def __enter__(self):
                    self._frames = iter(self._frames_fn())
                    return self

                def __exit__(self, *args):
                    return False

                def send(self, _data):
                    pass

                def recv(self, timeout=None):
                    item = next(self._frames)
                    return json.dumps(item() if callable(item) else item)

            def subscribe_side_effect(_base, _state, cursor):
                observed_cursors.append(cursor)
                if cursor == 0:
                    def pass1():
                        yield {'type': 'auth_challenge', 'challenge_hex': '11' * 32}
                        yield {'type': 'auth_ok'}
                        for seq in range(1, MAX_REPLAY_FRAMES_PER_PASS - 1):
                            yield {'type': 'message', 'seq': seq, 'envelope_b64': base64.b64encode(b'spam').decode()}
                    return FakeSocket(pass1)
                if cursor == MAX_REPLAY_FRAMES_PER_PASS - 2:
                    def pass2():
                        yield {'type': 'auth_challenge', 'challenge_hex': '22' * 32}
                        yield {'type': 'auth_ok'}
                        for seq in range(MAX_REPLAY_FRAMES_PER_PASS - 1, 4501):
                            yield {'type': 'message', 'seq': seq, 'envelope_b64': base64.b64encode(b'spam').decode()}
                        yield {'type': 'ready', 'head_seq': 4500}
                        yield lambda: {'type': 'message', 'seq': 4501, 'envelope_b64': posted_envelope_b64['val']}
                    return FakeSocket(pass2)
                if cursor == 4500:
                    def replay_pass():
                        yield {'type': 'auth_challenge', 'challenge_hex': '33' * 32}
                        yield {'type': 'auth_ok'}
                        yield {'type': 'message', 'seq': 4501, 'envelope_b64': posted_envelope_b64['val']}
                        yield {'type': 'ready', 'head_seq': 4501}
                    return FakeSocket(replay_pass)
                raise AssertionError(f'unexpected cursor {cursor}')

            open_sub.side_effect = subscribe_side_effect
            http = MagicMock()

            def post_side_effect(_url, json):
                posted_envelope_b64['val'] = json['envelope_b64']
                resp = MagicMock()
                resp.status_code = 201
                resp.json.return_value = {'seq': 4501}
                return resp

            http.post.side_effect = post_side_effect
            duration = run_probe('https://relay.example', state, http)
            self.assertGreaterEqual(duration, 0)
            self.assertEqual(state['cursor'], 4501)
            self.assertEqual(observed_cursors, [0, MAX_REPLAY_FRAMES_PER_PASS - 2, 4500])

    @patch('relay_monitor.open_subscription')
    @patch('relay_monitor.httpx.Client')
    def test_extreme_backlog_persists_advanced_cursor_for_self_healing(self, client_cls, open_sub):
        http = MagicMock()
        client_cls.return_value.__enter__.return_value = http
        http.get.return_value.json.side_effect = snapshot

        class EndlessBacklogSocket:
            def __init__(self, start_seq):
                self._seq = start_seq

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def recv(self, timeout=None):
                self._seq += 1
                return json.dumps({'type': 'message', 'seq': self._seq, 'envelope_b64': 'YWJj'})

        open_sub.side_effect = lambda _base, _state, cursor: EndlessBacklogSocket(cursor)
        config = {'relay_url': 'https://relay.example', 'metrics_read_token': 'test-only-token-not-a-real-secret'}
        with tempfile.TemporaryDirectory() as directory:
            monitor = Monitor(config, directory)
            with self.assertLogs(level='WARNING'):
                monitor.collect()
            self.assertEqual(monitor.metrics['qntm_relay_probe_success'], 0)
            expected_cursor = MAX_REPLAY_PASSES * MAX_REPLAY_FRAMES_PER_PASS
            self.assertEqual(monitor.state['cursor'], expected_cursor)
            persisted = load_probe(Path(directory) / 'probe.cbor')
            self.assertEqual(persisted['cursor'], expected_cursor)

    @patch('relay_monitor.open_subscription')
    def test_non_advancing_frame_flood_aborts_after_single_pass(self, open_sub):
        class PongFloodSocket:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def recv(self, timeout=None):
                return json.dumps({'type': 'pong'})

        open_sub.return_value = PongFloodSocket()
        with tempfile.TemporaryDirectory() as directory:
            state = load_probe(Path(directory) / 'probe.cbor')
            with self.assertRaisesRegex(ValueError, 'probe replay exceeded bound'):
                run_probe('https://relay.example', state, MagicMock())
            self.assertEqual(open_sub.call_count, 1)


if __name__ == '__main__':
    unittest.main()
