import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from relay_monitor import Monitor, load_probe, snapshot_metrics


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


if __name__ == '__main__':
    unittest.main()
