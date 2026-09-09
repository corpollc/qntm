import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('gate', Path(__file__).resolve().parents[1] / 'wait_for_release_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseGateTests(unittest.TestCase):
    def run_gate(self, runs, jobs):
        def get(path):
            return {'workflow_runs': runs} if '/workflows/' in path else {'jobs': jobs}
        with patch.dict(os.environ, {'GITHUB_SHA': 'abc', 'GITHUB_REF_NAME': 'v0.6.0'}), patch.object(gate, 'get', get), patch.object(gate.time, 'monotonic', side_effect=[0, 1, 99999]), patch.object(gate.time, 'sleep'):
            gate.main()

    def run_record(self, **changes):
        return dict(id=1, head_sha='abc', head_branch='v0.6.0', run_number=1, run_attempt=1, status='in_progress', html_url='https://example.invalid/run', **changes)

    def test_requires_exact_tag_and_commit(self):
        wrong_tag = self.run_record(); wrong_tag['head_branch'] = 'v0.5.1'
        wrong_sha = self.run_record(); wrong_sha['head_sha'] = 'def'
        for record in [wrong_tag, wrong_sha]:
            with self.assertRaisesRegex(SystemExit, 'Timed out'):
                self.run_gate([record], [{'name': 'Release gate', 'status': 'completed', 'conclusion': 'success'}])

    def test_successful_full_gate_allows_publish_before_other_publish_jobs_finish(self):
        self.run_gate([self.run_record()], [{'name': 'Release gate', 'status': 'completed', 'conclusion': 'success'}])

    def test_failed_cancelled_or_skipped_gate_never_authorizes_publish(self):
        for conclusion in ['failure', 'cancelled', 'skipped', 'timed_out']:
            with self.assertRaisesRegex(SystemExit, 'did not pass'):
                self.run_gate([self.run_record()], [{'name': 'Release gate', 'status': 'completed', 'conclusion': conclusion}])

    def test_completed_workflow_without_a_gate_fails_closed(self):
        record = self.run_record(); record['status'] = 'completed'
        with self.assertRaisesRegex(SystemExit, 'did not pass'):
            self.run_gate([record], [])

    def test_newest_attempt_is_checked(self):
        old = self.run_record(); new = self.run_record(); new['run_attempt'] = 2
        paths = []
        def get(path):
            paths.append(path)
            return {'workflow_runs': [old, new]} if '/workflows/' in path else {'jobs': [{'name': 'Release gate', 'status': 'completed', 'conclusion': 'failure'}]}
        with patch.dict(os.environ, {'GITHUB_SHA': 'abc', 'GITHUB_REF_NAME': 'v0.6.0'}), patch.object(gate, 'get', get):
            with self.assertRaises(SystemExit): gate.main()
        self.assertIn('/attempts/2/jobs?', paths[-1])


if __name__ == '__main__':
    unittest.main()
