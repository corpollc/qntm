"""Recovery and retention boundaries for the operator's encrypted snapshots."""
import importlib.util
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

spec = importlib.util.spec_from_file_location(
    "charter_backup", Path(__file__).resolve().parents[2] / "scripts" / "backup_charter.py"
)
backup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backup)


class CharterBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def capture(self, payload=b"a consistent database including its private seed", retain=None):
        with patch.object(backup, "capture_snapshot", return_value=payload):
            return backup.backup(self.directory, "example.invalid", retain)

    def test_disk_roundtrip_is_authenticated_and_private(self):
        payload = b"private database bytes"
        snapshot = self.capture(payload)
        encoded = snapshot.read_bytes()
        key = (self.directory / "encryption.key").read_bytes()
        self.assertNotIn(payload, encoded)
        self.assertEqual(backup.decrypt_snapshot(encoded, key), payload)
        for path in (snapshot, self.directory / "encryption.key"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        damaged = encoded[:-1] + bytes([encoded[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            backup.decrypt_snapshot(damaged, key)
        with self.assertRaises(InvalidTag):
            backup.decrypt_snapshot(encoded, bytes(32))
        with self.assertRaises(ValueError):
            backup.decrypt_snapshot(encoded[:len(backup.HEADER) + 3], key)

    def test_missing_existing_key_never_creates_a_replacement(self):
        self.capture()
        key = self.directory / "encryption.key"
        key.unlink()
        with self.assertRaisesRegex(ValueError, "missing original"):
            self.capture()
        self.assertFalse(key.exists())

    def test_insecure_key_and_symlink_key_are_rejected(self):
        self.capture()
        key = self.directory / "encryption.key"
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            self.capture()
        key.chmod(0o600)
        actual = self.directory / "original.key"
        key.rename(actual)
        key.symlink_to(actual)
        with self.assertRaises(OSError):
            self.capture()

    def test_retention_only_removes_authenticated_owned_snapshots(self):
        old = [self.capture(bytes([index])) for index in range(4)]
        corrupt = self.directory / "registry-20000101T000000000000Z.aesgcm"
        backup.private_write(corrupt, b"keep corrupt data for investigation")
        foreign = self.directory / "foreign.aesgcm"
        backup.private_write(foreign, b"not our filename")
        link = self.directory / "registry-20000102T000000000000Z.aesgcm"
        link.symlink_to(foreign)
        newest = self.capture(b"new", retain=2)
        self.assertTrue(newest.exists())
        self.assertTrue(old[-1].exists())
        self.assertTrue(all(not path.exists() for path in old[:-1]))
        self.assertTrue(corrupt.exists())
        self.assertTrue(foreign.exists())
        self.assertTrue(link.is_symlink())

    def test_capture_failure_keeps_every_previous_snapshot(self):
        previous = [self.capture() for _ in range(4)]
        with patch.object(backup, "capture_snapshot", side_effect=subprocess.TimeoutExpired("ssh", 90)):
            with self.assertRaises(subprocess.TimeoutExpired):
                backup.backup(self.directory, "example.invalid", 2)
        self.assertTrue(all(path.exists() for path in previous))

    def test_disk_verification_failure_never_prunes(self):
        previous = [self.capture() for _ in range(4)]
        with patch.object(backup, "decrypt_snapshot", side_effect=InvalidTag):
            with self.assertRaises(InvalidTag):
                self.capture(retain=2)
        self.assertTrue(all(path.exists() for path in previous))

    def test_retention_keeps_new_capture_after_clock_moves_backwards(self):
        previous = [self.capture() for _ in range(3)]
        newest = previous[0]
        key = (self.directory / "encryption.key").read_bytes()
        backup.prune_snapshots(self.directory, key, 2, newest)
        self.assertTrue(newest.exists())
        self.assertTrue(previous[-1].exists())
        self.assertFalse(previous[1].exists())

    def test_failure_status_preserves_last_success_without_exception_details(self):
        snapshot = self.capture()
        backup.record_status(self.directory, success=True, snapshot=snapshot)
        before = json.loads((self.directory / "status.json").read_text())
        backup.record_status(self.directory, success=False, error="TimeoutExpired")
        after = json.loads((self.directory / "status.json").read_text())
        self.assertFalse(after["success"])
        self.assertEqual(after["last_success"], before["last_success"])
        self.assertEqual(after["snapshot"], snapshot.name)
        self.assertEqual(after["error_class"], "TimeoutExpired")
        self.assertEqual((self.directory / "status.json").stat().st_mode & 0o777, 0o600)

    def test_ssh_is_noninteractive_bounded_and_never_receives_encryption_key(self):
        with patch.object(backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=b"db")) as run:
            self.assertEqual(backup.capture_snapshot("example.invalid"), b"db")
        argv = run.call_args.args[0]
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("--max-filesize 67108864", argv[-1])
        self.assertEqual(run.call_args.kwargs["timeout"], 90)
        self.assertNotIn("encryption.key", " ".join(argv))
        for host in ("-oProxyCommand=bad", "host;bad", "host\ncommand"):
            with self.assertRaises(ValueError):
                backup.capture_snapshot(host)

    def test_cli_lock_prevents_overlapping_capture_and_key_creation(self):
        with (self.directory / ".backup.lock").open("wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run(
                [sys.executable, spec.origin, "--directory", str(self.directory)],
                capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Another charter backup operation", result.stdout)
        self.assertFalse((self.directory / "encryption.key").exists())
        self.assertFalse((self.directory / "status.json").exists())

    def test_cli_failure_redacts_remote_output_and_keeps_last_success(self):
        snapshot = self.capture()
        backup.record_status(self.directory, success=True, snapshot=snapshot)
        binary_directory = self.directory / "bin"
        binary_directory.mkdir()
        fake_ssh = binary_directory / "ssh"
        fake_ssh.write_text("#!/bin/sh\nprintf 'private remote payload' >&2\nexit 1\n")
        fake_ssh.chmod(0o700)
        result = subprocess.run(
            [sys.executable, spec.origin, "--directory", str(self.directory), "--retain-count", "2"],
            env={**os.environ, "PATH": str(binary_directory) + os.pathsep + os.environ.get("PATH", "")},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("private remote payload", result.stdout + result.stderr)
        status = json.loads((self.directory / "status.json").read_text())
        self.assertFalse(status["success"])
        self.assertEqual(status["snapshot"], snapshot.name)
        self.assertEqual(status["error_class"], "CalledProcessError")
        self.assertTrue(snapshot.exists())


if __name__ == "__main__":
    unittest.main()
