#!/usr/bin/env python3
"""Pull a consistent charter snapshot over SSH and encrypt it locally.

Requires cryptography (included with qntm). The encryption key never leaves this
machine. Keep a separate protected copy of it for disaster recovery.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER = b"qntm-charter-backup-v1\n"
SNAPSHOT_NAME = re.compile(r"registry-\d{8}T\d{12}Z\.aesgcm\Z")
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def private_write(path: Path, content: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def private_read(path: Path, limit: int) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("backup files must be private regular files owned by this user")
        content = source.read(limit + 1)
        if len(content) > limit:
            raise ValueError("backup file exceeds size limit")
        return content


def atomic_private_write(path: Path, content: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".backup-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def decrypt_snapshot(encoded: bytes, key: bytes) -> bytes:
    if not encoded.startswith(HEADER) or len(encoded) < len(HEADER) + 28:
        raise ValueError("unsupported or truncated backup format")
    body = encoded[len(HEADER):]
    return AESGCM(key).decrypt(body[:12], body[12:], HEADER)


def load_key(directory: Path, *, create: bool) -> bytes:
    key_path = directory / "encryption.key"
    if not key_path.exists() and not key_path.is_symlink():
        # A missing recovery key must not silently strand an existing archive.
        if not create or any(directory.glob("registry-*.aesgcm")):
            raise ValueError("missing original encryption.key")
        private_write(key_path, AESGCM.generate_key(bit_length=256))
    key = private_read(key_path, 32)
    if len(key) != 32:
        raise ValueError("invalid encryption.key length")
    return key


def capture_snapshot(host: str) -> bytes:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*", host):
        raise ValueError("invalid SSH hostname")
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host,
         "curl --fail --silent --show-error --max-time 60 --max-filesize 67108864 http://127.0.0.1:9085/backup"],
        check=True, capture_output=True, timeout=90,
    )
    if not result.stdout or len(result.stdout) > MAX_SNAPSHOT_BYTES:
        raise ValueError("empty or oversized snapshot")
    return result.stdout


def prune_snapshots(directory: Path, key: bytes, retain_count: int, newest: Path) -> None:
    if retain_count < 2:
        raise ValueError("retain at least two snapshots")
    candidates = []
    for path in directory.iterdir():
        if not SNAPSHOT_NAME.fullmatch(path.name):
            continue
        try:
            decrypt_snapshot(private_read(path, MAX_SNAPSHOT_BYTES + 128), key)
        except Exception:
            # Preserve foreign, corrupt, insecure and symlink entries for review.
            continue
        candidates.append(path)
    # Always preserve this successful capture, even after a backwards clock jump.
    previous = sorted((path for path in candidates if path != newest), reverse=True)
    for path in previous[retain_count - 1:]:
        path.unlink()


def backup(directory: Path, host: str, retain_count: int | None = None) -> Path:
    key = load_key(directory, create=True)
    snapshot = capture_snapshot(host)
    nonce = os.urandom(12)
    encrypted = HEADER + nonce + AESGCM(key).encrypt(nonce, snapshot, HEADER)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = directory / f"registry-{stamp}.aesgcm"
    private_write(target, encrypted)
    # Authenticate the actual on-disk bytes before retention can remove anything.
    if decrypt_snapshot(private_read(target, MAX_SNAPSHOT_BYTES + 128), key) != snapshot:
        raise ValueError("saved snapshot verification failed")
    if retain_count is not None:
        prune_snapshots(directory, key, retain_count, target)
    return target


def record_status(directory: Path, *, success: bool, snapshot: Path | None = None, error: str | None = None) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    previous = {}
    try:
        previous = json.loads(private_read(directory / "status.json", 4096))
        if not isinstance(previous, dict):
            previous = {}
    except (OSError, ValueError):
        pass
    status = {"version": 1, "last_attempt": now, "success": success}
    for field in ("last_success", "snapshot"):
        if isinstance(previous.get(field), str):
            status[field] = previous[field]
    if success:
        status.update(last_success=now, snapshot=snapshot.name)
    else:
        status["error_class"] = error
    atomic_private_write(directory / "status.json", (json.dumps(status, indent=2) + "\n").encode())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="qntm-charter.exe.xyz")
    parser.add_argument("--directory", type=Path, default=Path.home() / ".qntm-backups" / "charter")
    parser.add_argument("--decrypt", type=Path, help="decrypt an existing snapshot instead of contacting the server")
    parser.add_argument("--output", type=Path, help="new private file for a decrypted database")
    parser.add_argument("--retain-count", type=int, help="after a verified capture, retain this many authenticated snapshots (minimum 2; default keeps all)")
    args = parser.parse_args()
    directory = args.directory.expanduser()
    if directory.is_symlink():
        parser.error("backup directory must not be a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    if args.retain_count is not None and args.retain_count < 2:
        parser.error("--retain-count must be at least 2")
    with os.fdopen(os.open(directory / ".backup.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "wb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another charter backup operation is running.")
            return
        try:
            if args.decrypt:
                if not args.output:
                    parser.error("--decrypt requires --output")
                key = load_key(directory, create=False)
                encoded = private_read(args.decrypt, MAX_SNAPSHOT_BYTES + 128)
                private_write(args.output, decrypt_snapshot(encoded, key))
                print(f"Decrypted snapshot: {args.output}")
            else:
                target = backup(directory, args.host, args.retain_count)
                record_status(directory, success=True, snapshot=target)
                print(f"Encrypted and authenticated snapshot: {target}")
        except Exception as error:
            if not args.decrypt:
                record_status(directory, success=False, error=type(error).__name__)
            print(f"Charter backup failed: {type(error).__name__}", file=sys.stderr)
            raise SystemExit(1) from None


if __name__ == "__main__":
    main()
