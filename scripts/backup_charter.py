#!/usr/bin/env python3
"""Pull a consistent charter snapshot over SSH and encrypt it locally.

Requires cryptography (included with qntm). The encryption key never leaves this
machine. Keep a separate protected copy of it for disaster recovery.
"""
import argparse
import datetime
import os
from pathlib import Path
import re
import subprocess

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HEADER = b"qntm-charter-backup-v1\n"


def private_write(path: Path, content: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="qntm-charter.exe.xyz")
    parser.add_argument("--directory", type=Path, default=Path.home() / ".qntm-backups" / "charter")
    parser.add_argument("--decrypt", type=Path, help="decrypt an existing snapshot instead of contacting the server")
    parser.add_argument("--output", type=Path, help="new private file for a decrypted database")
    args = parser.parse_args()
    directory = args.directory.expanduser()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    key_path = directory / "encryption.key"
    if not key_path.exists():
        if args.decrypt:
            parser.error("missing original encryption.key")
        private_write(key_path, AESGCM.generate_key(bit_length=256))
    key = key_path.read_bytes()
    if args.decrypt:
        if not args.output:
            parser.error("--decrypt requires --output")
        encoded = args.decrypt.read_bytes()
        if not encoded.startswith(HEADER):
            parser.error("unsupported backup format")
        body = encoded[len(HEADER):]
        private_write(args.output, AESGCM(key).decrypt(body[:12], body[12:], HEADER))
        print(f"Decrypted snapshot: {args.output}")
        return
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*", args.host):
        parser.error("invalid SSH hostname")
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", args.host,
         "curl --fail --silent --show-error --max-time 60 http://127.0.0.1:9085/backup"],
        check=True, capture_output=True, timeout=90,
    )
    if not result.stdout:
        raise RuntimeError("empty snapshot")
    nonce = os.urandom(12)
    encrypted = HEADER + nonce + AESGCM(key).encrypt(nonce, result.stdout, HEADER)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = directory / f"registry-{stamp}.aesgcm"
    private_write(target, encrypted)
    print(f"Encrypted snapshot: {target} ({len(result.stdout)} database bytes)")


if __name__ == "__main__":
    main()
