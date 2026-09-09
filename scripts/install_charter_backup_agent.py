#!/usr/bin/env python3
"""Install a private, best-effort macOS charter backup job for the current user.

Prepare a dedicated Python environment containing cryptography and pass its
absolute interpreter path with --python. This copies the backup script so the
job does not depend on a Git checkout. It never copies the encryption key.
"""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile

LABEL = "llc.corpo.qntm.charter-backup"


def configuration(python: Path, script: Path, directory: Path) -> dict:
    return {
        "Label": LABEL,
        "ProgramArguments": [str(python), str(script), "--directory", str(directory), "--retain-count", "28"],
        "RunAtLoad": True,
        "StartInterval": 6 * 60 * 60,
        "ProcessType": "Background",
        "Umask": 0o077,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }


def install_file(path: Path, content: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".qntm-install-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True, help="stable dedicated interpreter with cryptography installed")
    parser.add_argument("--directory", type=Path, default=Path.home() / ".qntm-backups" / "charter")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this installer requires a logged-in macOS user session")
    python = args.python.expanduser().absolute()
    directory = args.directory.expanduser().absolute()
    subprocess.run([str(python), "-c", "from cryptography.hazmat.primitives.ciphers.aead import AESGCM"], check=True)
    runtime = Path.home() / ".local" / "share" / "qntm-charter-backup"
    if runtime.is_symlink() or directory.is_symlink():
        parser.error("runtime and backup directories must not be symlinks")
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime.chmod(0o700)
    script = runtime / "backup_charter.py"
    install_file(script, Path(__file__).with_name("backup_charter.py").read_bytes())
    agents = Path.home() / "Library" / "LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    target = agents / f"{LABEL}.plist"
    install_file(target, plistlib.dumps(configuration(python, script, directory)))
    domain = f"gui/{os.getuid()}"
    # Replace only this job; an absent prior instance is normal on first install.
    subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["launchctl", "bootstrap", domain, str(target)], check=True)
    print(f"Installed {LABEL}: runs at login/load and every six hours while available.")
    print(f"Private status: {directory / 'status.json'}")
    print("This Mac must be logged in and online. Check last_success; a loaded job is not proof of a backup.")


if __name__ == "__main__":
    main()
