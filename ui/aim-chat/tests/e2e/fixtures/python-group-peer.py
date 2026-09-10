"""Fresh-process Python CLI peer for the local browser contact-group journey."""
import json
from pathlib import Path
import subprocess
import sys

from qntm import cli, generate_identity

profile, phase, *arguments = sys.argv[1:]
if phase == 'identity':
    identity = generate_identity()
    cli._save_identity(profile, identity)
    print(json.dumps({'public_key': identity['publicKey'].hex(), 'key_id': identity['keyID'].hex()}))
else:
    result = subprocess.run([sys.executable, '-m', 'qntm.cli', '--config-dir', profile, *arguments],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'CLI {arguments[0]} failed: {result.stderr}')
    parsed = json.loads(result.stdout)
    assert parsed['ok']
    print(json.dumps(parsed['data']))
