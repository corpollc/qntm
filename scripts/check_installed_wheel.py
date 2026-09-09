#!/usr/bin/env python3
"""Install a built wheel in isolation and exercise its bundled runtime resources."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import venv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    expected = json.loads((root / 'gate/recipes/starter.json').read_text())
    env = {key: value for key, value in os.environ.items() if key not in ('PYTHONPATH', 'QNTM_RECIPE_CATALOG_PATH')}
    with tempfile.TemporaryDirectory(prefix='qntm-wheel-') as directory:
        target = Path(directory)
        venv.EnvBuilder(with_pip=True).create(target / 'venv')
        python = target / 'venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        subprocess.run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check', str(wheel)], cwd=target, env=env, check=True)
        check = '''
import json, sys
from pathlib import Path
from importlib.resources import files
import qntm
from qntm.cli import _load_starter_catalog, _build_gate_request_message
from qntm.identity import generate_identity
from qntm.wire import kid_to_wire
assert Path(qntm.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
catalog = _load_starter_catalog()
identity = generate_identity()
message, request_id = _build_gate_request_message(identity=identity, recipe=catalog['httpbin.echo'],
    conv_id='ab'*16, args={'data':'installed wheel'}, eligible_signer_kids=[kid_to_wire(identity['keyID'])], required_approvals=1)
assert message['request_id'] == request_id
assert message['payload'] == {'data': 'installed wheel'}
assert message['target_url'] == 'https://httpbin.org/post'
print(json.dumps({'version': qntm.__version__, 'catalog': json.loads(files('qntm').joinpath('recipes.json').read_text())}))
'''
        completed = subprocess.run([str(python), '-I', '-c', check], cwd=target, env=env, check=True, text=True, capture_output=True)
        actual = json.loads(completed.stdout)
        if actual['catalog'] != expected:
            raise SystemExit('Installed recipe catalog differs from canonical catalog')
        subprocess.run([str(python), '-I', '-m', 'qntm.cli', '--help'], cwd=target, env=env, check=True, capture_output=True)
        print(f"Installed wheel v{actual['version']}: CLI, default catalog and signed request construction passed outside the repository")


if __name__ == '__main__':
    main()
