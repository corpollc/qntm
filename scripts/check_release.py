#!/usr/bin/env python3
"""Fail on source/lockfile version drift before testing or publishing."""
import argparse
import ast
import json
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag')
    args = parser.parse_args()
    version = json.loads((ROOT / 'client/package.json').read_text())['version']
    errors = []
    if (ROOT / 'gate/recipes/starter.json').read_bytes() != (ROOT / 'python-dist/src/qntm/recipes.json').read_bytes():
        errors.append('Bundled Python recipes are stale: copy gate/recipes/starter.json to python-dist/src/qntm/recipes.json')

    def check(label, actual):
        if actual != version:
            errors.append(f'{label}: {actual!r}, expected {version!r}')

    if args.tag:
        check('tag', args.tag.removeprefix('v'))
    for package in ['client', 'ui/aim-chat', 'ui/tui', 'channel']:
        for name in ['package.json', 'package-lock.json']:
            data = json.loads((ROOT / package / name).read_text())
            check(f'{package}/{name}', data['version'])
            if 'packages' in data:
                check(f'{package} lock root', data['packages']['']['version'])
    for path in ROOT.glob('**/package-lock.json'):
        if any(part in ['node_modules', 'tmp', '.venv'] for part in path.parts):
            continue
        for key, data in json.loads(path.read_text()).get('packages', {}).items():
            if key.endswith('/client') and data.get('name') == '@corpollc/qntm':
                check(f'{path.relative_to(ROOT)} client link', data['version'])
    check('Python project', tomllib.loads((ROOT / 'python-dist/pyproject.toml').read_text())['project']['version'])
    for package in tomllib.loads((ROOT / 'python-dist/uv.lock').read_text())['package']:
        if package['name'] == 'qntm':
            check('Python lock', package['version'])
    for node in ast.parse((ROOT / 'python-dist/src/qntm/__init__.py').read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '__version__' for target in node.targets):
            check('Python runtime', ast.literal_eval(node.value))
    if not (ROOT / f'docs/releases/v{version}.md').is_file():
        errors.append(f'Missing curated release notes for v{version}')
    if f'## v{version}' not in (ROOT / 'docs/CHANGELOG.md').read_text():
        errors.append(f'Missing changelog entry for v{version}')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Release metadata is consistent: v{version}')


if __name__ == '__main__':
    main()
