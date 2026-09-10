"""Real CLI peer for the local relay interoperability journey.

Only synthetic identities and the caller's disposable test directory are used.
Every command runs in a fresh Python process against the real local relay.
"""
import json
from pathlib import Path
import subprocess
import sys

from qntm import cli, generate_identity

phase, relay, directory = sys.argv[1:4]
profile = str(Path(directory) / 'python-profile')


def command(*args):
    result = subprocess.run([sys.executable, '-m', 'qntm.cli', '--config-dir', profile, *args],
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'CLI test command {args[0]} failed: {result.stderr}')
    response = json.loads(result.stdout)
    assert response['ok']
    return response['data']


if phase == 'prepare':
    cli._save_identity(profile, generate_identity())
    created = command('--dropbox-url', relay, 'group', 'create', 'CLI and TypeScript')
    cid = created['conversation_id']
    command('--dropbox-url', relay, 'send', cid, 'before TypeScript admission')
    command('contact', 'add', 'TypeScript peer', sys.argv[4])
    result = command('--dropbox-url', relay, 'group', 'add', cid, 'TypeScript peer')
    print(json.dumps({'conversation_id': cid, 'group_link': result['group_link']}))
elif phase == 'refresh':
    result = command('group', 'refresh', sys.argv[4], 'TypeScript peer',
                     *(['--challenge', sys.argv[5]] if len(sys.argv) > 5 else []))
    print(json.dumps({'group_link': result['group_link'], 'epoch': result['current_epoch']}))
elif phase == 'missed':
    result = command('send', sys.argv[4], 'message that will expire')
    print(json.dumps({'sequence': result['sequence']}))
elif phase == 'finish':
    cid = sys.argv[4]
    received = command('recv', cid)
    assert any(row.get('unsafe_body') == 'TypeScript contact reply' for row in received['messages'])
    removed = command('group', 'remove', cid, 'TypeScript peer')
    assert removed['current_epoch'] == 2
    future = command('send', cid, 'after TypeScript removal')
    print(json.dumps({'received_reply': True, 'epoch': 2, 'future_message_id': future['message_id']}))
else:
    raise ValueError('Unknown test phase')
