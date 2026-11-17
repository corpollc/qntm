#!/usr/bin/env python3
"""Exercise the installed Swift executable against a local relay; no production traffic."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--relay', required=True)
    parser.add_argument('--binary', default='.build/debug/qntm-swift')
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix='qntm-swift-cli-') as temporary:
        root = Path(temporary)

        def cli(profile, *arguments):
            process = subprocess.run([binary, '--config-dir', str(root / profile), '--relay-url', args.relay, *arguments], text=True, capture_output=True, check=True)
            result = json.loads(process.stdout)
            assert result['ok'], result
            return result['data']

        alice = cli('alice', 'identity', 'generate')
        bob = cli('bob', 'identity', 'generate')
        assert alice['key_id'] != bob['key_id']
        direct = cli('alice', 'convo', 'create', '--name', 'hello')
        cid = direct['conversation_id']
        cli('bob', 'convo', 'join', direct['invite_token'])
        cli('alice', 'send', cid, 'Hello Swift 👋')
        assert cli('bob', 'recv', cid)['messages'][0]['unsafe_body'] == 'Hello Swift 👋'
        assert cli('bob', 'recv', cid)['messages'] == []
        cli('bob', 'send', cid, 'Persistent reply')
        assert any(m['unsafe_body'] == 'Persistent reply' for m in cli('alice', 'recv', cid)['messages'])
        source, output = root / 'attachment.bin', root / 'download.bin'
        source.write_bytes(bytes(range(256)) * 300)
        message = cli('alice', 'file', 'send', cid, str(source))
        cli('bob', 'recv', cid)
        cli('bob', 'file', 'get', cid, message['message_id'], str(output))
        assert output.read_bytes() == source.read_bytes()
        group = cli('alice', 'convo', 'create', '--group', '--name', 'group', '--members', bob['public_key'])
        gid = group['conversation_id']
        cli('bob', 'convo', 'join', group['invite_token'])
        cli('bob', 'recv', gid)
        charlie = cli('charlie', 'identity', 'generate')
        welcomes = cli('alice', 'group', 'add', gid, charlie['public_key'])['invitations']
        cli('charlie', 'convo', 'join', welcomes[charlie['public_key']])
        cli('bob', 'recv', gid)
        cli('charlie', 'recv', gid)
        cli('charlie', 'send', gid, 'New member after restart')
        assert any(m['unsafe_body'] == 'New member after restart' for m in cli('bob', 'recv', gid)['messages'])
        cli('alice', 'group', 'remove', gid, bob['key_id'])
        cli('bob', 'recv', gid)
        cli('charlie', 'recv', gid)
        cli('charlie', 'send', gid, 'Remaining member')
        assert any(m['unsafe_body'] == 'Remaining member' for m in cli('alice', 'recv', gid)['messages'])
        exported = root / 'identity.cbor'
        cli('alice', 'identity', 'export', str(exported))
        imported = cli('imported', 'identity', 'import', str(exported))
        assert imported == alice
        assert len(cli('alice', 'guidance', 'list')['providers']) == 3
        print('PASS Swift CLI: separate-process profiles, messaging, attachments, group admission/rekey/removal, identity import/export')


if __name__ == '__main__':
    main()
