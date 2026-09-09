#!/usr/bin/env python3
"""Generate help from the actual parser without invoking commands or loading state."""
import argparse
import os
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'python-dist/src'))
from qntm.cli import _main


class Captured(Exception):
    pass


def generate():
    parsers = []

    def capture(parser, *args, **kwargs):
        parsers.append(parser)
        raise Captured()

    with patch.dict(os.environ, {'COLUMNS': '88'}), patch.object(argparse.ArgumentParser, 'parse_args', capture):
        try:
            _main()
        except Captured:
            pass
        output = ['# CLI reference\n\nGenerated from the Python CLI parser. Regenerate with `python scripts/generate_cli_reference.py` in an environment with the qntm dependencies installed. CI checks for drift.\n\nGlobal options precede the command. One-shot commands return JSON; `recv --watch` streams JSONL. See [receive hooks](receive-hooks.md), [guidance](guidance.md), and [gateway invitations](gateway-invitations.md) for complete workflows.\n']

        def visit(parser):
            output.append(f'\n## `{parser.prog}`\n\n```text\n{parser.format_help()}```\n')
            for action in parser._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for child in action.choices.values():
                        visit(child)
        visit(parsers[0])
        return ''.join(output)


if __name__ == '__main__':
    path = ROOT / 'docs/cli-reference.md'
    text = generate()
    if '--check' in sys.argv:
        if not path.exists() or path.read_text() != text:
            raise SystemExit('CLI reference is stale; run scripts/generate_cli_reference.py')
    else:
        path.write_text(text)
