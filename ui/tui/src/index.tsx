#!/usr/bin/env node
/**
 * qntm TUI — Terminal chat client for the qntm messaging protocol.
 *
 * Usage:
 *   npx tsx src/index.tsx [options]
 *
 * Options:
 *   --config-dir <path>    Config directory (default: ~/.qntm-human)
 *   --dropbox-url <url>    Dropbox relay URL (default: https://inbox.qntm.corpo.llc)
 *   --help                 Show this help message
 */

import React from 'react';
import { render } from 'ink';
import App from './App.js';

// ── Arg parsing ──────────────────────────────────────────────────────────

function parseArgs(argv: string[]): {
  configDir: string;
  dropboxUrl: string;
  help: boolean;
} {
  const result = {
    configDir: '',
    dropboxUrl: '',
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      result.help = true;
    } else if (arg === '--config-dir' && i + 1 < argv.length) {
      result.configDir = argv[++i];
    } else if (arg === '--dropbox-url' && i + 1 < argv.length) {
      result.dropboxUrl = argv[++i];
    }
  }

  return result;
}

const HELP_TEXT = `
qntm TUI — Terminal chat client

Usage:
  npx tsx src/index.tsx [options]

Options:
  --config-dir <path>    Config directory (default: ~/.qntm-human)
  --dropbox-url <url>    Dropbox relay URL (default: https://inbox.qntm.corpo.llc)
  --help, -h             Show this help message

Slash commands (in chat):
  /help                  Show available commands
  /invite [name]         Create an invite token for a new conversation
  /join <token>          Accept an invite and join a conversation
  /name <name>           Set conversation name
  /nick <name>           Set your display name
  /alias <kid> <name>    Set a contact alias
  /identity              Show your identity info
  /conversations         List all conversations
  /approve <reqid>       Approve a gate request
  /quit                  Exit the client

Navigation:
  Tab                    Toggle conversation sidebar
  1-9                    Switch to conversation by number
  j / k                  Scroll messages up/down
  Ctrl-C                 Quit
`.trim();

// ── Main ──────────────────────────────────────────────────────────────────

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  console.log(HELP_TEXT);
  process.exit(0);
}

import os from 'node:os';
import path from 'node:path';

const configDir = args.configDir || path.join(os.homedir(), '.qntm-human');
const dropboxUrl = args.dropboxUrl || 'https://inbox.qntm.corpo.llc';

const { waitUntilExit } = render(
  <App configDir={configDir} dropboxUrl={dropboxUrl} />,
  { exitOnCtrlC: true },
);

waitUntilExit().catch(() => {
  process.exit(1);
});
