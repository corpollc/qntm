import { afterEach, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { ChannelInbox, saveJson } from '../inbox.js';
import { createConversation, createInvite, createMessage, createReceiveEvent, decryptMessage, deriveConversationKeys, generateIdentity, defaultTTL } from '@corpollc/qntm';

const directories: string[] = [];
afterEach(() => { for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });
function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'qntm-channel-')); directories.push(directory);
  const path = join(directory, 'inbox.json');
  const identity = generateIdentity();
  const invite = createInvite(identity, 'direct');
  const conversation = createConversation(invite, deriveConversationKeys(invite));
  const event = (seq: number) => createReceiveEvent(decryptMessage(createMessage(identity, conversation, 'text', new TextEncoder().encode(`event ${seq}`), undefined, defaultTTL()), conversation), seq);
  return { path, directory, event };
}

it('retains a failed notification across restart and ignores a shared CLI cursor advance', async () => {
  const { path, directory, event } = fixture();
  const first = event(4);
  const inbox = new ChannelInbox(path, 3);
  inbox.capture(4, first);
  await expect(inbox.drain(async () => { throw new Error('transport disconnected'); })).rejects.toThrow('disconnected');
  saveJson(join(directory, 'sequence_cursors.json'), { [first.conversation_id]: 50 });
  const restarted = new ChannelInbox(path, 50);
  expect(restarted.cursor).toBe(4);
  const delivered: string[] = [];
  await restarted.drain(async message => { delivered.push(message.event_id); });
  expect(delivered).toEqual([first.event_id]);
  expect(new ChannelInbox(path).pending).toEqual([]);
  expect(statSync(path).mode & 0o777).toBe(0o600);
});

it('preserves arrivals during handoff and serializes simultaneous drains', async () => {
  const { path, event } = fixture();
  const inbox = new ChannelInbox(path);
  const first = event(1), second = event(2);
  inbox.capture(1, first);
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const delivered: string[] = [];
  const drain = inbox.drain(async message => { delivered.push(message.event_id); await waiting; });
  expect(inbox.drain(async () => { throw new Error('must not run'); })).toBe(drain);
  inbox.capture(2, second);
  release(); await drain;
  expect(delivered).toEqual([first.event_id, second.event_id]);
  expect(JSON.parse(readFileSync(path, 'utf8'))).toMatchObject({ cursor: 2, pending: [] });
});

it('advances past self or invalid frames without acknowledging a pending peer event', () => {
  const { path, event } = fixture();
  const inbox = new ChannelInbox(path);
  const first = event(1);
  inbox.capture(1, first); inbox.capture(2); inbox.capture(1, first);
  expect(new ChannelInbox(path).pending).toEqual([first]);
  expect(inbox.cursor).toBe(2);
});
