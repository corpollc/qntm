import { parseGroupLink } from '@corpollc/qntm';
import { splitGroupArguments } from './groups.js';
import { Store, bytesToHex } from './store.js';

export interface GroupCommandResult { text: string; conversationId?: string }

/** Only called by explicit composer commands, never incoming messages. */
export async function runGroupCommand(store: Store, command: string, args: string, activeId: string | null): Promise<GroupCommandResult> {
  const tokens = splitGroupArguments(args);
  if (command === 'join' || (command === 'group' && tokens[0] === 'open')) {
    const link = command === 'join' ? args.trim() : tokens.slice(1).join(' ');
    const parsed = parseGroupLink(link);
    const existing = store.findConversation(bytesToHex(parsed.conversationId));
    if (existing && !existing.managedGroup) throw new Error('This group already exists in the legacy terminal profile. Automatic migration is not available; keep that profile intact.');
    const data = await store.groups.run(['group', 'join', '--', link]);
    const id = String(data.conversation_id);
    return { conversationId: id, text: `Opened group ${id}\n${store.groups.status(id)}` };
  }
  if (command === 'contact') {
    const action = tokens.shift() || 'list';
    if (action === 'list' && !tokens.length) {
      const data = await store.groups.run(['contact', 'list']);
      return { text: data.contacts.length ? data.contacts.map((contact: { name: string; public_key: string }) => `${contact.name}: ${contact.public_key}`).join('\n') : 'No pinned contacts. Use /contact add <name> <full-public-key> after verifying its owner.' };
    }
    if (action === 'add' && tokens.length === 2) {
      const data = await store.groups.run(['contact', 'add', '--', ...tokens]);
      store.setContact(String(data.key_id), String(data.name));
      return { text: `Pinned contact ${data.name}\nPublic key: ${data.public_key}\nKey ID: ${data.key_id}` };
    }
    if (action === 'remove' && tokens.length === 1) {
      await store.groups.run(['contact', 'remove', '--', ...tokens]);
      return { text: `Removed local contact pin ${tokens[0]}. Group membership is unchanged.` };
    }
    throw new Error('Usage: /contact list | /contact add <name> <public-key> | /contact remove <name>. Quote names containing spaces.');
  }
  const action = tokens.shift() || 'status';
  if (action === 'create') {
    if (!tokens.length) throw new Error('Usage: /group create <name>');
    const data = await store.groups.run(['group', 'create', '--contact', '--', tokens.join(' ')]);
    const id = String(data.conversation_id);
    // A legacy client may leave creation incomplete: never enable native sends.
    return { conversationId: id, text: `Created contact group ${id}. Use /group add <contact> to add a pinned address.\n${store.groups.status(id)}` };
  }
  if (!activeId || !store.findConversation(activeId)?.managedGroup) throw new Error('Select a contact group first, or use /group create <name>. Legacy and gateway conversations keep their existing commands.');
  if (action === 'status' && !tokens.length) return { text: store.groups.status(activeId) };
  let cliArgs: string[];
  if (action === 'retry' && tokens.length === 1 && tokens[0] === '--release-unproven') {
    // Explicit local release of a stale, unverified saved removal. Grammar
    // matches the Python CLI: `group retry <conversation> --release-unproven`.
    cliArgs = ['group', 'retry', activeId, '--release-unproven'];
  } else if (['link', 'retry', 'rekey'].includes(action) && !tokens.length) cliArgs = ['group', action, activeId];
  else if (['add', 'refresh'].includes(action) && (tokens.length === 1 || (tokens.length === 3 && tokens[1] === '--challenge'))) {
    const challenge = tokens.length === 3 ? ['--challenge', tokens[2]] : [];
    cliArgs = ['group', action, ...challenge, '--', activeId, tokens[0]];
  } else if (action === 'remove' && tokens.length === 1) cliArgs = ['group', action, '--', activeId, tokens[0]];
  else throw new Error('Use /group add|remove|refresh <contact>, /group link|retry|rekey|status, /group retry --release-unproven, or /help group. Quote contact names containing spaces.');
  const data = await store.groups.run(cliArgs);
  if (data.released === true) {
    return { text: [`Local retry released (${String(data.reason).replace(/_/g, ' ')}). The saved removal was never verified; membership is unchanged and its ciphertext stays in the private profile.`,
      'Use /group remove <contact> if you still want them out.', store.groups.status(activeId)].join('\n') };
  }
  return { text: [`Group ${action} complete${tokens[0] ? ` for ${tokens[0]}` : ''}.`, data.group_link ? `Public group link (no keys, no expiry):\n${data.group_link}` : '', store.groups.status(activeId)].filter(Boolean).join('\n') };
}
