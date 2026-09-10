import { it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { inviteFromURL, createConversation, deriveConversationKeys, deserializeEnvelope, decryptMessage } from '../src/index.js';
it('authenticates the exact legacy bearer hello consumed by the Python receiver', () => {
  const f=JSON.parse(readFileSync(new URL('./legacy-bearer-typescript.json',import.meta.url),'utf8'));
  const invite=inviteFromURL(f.invite_token), conversation=createConversation(invite,deriveConversationKeys(invite));
  const message=decryptMessage(deserializeEnvelope(new Uint8Array(Buffer.from(f.hello,'base64'))),conversation,{allowExpired:true});
  expect(message.verified).toBe(true);
  expect(Buffer.from(message.inner.sender_ik_pk).toString('hex')).toBe(f.peer_public_key);
  expect(new TextDecoder().decode(message.inner.body)).toBe('Legacy bearer hello');
});
