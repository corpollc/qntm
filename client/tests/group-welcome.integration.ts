import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  QSP1Suite, GroupState, generateIdentity, createInvite, createConversation,
  deriveConversationKeys, createGroupGenesisBody, parseGroupGenesisBody, applyRekey,
  createMessage, decryptMessage, marshalCanonical, deserializeEnvelope,
  prepareGroupAddition, openGroupWelcome, createGroupLink, parseGroupLink,
} from '../src/index.js';
import type { Identity } from '../src/index.js';

const suite = new QSP1Suite();
const hex = (value: Uint8Array) => Buffer.from(value).toString('hex');
const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'hex'));
const identity = (value: Record<string, string>): Identity => ({
  privateKey: bytes(value.privateKey), publicKey: bytes(value.publicKey), keyID: bytes(value.keyID),
});
function python(request: Record<string, unknown>): any {
  return JSON.parse(execFileSync(process.env.QNTM_TEST_PYTHON ?? 'python3', [
    fileURLToPath(new URL('../../python-dist/tests/group_welcome_peer.py', import.meta.url)),
  ], {
    input: JSON.stringify(request), encoding: 'utf8', timeout: 15000,
    env: { ...process.env, PYTHONPATH: fileURLToPath(new URL('../../python-dist/src', import.meta.url)) },
  }));
}

describe('fresh Python / TypeScript contact addition interoperability', () => {
  for (const epoch of [0, 7]) {
    it(`Python opens a TypeScript welcome after epoch ${epoch} and replies without old keys`, () => {
      const owner = generateIdentity(), late = generateIdentity();
      const invite = createInvite(owner, 'group');
      const source = createConversation(invite, deriveConversationKeys(invite));
      const state = new GroupState();
      state.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Interop colleagues', 'Ω private roster', owner, [])));
      source.participants = state.listMembers();
      if (epoch) applyRekey(source, suite.generateGroupKey(), epoch);
      const before = createMessage(owner, source, 'text', new TextEncoder().encode('before addition'));
      const added = prepareGroupAddition(owner, source, state, [late.publicKey]);
      const after = createMessage(owner, added.conversation, 'text', new TextEncoder().encode('after addition'));
      const result = python({ action: 'open', identity: Object.fromEntries(Object.entries(late).map(([k, v]) => [k, hex(v)])),
        link: createGroupLink({ conversationId: source.id, inviterPublicKey: owner.publicKey, relayUrl: 'https://inbox.qntm.corpo.llc' }),
        welcome: hex(marshalCanonical(added.welcomes[0])), conversation_id: hex(source.id), inviter_public_key: hex(owner.publicKey),
        before: hex(marshalCanonical(before)), after: hex(marshalCanonical(after)) });
      expect(result).toMatchObject({ old_decrypts: false, epoch: epoch + 1, after: 'after addition' });
      const reply = decryptMessage(deserializeEnvelope(bytes(result.reply)), added.conversation);
      expect(new TextDecoder().decode(reply.inner.body)).toBe('Python recipient reply');
      expect(reply.inner.sender_ik_pk).toEqual(late.publicKey);
    });

    it(`TypeScript opens a Python welcome after epoch ${epoch} without earlier history`, () => {
      const result = python({ action: 'prepare', epoch });
      const late = identity(result.late);
      const locator = parseGroupLink(result.link);
      expect(locator.conversationId).toEqual(bytes(result.conversation_id));
      expect(locator.inviterPublicKey).toEqual(bytes(result.owner.publicKey));
      const joined = openGroupWelcome(late, bytes(result.welcome), locator);
      expect(joined.conversation.currentEpoch).toBe(epoch + 1);
      expect(hex(joined.conversation.keys.root)).toBe(result.root);
      expect(hex(joined.additionId)).toBe(result.addition_id);
      expect(hex(joined.rekeyId)).toBe(result.rekey_id);
      expect(() => decryptMessage(deserializeEnvelope(bytes(result.before)), joined.conversation)).toThrow();
      const after = decryptMessage(deserializeEnvelope(bytes(result.after)), joined.conversation);
      expect(new TextDecoder().decode(after.inner.body)).toBe('after addition');
    });
  }
});
