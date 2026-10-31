import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { generateIdentity, createInvite, inviteToToken, decryptMessage, openSecret, base64UrlDecode,
  createGuidanceIntake, openGuidanceIntake, guidanceIntake, CORPO_GUIDANCE_PROVIDERS } from '../src/index.js';
import type { GuidanceProvider } from '../src/index.js';
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
function fixture() {
  const recipient = generateIdentity(), invite = createInvite(recipient, 'direct');
  const provider: GuidanceProvider = { ...CORPO_GUIDANCE_PROVIDERS[0], recipient_public_key: hex(recipient.publicKey),
    recipient_key_id: hex(recipient.keyID), conversation_id: hex(invite.conv_id), intake_invite: inviteToToken(invite) };
  return { recipient, provider };
}
describe('sealed guidance intake', () => {
  it('separates requesters and binds the private reply conversation to the sender', () => {
    const { recipient, provider } = fixture();
    const sender = generateIdentity(), stranger = generateIdentity();
    const request = createGuidanceIntake(sender, provider, 'Private question', 'Private context');
    const publicView = decryptMessage(request.envelope, guidanceIntake(provider));
    const body = new TextDecoder().decode(publicView.inner.body);
    expect(body).not.toContain('Private');
    expect(() => openSecret(stranger.privateKey, sender.publicKey, base64UrlDecode(body))).toThrow();
    const opened = openGuidanceIntake(recipient, provider, request.envelope);
    expect(opened.question).toBe('Private question');
    expect(opened.context).toBe('Private context');
    expect(opened.replyInvite.inviter_ik_pk).toEqual(sender.publicKey);
    expect(hex(opened.replyInvite.conv_id)).toBe(request.requestId);
    expect(request.replyConversation.participants).toEqual([sender.keyID, recipient.keyID]);
  });
  it('rejects substituted destinations and modified envelopes', () => {
    const { recipient, provider } = fixture();
    const sender = generateIdentity();
    expect(() => createGuidanceIntake(sender, { ...provider, recipient_key_id: 'f'.repeat(32) }, 'Question')).toThrow();
    expect(() => createGuidanceIntake(sender, { ...provider, conversation_id: 'f'.repeat(32) }, 'Question')).toThrow();
    const request = createGuidanceIntake(sender, provider, 'Question');
    request.envelope.ciphertext[0] ^= 1;
    expect(() => openGuidanceIntake(recipient, provider, request.envelope)).toThrow();
  });
  it('ships exactly the same distinct public destinations as Python', () => {
    expect(CORPO_GUIDANCE_PROVIDERS).toEqual(JSON.parse(readFileSync(new URL('../../python-dist/src/qntm/guidance_providers.json', import.meta.url), 'utf8')));
    expect(new Set(CORPO_GUIDANCE_PROVIDERS.map(p => p.recipient_key_id)).size).toBe(3);
    for (const p of CORPO_GUIDANCE_PROVIDERS) guidanceIntake(p);
  });
});
