import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createConversationFixture, createIdentityDirFixture } from './helpers.js';
import { describe, expect, it } from 'vitest';
import { generateIdentity, createGroupLink, base64UrlEncode, serializeIdentity, GroupState, createGroupGenesisBody, parseGroupGenesisBody, createGroupSession } from '@corpollc/qntm';
import type { OpenClawPluginToolContext } from 'openclaw/plugin-sdk/core';
import { resolveQntmAccount } from '../src/accounts.js';
import { QntmConfigSchema } from '../src/config-schema.js';
import { QntmGroupActions, createQntmGroupTool, resolveGroupToolScope } from '../src/group-tool.js';
import type { QntmRootConfig } from '../src/types.js';
function fixture() {
  const identity = generateIdentity(), inviter = generateIdentity(), id = generateIdentity().keyID;
  const groupLink = createGroupLink({ conversationId: id, inviterPublicKey: inviter.publicKey, relayUrl: 'https://relay.test' });
  const cfg: QntmRootConfig = { channels: { qntm: { identity: base64UrlEncode(serializeIdentity(identity)), relayUrl: 'https://relay.test',
    contacts: { Colleague: base64UrlEncode(inviter.publicKey) }, conversations: { team: { groupLink, groupActions: ['add', 'open'] } } } } };
  const ctx = { messageChannel: 'qntm', agentAccountId: 'default', agentId: 'main', sessionId: 'test-session', nativeChannelId: Buffer.from(id).toString('hex') } as OpenClawPluginToolContext;
  return { cfg, ctx };
}
describe('OpenClaw contact group configuration and native scope', () => {
  it('requires the full inviter pin and exact locally configured relay before fetching a welcome', () => {
    const { cfg } = fixture(); expect(resolveQntmAccount({ cfg }).configured).toBe(true);
    cfg.channels!.qntm!.contacts!.Colleague = base64UrlEncode(generateIdentity().publicKey);
    expect(resolveQntmAccount({ cfg }).configured).toBe(false);
    expect(resolveQntmAccount({ cfg }).configErrors.join(' ')).toContain('contact pin');
    const fresh = fixture().cfg; fresh.channels!.qntm!.relayUrl = 'https://another-relay.test';
    expect(resolveQntmAccount({ cfg: fresh }).configErrors.join(' ')).toContain('relay differs');
  });
  it('imports a complete trusted CLI seed but rejects gateway state, a changed relay and pending operations', () => {
    const conv = createConversationFixture('group'), roster = new GroupState();
    roster.applyGenesis(parseGroupGenesisBody(createGroupGenesisBody('Team', '', conv.inviter, [])));
    conv.conversation.participants = roster.listMembers();
    const profile = createIdentityDirFixture({ identity: conv.inviter, conversations: [conv] });
    try {
      const filename = join(profile.dir, 'conversations.json'), records = JSON.parse(readFileSync(filename, 'utf8'));
      records[0].group_session = createGroupSession(conv.inviter, conv.conversation, roster); records[0].group_cursor = 0;
      const cfg: QntmRootConfig = { channels: { qntm: { identityDir: profile.dir, relayUrl: 'https://relay.test',
        conversations: { team: { convId: conv.conversationId, groupActions: ['add'] } } } } };
      const check = () => { writeFileSync(filename, JSON.stringify(records)); return resolveQntmAccount({ cfg }); };
      expect(check().bindings[0].ordinaryGroup).toBe(true);
      records[0].gateway = { accepted: true }; expect(check().configured).toBe(false); delete records[0].gateway;
      records[0].relay_url = 'https://wrong-relay.test'; expect(check().configured).toBe(false); delete records[0].relay_url;
      records[0].group_operation = { action: 'add' }; expect(check().configured).toBe(false);
    } finally { profile.cleanup(); }
  });
  it('rejects gateway/ordinary ambiguity and hides the optional tool outside its permitted native route', () => {
    const { cfg, ctx } = fixture(), service = new QntmGroupActions();
    expect(createQntmGroupTool(ctx, cfg, service)?.name).toBe('qntm_group');
    expect(createQntmGroupTool({ ...ctx, messageChannel: 'slack' }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...ctx, nativeChannelId: 'ff'.repeat(16) }, cfg, service)).toBeNull();
    cfg.channels!.qntm!.conversations!.team!.groupActions = [];
    expect(createQntmGroupTool(ctx, cfg, service)).toBeNull();
    cfg.channels!.qntm!.conversations!.team!.gatewayActions = ['approve'];
    expect(QntmConfigSchema.safeParse(cfg.channels!.qntm).success).toBe(false);
  });
  it('scopes an operator-initiated turn only through its Gateway-resolved qntm delivery route', async () => {
    const { cfg, ctx } = fixture(), service = new QntmGroupActions(), conversation = ctx.nativeChannelId!;
    const { nativeChannelId: _native, ...bare } = ctx;
    const routed = { ...bare, senderIsOwner: true, deliveryContext: { channel: 'qntm', to: `qntm:${conversation}`, accountId: 'default' } } as OpenClawPluginToolContext;
    expect(createQntmGroupTool(bare as OpenClawPluginToolContext, cfg, service)).toBeNull();
    expect(createQntmGroupTool(routed, cfg, service)?.name).toBe('qntm_group');
    expect(resolveGroupToolScope(routed, cfg).store.binding.conversationId).toBe(conversation);
    // Only an owner-initiated run addressed to this channel may use the delivery route; a
    // host-scheduled turn in the same session carries neither the native id nor that marking.
    expect(createQntmGroupTool({ ...routed, senderIsOwner: false }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, senderIsOwner: undefined }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, messageChannel: undefined }, cfg, service)).toBeNull();
    // The route is runtime-provided and must name a configured qntm conversation of this account.
    expect(createQntmGroupTool({ ...routed, deliveryContext: { channel: 'slack', to: `qntm:${conversation}` } }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, deliveryContext: { channel: 'qntm', to: conversation } }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, deliveryContext: { channel: 'qntm', to: `qntm:${'ff'.repeat(16)}` } }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, deliveryContext: { channel: 'qntm', to: `qntm:${conversation}`, accountId: 'other' } }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, agentAccountId: 'other' }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...routed, sessionId: undefined }, cfg, service)).toBeNull();
    for (const nativeChannelId of ['', 'not-a-conversation']) {
      expect(createQntmGroupTool({ ...routed, nativeChannelId }, cfg, service)).toBeNull();
    }
    // A native inbound turn whose delivery route disagrees with its platform conversation is refused.
    expect(createQntmGroupTool({ ...ctx, deliveryContext: { channel: 'qntm', to: `qntm:${'ff'.repeat(16)}` } }, cfg, service)).toBeNull();
    expect(createQntmGroupTool({ ...ctx, deliveryContext: { channel: 'qntm', to: `qntm:${conversation}` } }, cfg, service)?.name).toBe('qntm_group');
    // Reviews stay bound to the initiating route: an inbound requester's review cannot be committed by the operator route.
    const inbound = resolveGroupToolScope({ ...ctx, requesterSenderId: 'ab'.repeat(16) }, cfg);
    expect(resolveGroupToolScope(routed, cfg).key).not.toBe(inbound.key);
    await expect(service.execute(resolveGroupToolScope(routed, cfg), { operation: 'commit', reviewToken: '00'.repeat(16), reviewHash: '00'.repeat(32) }))
      .rejects.toThrow('Review unavailable, expired or mismatched');
    // Local initiation grants no action the binding does not permit, including
    // release_unproven which is never implied by an unknown or add-only grant.
    await expect(service.execute(resolveGroupToolScope(routed, cfg), { operation: 'prepare', action: 'retry' })).rejects.toThrow('not permitted');
    await expect(service.execute(resolveGroupToolScope(routed, cfg), { operation: 'prepare', action: 'release_unproven' })).rejects.toThrow('not permitted');
  });
});
