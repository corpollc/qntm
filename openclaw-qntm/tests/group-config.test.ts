import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createConversationFixture, createIdentityDirFixture } from './helpers.js';
import { describe, expect, it } from 'vitest';
import { generateIdentity, createGroupLink, base64UrlEncode, serializeIdentity, GroupState, createGroupGenesisBody, parseGroupGenesisBody, createGroupSession } from '@corpollc/qntm';
import type { OpenClawPluginToolContext } from 'openclaw/plugin-sdk/core';
import { resolveQntmAccount } from '../src/accounts.js';
import { QntmConfigSchema } from '../src/config-schema.js';
import { QntmGroupActions, createQntmGroupTool } from '../src/group-tool.js';
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
});
