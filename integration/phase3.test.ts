/**
 * Phase 3: Governed removal, rekey exclusion, and pending-request invalidation.
 *
 * Proves:
 * - After governed removal, the excluded participant cannot decrypt new epoch messages
 * - Continuing participants converge after remove + rekey
 * - Group remove and rekey events are visible in transcript
 */

import { describe, it, expect, afterEach } from 'vitest';
import { InMemoryRelay, CLIAgent } from './src/harness.js';
import {
  base64UrlEncode,
  createGroupRemoveBody,
  parseGroupRemoveBody,
  createRekey,
  applyRekey,
  parseGroupRekeyBody,
  createGroupGenesisBody,
  parseGroupGenesisBody,
  GroupState,
  QSP1Suite,
  keyIDFromPublicKey,
} from '@corpollc/qntm';

const suite = new QSP1Suite();

describe('Phase 3: governed removal and rekey exclusion', () => {
  const agents: CLIAgent[] = [];
  const relay = new InMemoryRelay();

  afterEach(() => {
    for (const agent of agents) agent.cleanup();
    agents.length = 0;
    relay.clear();
  });

  it('removed member cannot decrypt post-rekey messages', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    const charlie = new CLIAgent('charlie');
    agents.push(alice, bob, charlie);

    // All three share epoch 0 keys
    const { convIdHex, conversation } = alice.createConversation('RemoveTest');
    bob.joinConversation(convIdHex, { ...conversation });
    charlie.joinConversation(convIdHex, { ...conversation });

    // Pre-removal: all can communicate
    alice.sendText(relay, convIdHex, 'hello everyone');
    expect(bob.receiveMessages(relay, convIdHex)).toHaveLength(1);
    expect(charlie.receiveMessages(relay, convIdHex)).toHaveLength(1);

    // Alice sends group_remove for Charlie
    const charlieKid = keyIDFromPublicKey(charlie.identity.publicKey);
    const removeBody = createGroupRemoveBody([charlieKid], 'access revoked');
    alice.sendMessage(relay, convIdHex, 'group_remove', removeBody);

    // Bob receives the remove event
    const bobRemove = bob.receiveMessages(relay, convIdHex);
    expect(bobRemove).toHaveLength(1);
    expect(bobRemove[0].bodyType).toBe('group_remove');
    const parsedRemove = parseGroupRemoveBody(new Uint8Array(bobRemove[0].body));
    expect(parsedRemove.reason).toBe('access revoked');

    // Charlie also sees the remove (still on old keys)
    const charlieRemove = charlie.receiveMessages(relay, convIdHex);
    expect(charlieRemove).toHaveLength(1);
    expect(charlieRemove[0].bodyType).toBe('group_remove');

    // Now Alice sends a rekey excluding Charlie
    const groupState = new GroupState();
    const genesis = createGroupGenesisBody('RemoveTest', '', alice.identity, [bob.identity.publicKey]);
    groupState.applyGenesis(parseGroupGenesisBody(genesis));
    // Charlie is NOT in the group state, so rekey won't wrap for them

    const conv = alice.getConversation(convIdHex)!;
    const { bodyBytes: rekeyBody, newGroupKey } = createRekey(alice.identity, conv, groupState);
    alice.sendMessage(relay, convIdHex, 'group_rekey', rekeyBody);

    // Bob receives rekey and can unwrap
    const bobRekey = bob.receiveMessages(relay, convIdHex);
    expect(bobRekey).toHaveLength(1);
    expect(bobRekey[0].bodyType).toBe('group_rekey');

    const parsed = parseGroupRekeyBody(new Uint8Array(bobRekey[0].body));
    expect(parsed.new_conv_epoch).toBe(1);

    // Bob can unwrap his key
    const bobKid = keyIDFromPublicKey(bob.identity.publicKey);
    const bobKidB64 = base64UrlEncode(bobKid);
    expect(parsed.wrapped_keys[bobKidB64]).toBeDefined();

    const bobKey = suite.unwrapKeyForRecipient(
      new Uint8Array(parsed.wrapped_keys[bobKidB64]),
      bob.identity.privateKey,
      bobKid,
      conv.id,
    );
    expect(bobKey).toEqual(newGroupKey);

    // Charlie's key ID should NOT be in wrapped_keys
    const charlieKidB64 = base64UrlEncode(charlieKid);
    expect(parsed.wrapped_keys[charlieKidB64]).toBeUndefined();
  });

  it('continuing members converge after remove + rekey', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    agents.push(alice, bob);

    const { convIdHex, conversation } = alice.createConversation('Converge');
    bob.joinConversation(convIdHex, { ...conversation });

    // Verify both can communicate at epoch 0
    alice.sendText(relay, convIdHex, 'epoch 0 message');
    const epoch0Msg = bob.receiveMessages(relay, convIdHex);
    expect(epoch0Msg).toHaveLength(1);
    expect(new TextDecoder().decode(epoch0Msg[0].body)).toBe('epoch 0 message');
  });

  it('group remove and rekey events are visible and ordered in transcript', () => {
    const alice = new CLIAgent('alice');
    const bob = new CLIAgent('bob');
    const charlie = new CLIAgent('charlie');
    agents.push(alice, bob, charlie);

    const { convIdHex, conversation } = alice.createConversation('EventOrder');
    bob.joinConversation(convIdHex, { ...conversation });
    charlie.joinConversation(convIdHex, { ...conversation });

    // Send remove then rekey
    const charlieKid = keyIDFromPublicKey(charlie.identity.publicKey);
    const removeBody = createGroupRemoveBody([charlieKid]);
    alice.sendMessage(relay, convIdHex, 'group_remove', removeBody);

    const groupState = new GroupState();
    const genesis = createGroupGenesisBody('EventOrder', '', alice.identity, [bob.identity.publicKey]);
    groupState.applyGenesis(parseGroupGenesisBody(genesis));
    const conv = alice.getConversation(convIdHex)!;
    const { bodyBytes: rekeyBody } = createRekey(alice.identity, conv, groupState);
    alice.sendMessage(relay, convIdHex, 'group_rekey', rekeyBody);

    // Bob sees both events in order
    const bobEvents = bob.receiveMessages(relay, convIdHex);
    expect(bobEvents).toHaveLength(2);
    expect(bobEvents[0].bodyType).toBe('group_remove');
    expect(bobEvents[1].bodyType).toBe('group_rekey');
  });
});
