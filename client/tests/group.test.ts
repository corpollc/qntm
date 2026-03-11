import { describe, it, expect } from 'vitest';
import {
  QSP1Suite,
  generateIdentity,
  keyIDFromPublicKey,
  keyIDToString,
  marshalCanonical,
  unmarshalCanonical,
  createInvite,
  deriveConversationKeys,
  createConversation,
  createMessage,
  decryptMessage,
  MAX_GROUP_SIZE,
  base64UrlEncode,
} from '../src/index.js';
import {
  createGroupGenesisBody,
  parseGroupGenesisBody,
  createGroupAddBody,
  parseGroupAddBody,
  createGroupRemoveBody,
  parseGroupRemoveBody,
  createGroupRekeyBody,
  parseGroupRekeyBody,
  GroupState,
  processGroupMessage,
  createRekey,
  applyRekey,
} from '../src/group/index.js';
import type { Identity, Conversation } from '../src/types.js';

const suite = new QSP1Suite();

function makeIdentity(): Identity {
  return generateIdentity();
}

// Helper: set up a group conversation from an invite
function setupGroupConversation(creator: Identity): Conversation {
  const invite = createInvite(creator, 'group');
  const keys = deriveConversationKeys(invite);
  return createConversation(invite, keys);
}

// === 1. Group genesis body ===
describe('createGroupGenesisBody', () => {
  it('creates a genesis body with creator as admin', () => {
    const creator = makeIdentity();
    const member1 = makeIdentity();

    const body = createGroupGenesisBody('Test Group', 'A test', creator, [member1.publicKey]);
    const parsed = parseGroupGenesisBody(body);

    expect(parsed.group_name).toBe('Test Group');
    expect(parsed.description).toBe('A test');
    expect(parsed.created_at).toBeGreaterThan(0);
    expect(parsed.founding_members).toHaveLength(2);

    // Creator is first member with role admin
    const creatorMember = parsed.founding_members[0];
    expect(creatorMember.role).toBe('admin');
    expect(new Uint8Array(creatorMember.public_key)).toEqual(creator.publicKey);

    // Second member has role member
    const m1 = parsed.founding_members[1];
    expect(m1.role).toBe('member');
    expect(new Uint8Array(m1.public_key)).toEqual(member1.publicKey);
  });

  it('deduplicates creator from founding member list', () => {
    const creator = makeIdentity();
    const body = createGroupGenesisBody('Dup Test', '', creator, [creator.publicKey]);
    const parsed = parseGroupGenesisBody(body);
    expect(parsed.founding_members).toHaveLength(1);
  });

  it('creates genesis with creator only when no extra members', () => {
    const creator = makeIdentity();
    const body = createGroupGenesisBody('Solo', '', creator, []);
    const parsed = parseGroupGenesisBody(body);
    expect(parsed.founding_members).toHaveLength(1);
    expect(parsed.founding_members[0].role).toBe('admin');
  });
});

// === 2. Group add body ===
describe('createGroupAddBody', () => {
  it('creates an add body with new members', () => {
    const adder = makeIdentity();
    const newMember = makeIdentity();

    const body = createGroupAddBody(adder, [newMember.publicKey]);
    const parsed = parseGroupAddBody(body);

    expect(parsed.added_at).toBeGreaterThan(0);
    expect(parsed.new_members).toHaveLength(1);
    expect(parsed.new_members[0].role).toBe('member');
    expect(new Uint8Array(parsed.new_members[0].public_key)).toEqual(newMember.publicKey);

    const adderKid = keyIDFromPublicKey(adder.publicKey);
    expect(new Uint8Array(parsed.new_members[0].added_by)).toEqual(adderKid);
  });

  it('creates add body with multiple new members', () => {
    const adder = makeIdentity();
    const m1 = makeIdentity();
    const m2 = makeIdentity();

    const body = createGroupAddBody(adder, [m1.publicKey, m2.publicKey]);
    const parsed = parseGroupAddBody(body);
    expect(parsed.new_members).toHaveLength(2);
  });
});

// === 3. Group remove body ===
describe('createGroupRemoveBody', () => {
  it('creates a remove body with member kids', () => {
    const member = makeIdentity();
    const kid = keyIDFromPublicKey(member.publicKey);

    const body = createGroupRemoveBody([kid], 'violated policy');
    const parsed = parseGroupRemoveBody(body);

    expect(parsed.removed_at).toBeGreaterThan(0);
    expect(parsed.reason).toBe('violated policy');
    expect(parsed.removed_members).toHaveLength(1);
    expect(new Uint8Array(parsed.removed_members[0])).toEqual(kid);
  });

  it('creates a remove body with empty reason', () => {
    const member = makeIdentity();
    const kid = keyIDFromPublicKey(member.publicKey);

    const body = createGroupRemoveBody([kid]);
    const parsed = parseGroupRemoveBody(body);
    expect(parsed.reason).toBe('');
  });
});

// === 4. Group rekey body — wrap/unwrap roundtrip ===
describe('createGroupRekeyBody', () => {
  it('creates a rekey body and recipient can unwrap', () => {
    const member = makeIdentity();
    const kid = keyIDFromPublicKey(member.publicKey);
    const convID = new Uint8Array(16).fill(0xab);
    const newGroupKey = suite.generateGroupKey();

    const members = [{ kid, publicKey: member.publicKey }];
    const body = createGroupRekeyBody(newGroupKey, 1, members, convID);
    const parsed = parseGroupRekeyBody(body);

    expect(parsed.new_conv_epoch).toBe(1);
    expect(Object.keys(parsed.wrapped_keys)).toHaveLength(1);

    // Unwrap the key
    const kidStr = base64UrlEncode(kid);
    const wrappedKey = parsed.wrapped_keys[kidStr];
    expect(wrappedKey).toBeDefined();

    const unwrapped = suite.unwrapKeyForRecipient(
      new Uint8Array(wrappedKey),
      member.privateKey,
      kid,
      convID,
    );
    expect(unwrapped).toEqual(newGroupKey);
  });

  it('wraps key for multiple members', () => {
    const m1 = makeIdentity();
    const m2 = makeIdentity();
    const convID = new Uint8Array(16).fill(0xcd);
    const newGroupKey = suite.generateGroupKey();

    const members = [
      { kid: keyIDFromPublicKey(m1.publicKey), publicKey: m1.publicKey },
      { kid: keyIDFromPublicKey(m2.publicKey), publicKey: m2.publicKey },
    ];
    const body = createGroupRekeyBody(newGroupKey, 2, members, convID);
    const parsed = parseGroupRekeyBody(body);

    expect(Object.keys(parsed.wrapped_keys)).toHaveLength(2);

    // Both members can unwrap
    for (const m of [m1, m2]) {
      const kid = keyIDFromPublicKey(m.publicKey);
      const kidStr = base64UrlEncode(kid);
      const unwrapped = suite.unwrapKeyForRecipient(
        new Uint8Array(parsed.wrapped_keys[kidStr]),
        m.privateKey,
        kid,
        convID,
      );
      expect(unwrapped).toEqual(newGroupKey);
    }
  });
});

// === 5. GroupState lifecycle ===
describe('GroupState', () => {
  it('applies genesis correctly', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();

    const body = createGroupGenesisBody('G1', 'desc', creator, [m1.publicKey]);
    const parsed = parseGroupGenesisBody(body);

    const state = new GroupState();
    state.applyGenesis(parsed);

    expect(state.groupName).toBe('G1');
    expect(state.description).toBe('desc');
    expect(state.memberCount()).toBe(2);
    expect(state.isMember(keyIDFromPublicKey(creator.publicKey))).toBe(true);
    expect(state.isMember(keyIDFromPublicKey(m1.publicKey))).toBe(true);
    expect(state.isAdmin(keyIDFromPublicKey(creator.publicKey))).toBe(true);
    expect(state.isAdmin(keyIDFromPublicKey(m1.publicKey))).toBe(false);
  });

  it('applies add correctly', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();
    const m2 = makeIdentity();

    const state = new GroupState();
    const genesisBody = createGroupGenesisBody('G2', '', creator, [m1.publicKey]);
    state.applyGenesis(parseGroupGenesisBody(genesisBody));

    const addBody = createGroupAddBody(creator, [m2.publicKey]);
    state.applyAdd(parseGroupAddBody(addBody));

    expect(state.memberCount()).toBe(3);
    expect(state.isMember(keyIDFromPublicKey(m2.publicKey))).toBe(true);
  });

  it('applies remove correctly', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();
    const m1Kid = keyIDFromPublicKey(m1.publicKey);

    const state = new GroupState();
    const genesisBody = createGroupGenesisBody('G3', '', creator, [m1.publicKey]);
    state.applyGenesis(parseGroupGenesisBody(genesisBody));

    expect(state.memberCount()).toBe(2);

    const removeBody = createGroupRemoveBody([m1Kid]);
    state.applyRemove(parseGroupRemoveBody(removeBody));

    expect(state.memberCount()).toBe(1);
    expect(state.isMember(m1Kid)).toBe(false);
  });

  it('does not allow removing the creator', () => {
    const creator = makeIdentity();
    const creatorKid = keyIDFromPublicKey(creator.publicKey);

    const state = new GroupState();
    const genesisBody = createGroupGenesisBody('G4', '', creator, []);
    state.applyGenesis(parseGroupGenesisBody(genesisBody));

    const removeBody = createGroupRemoveBody([creatorKid]);
    state.applyRemove(parseGroupRemoveBody(removeBody));

    expect(state.memberCount()).toBe(1);
    expect(state.isMember(creatorKid)).toBe(true);
  });

  it('processGroupMessage dispatches correctly', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();
    const m2 = makeIdentity();

    const state = new GroupState();

    // Genesis
    const genesis = createGroupGenesisBody('G5', '', creator, [m1.publicKey]);
    processGroupMessage('group_genesis', genesis, state);
    expect(state.memberCount()).toBe(2);

    // Add
    const add = createGroupAddBody(creator, [m2.publicKey]);
    processGroupMessage('group_add', add, state);
    expect(state.memberCount()).toBe(3);

    // Remove
    const remove = createGroupRemoveBody([keyIDFromPublicKey(m1.publicKey)]);
    processGroupMessage('group_remove', remove, state);
    expect(state.memberCount()).toBe(2);
    expect(state.isMember(keyIDFromPublicKey(m1.publicKey))).toBe(false);

    // Ignored body types
    processGroupMessage('text', new Uint8Array(0), state);
    expect(state.memberCount()).toBe(2);
  });

  it('listMembers and listAdmins return correct kids', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();

    const state = new GroupState();
    const genesis = createGroupGenesisBody('G6', '', creator, [m1.publicKey]);
    state.applyGenesis(parseGroupGenesisBody(genesis));

    const members = state.listMembers();
    expect(members).toHaveLength(2);

    const admins = state.listAdmins();
    expect(admins).toHaveLength(1);
  });
});

// === 6. createRekey and applyRekey ===
describe('createRekey / applyRekey', () => {
  it('creates rekey and applies it to conversation', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();

    const conv = setupGroupConversation(creator);
    const state = new GroupState();
    const genesis = createGroupGenesisBody('G7', '', creator, [m1.publicKey]);
    state.applyGenesis(parseGroupGenesisBody(genesis));

    expect(conv.currentEpoch).toBe(0);

    const { bodyBytes, newGroupKey } = createRekey(creator, conv, state);
    const parsed = parseGroupRekeyBody(bodyBytes);
    expect(parsed.new_conv_epoch).toBe(1);

    // Apply rekey
    applyRekey(conv, newGroupKey, 1);
    expect(conv.currentEpoch).toBe(1);

    // Verify keys were updated
    const { aeadKey, nonceKey } = suite.deriveEpochKeys(newGroupKey, conv.id, 1);
    expect(conv.keys.aeadKey).toEqual(aeadKey);
    expect(conv.keys.nonceKey).toEqual(nonceKey);
  });

  it('recipient can unwrap rekey and derive same keys', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();
    const m1Kid = keyIDFromPublicKey(m1.publicKey);

    const conv = setupGroupConversation(creator);
    const state = new GroupState();
    const genesis = createGroupGenesisBody('G8', '', creator, [m1.publicKey]);
    state.applyGenesis(parseGroupGenesisBody(genesis));

    const { bodyBytes, newGroupKey } = createRekey(creator, conv, state);
    const parsed = parseGroupRekeyBody(bodyBytes);

    // m1 unwraps the key
    const kidStr = base64UrlEncode(m1Kid);
    const unwrapped = suite.unwrapKeyForRecipient(
      new Uint8Array(parsed.wrapped_keys[kidStr]),
      m1.privateKey,
      m1Kid,
      conv.id,
    );
    expect(unwrapped).toEqual(newGroupKey);

    // Both sides derive same epoch keys
    const creatorKeys = suite.deriveEpochKeys(newGroupKey, conv.id, 1);
    const m1Keys = suite.deriveEpochKeys(unwrapped, conv.id, 1);
    expect(m1Keys.aeadKey).toEqual(creatorKeys.aeadKey);
    expect(m1Keys.nonceKey).toEqual(creatorKeys.nonceKey);
  });
});

// === 7. Full encrypted message roundtrip with group epoch keys ===
describe('Group message roundtrip', () => {
  it('encrypts and decrypts after rekey', () => {
    const creator = makeIdentity();
    const m1 = makeIdentity();
    const m1Kid = keyIDFromPublicKey(m1.publicKey);

    // Set up group conversation and state
    const senderConv = setupGroupConversation(creator);
    const state = new GroupState();
    const genesis = createGroupGenesisBody('G9', '', creator, [m1.publicKey]);
    state.applyGenesis(parseGroupGenesisBody(genesis));

    // Rekey to epoch 1
    const { bodyBytes, newGroupKey } = createRekey(creator, conv(senderConv), state);
    applyRekey(senderConv, newGroupKey, 1);

    // Receiver side: unwrap and apply
    const parsed = parseGroupRekeyBody(bodyBytes);
    const kidStr = base64UrlEncode(m1Kid);
    const unwrapped = suite.unwrapKeyForRecipient(
      new Uint8Array(parsed.wrapped_keys[kidStr]),
      m1.privateKey,
      m1Kid,
      senderConv.id,
    );

    // Build receiver conversation with same ID and unwrapped keys
    const receiverConv: Conversation = {
      id: senderConv.id,
      type: 'group',
      keys: {
        root: unwrapped,
        aeadKey: suite.deriveEpochKeys(unwrapped, senderConv.id, 1).aeadKey,
        nonceKey: suite.deriveEpochKeys(unwrapped, senderConv.id, 1).nonceKey,
      },
      participants: [],
      createdAt: new Date(),
      currentEpoch: 1,
    };

    // Creator sends a message
    const messageBody = new TextEncoder().encode('hello group');
    const envelope = createMessage(creator, senderConv, 'text', messageBody, undefined, 86400);

    // Receiver decrypts
    const msg = decryptMessage(envelope, receiverConv);
    expect(msg.verified).toBe(true);
    expect(new Uint8Array(msg.inner.body)).toEqual(messageBody);
  });
});

// identity passthrough helper (no-op, just for readability)
function conv(c: Conversation): Conversation {
  return c;
}
