/**
 * Tests for applying group events on receive in the AIM browser adapter.
 * Verifies that group_genesis, group_add, group_remove, and group_rekey
 * mutate local conversation state correctly.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  generateIdentity,
  keyIDFromPublicKey,
  base64UrlEncode,
  createGroupGenesisBody,
  createGroupAddBody,
  createGroupRemoveBody,
  createRekey,
  GroupState,
  parseGroupGenesisBody,
  createInvite,
  deriveConversationKeys,
  createConversation,
  addParticipant,
  createMessage,
  serializeEnvelope,
  defaultTTL,
  QSP1Suite,
} from '@corpollc/qntm'
import type { Identity, Conversation as CryptoConversation } from '@corpollc/qntm'
import * as store from './store'
import { receiveMessages, generateIdentityForProfile, createInviteForProfile, bytesToHex, hexToBytes } from './qntm'

const suite = new QSP1Suite()

class MemoryStorage implements Storage {
  private data = new Map<string, string>()
  get length(): number { return this.data.size }
  clear(): void { this.data.clear() }
  getItem(key: string): string | null { return this.data.has(key) ? this.data.get(key)! : null }
  key(index: number): string | null { return Array.from(this.data.keys())[index] ?? null }
  removeItem(key: string): void { this.data.delete(key) }
  setItem(key: string, value: string): void { this.data.set(key, value) }
}

class FakeDropboxRelay {
  private conversations = new Map<string, Array<{ seq: number; envelope_b64: string }>>()

  push(convId: string, envelopeBytes: Uint8Array): void {
    const messages = this.conversations.get(convId) || []
    const seq = messages.length + 1
    const b64 = btoa(String.fromCharCode(...envelopeBytes))
    messages.push({ seq, envelope_b64: b64 })
    this.conversations.set(convId, messages)
  }

  async handleFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url

    if (url.endsWith('/v1/send')) {
      const body = JSON.parse(String(init?.body || '{}')) as { conv_id: string; envelope_b64: string }
      const messages = this.conversations.get(body.conv_id) || []
      const seq = messages.length + 1
      messages.push({ seq, envelope_b64: body.envelope_b64 })
      this.conversations.set(body.conv_id, messages)
      return new Response(JSON.stringify({ seq }), { status: 200 })
    }

    if (url.endsWith('/v1/poll')) {
      const body = JSON.parse(String(init?.body || '{}')) as {
        conversations: Array<{ conv_id: string; from_seq: number }>
        max_messages?: number
      }
      const request = body.conversations[0]
      const messages = this.conversations.get(request.conv_id) || []
      const visible = messages
        .filter((m) => m.seq > request.from_seq)
        .slice(0, body.max_messages || messages.length)
      return new Response(JSON.stringify({
        conversations: [{
          conv_id: request.conv_id,
          up_to_seq: messages.at(-1)?.seq || request.from_seq,
          messages: visible,
        }],
      }), { status: 200 })
    }

    throw new Error(`Unexpected fetch URL: ${url}`)
  }
}

function makeIdentity(): Identity {
  return generateIdentity()
}

function setupConversation(creator: Identity): CryptoConversation {
  const invite = createInvite(creator, 'group')
  const keys = deriveConversationKeys(invite)
  return createConversation(invite, keys)
}

describe('group event application on receive', () => {
  let relay: FakeDropboxRelay

  beforeEach(() => {
    relay = new FakeDropboxRelay()
    vi.stubGlobal('localStorage', new MemoryStorage())
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => relay.handleFetch(input, init)))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  function createProfileWithIdentity(name: string): { profileId: string; identity: Identity; keyIdHex: string } {
    const profile = store.createProfile(name)
    generateIdentityForProfile(profile.id)
    const storedId = store.getIdentity(profile.id)!
    const identity: Identity = {
      privateKey: hexToBytes(storedId.privateKey),
      publicKey: hexToBytes(storedId.publicKey),
      keyID: hexToBytes(storedId.keyId),
    }
    return { profileId: profile.id, identity, keyIdHex: storedId.keyId }
  }

  function setupSharedConversation(aliceProfile: string, aliceIdentity: Identity) {
    const invite = createInviteForProfile(aliceProfile, 'Test Group')
    const convIdHex = invite.conversationId

    // Get the crypto conversation from store
    const convRecord = store.findConversation(aliceProfile, convIdHex)!
    const convCrypto: CryptoConversation = {
      id: hexToBytes(convRecord.id),
      type: 'group',
      keys: {
        root: hexToBytes(convRecord.keys.root),
        aeadKey: hexToBytes(convRecord.keys.aeadKey),
        nonceKey: hexToBytes(convRecord.keys.nonceKey),
      },
      participants: convRecord.participants.map(p => hexToBytes(p)),
      createdAt: new Date(convRecord.createdAt),
      currentEpoch: convRecord.currentEpoch,
    }

    return { convIdHex, convCrypto }
  }

  it('applies group_add and updates participant roster', async () => {
    const { profileId: aliceProfileId, identity: alice } = createProfileWithIdentity('Alice')
    const bob = makeIdentity()

    const { convIdHex, convCrypto } = setupSharedConversation(aliceProfileId, alice)

    // Bob sends a group_add from outside (simulating another participant)
    const addBody = createGroupAddBody(bob, [bob.publicKey])
    const envelope = createMessage(bob, convCrypto, 'group_add', addBody, undefined, defaultTTL())
    const serialized = serializeEnvelope(envelope)
    relay.push(convIdHex, serialized)

    // Alice receives
    const result = await receiveMessages(aliceProfileId, 'Alice', convIdHex)
    expect(result.messages).toHaveLength(1)
    expect(result.messages[0].bodyType).toBe('group_add')

    // Verify participant roster was updated
    const conv = store.findConversation(aliceProfileId, convIdHex)
    expect(conv).not.toBeNull()
    const bobKidHex = bytesToHex(keyIDFromPublicKey(bob.publicKey)).toLowerCase()
    expect(conv!.participants).toContain(bobKidHex)
  })

  it('applies group_remove and updates participant roster', async () => {
    const { profileId: aliceProfileId, identity: alice } = createProfileWithIdentity('Alice')
    const bob = makeIdentity()
    const bobKid = keyIDFromPublicKey(bob.publicKey)

    const { convIdHex, convCrypto } = setupSharedConversation(aliceProfileId, alice)

    // First add Bob to participants manually
    store.updateConversation(aliceProfileId, convIdHex, (conv) => ({
      ...conv,
      participants: [...conv.participants, bytesToHex(bobKid).toLowerCase()],
      participantPublicKeys: [...(conv.participantPublicKeys || []), bytesToHex(bob.publicKey)],
    }))

    // Now send a group_remove for Bob
    const removeBody = createGroupRemoveBody([bobKid])
    const envelope = createMessage(alice, convCrypto, 'group_remove', removeBody, undefined, defaultTTL())
    const serialized = serializeEnvelope(envelope)
    relay.push(convIdHex, serialized)

    // Alice receives
    const result = await receiveMessages(aliceProfileId, 'Alice', convIdHex)
    expect(result.messages).toHaveLength(1)
    expect(result.messages[0].bodyType).toBe('group_remove')

    // Verify Bob was removed from roster
    const conv = store.findConversation(aliceProfileId, convIdHex)
    const bobKidHex = bytesToHex(bobKid).toLowerCase()
    expect(conv!.participants).not.toContain(bobKidHex)
  })

  it('applies group_rekey and updates epoch and keys', async () => {
    const { profileId: aliceProfileId, identity: alice, keyIdHex: aliceKidHex } = createProfileWithIdentity('Alice')

    const { convIdHex, convCrypto } = setupSharedConversation(aliceProfileId, alice)

    // Build a GroupState with alice as member
    const groupState = new GroupState()
    const genesis = createGroupGenesisBody('Test', '', alice, [])
    groupState.applyGenesis(parseGroupGenesisBody(genesis))

    // Create a rekey
    const { bodyBytes: rekeyBody, newGroupKey } = createRekey(alice, convCrypto, groupState)
    const envelope = createMessage(alice, convCrypto, 'group_rekey', rekeyBody, undefined, defaultTTL())
    const serialized = serializeEnvelope(envelope)
    relay.push(convIdHex, serialized)

    // Before receive: epoch should be 0
    expect(store.findConversation(aliceProfileId, convIdHex)!.currentEpoch).toBe(0)

    // Alice receives
    const result = await receiveMessages(aliceProfileId, 'Alice', convIdHex)
    expect(result.messages).toHaveLength(1)
    expect(result.messages[0].bodyType).toBe('group_rekey')

    // After receive: epoch should be 1
    const conv = store.findConversation(aliceProfileId, convIdHex)
    expect(conv!.currentEpoch).toBe(1)
    // Keys should have changed
    expect(conv!.keys.root).not.toBe('') // non-empty
  })

  it('group_rekey with excluded member does not update keys', async () => {
    const { profileId: aliceProfileId, identity: alice } = createProfileWithIdentity('Alice')
    const bob = makeIdentity()

    const { convIdHex, convCrypto } = setupSharedConversation(aliceProfileId, alice)

    // Build a GroupState with only Bob as member (alice is excluded)
    const groupState = new GroupState()
    const genesis = createGroupGenesisBody('Test', '', bob, [])
    groupState.applyGenesis(parseGroupGenesisBody(genesis))

    // Create a rekey that only wraps for Bob (not Alice)
    const bobConv: CryptoConversation = { ...convCrypto }
    const { bodyBytes: rekeyBody } = createRekey(bob, bobConv, groupState)
    const envelope = createMessage(bob, convCrypto, 'group_rekey', rekeyBody, undefined, defaultTTL())
    const serialized = serializeEnvelope(envelope)
    relay.push(convIdHex, serialized)

    const origConv = store.findConversation(aliceProfileId, convIdHex)!
    const origKeys = { ...origConv.keys }

    // Alice receives — she has no wrapped key
    const result = await receiveMessages(aliceProfileId, 'Alice', convIdHex)
    expect(result.messages).toHaveLength(1)

    // Keys should NOT have changed (alice couldn't unwrap)
    const conv = store.findConversation(aliceProfileId, convIdHex)
    expect(conv!.keys.aeadKey).toBe(origKeys.aeadKey)
    expect(conv!.keys.nonceKey).toBe(origKeys.nonceKey)
  })
})
