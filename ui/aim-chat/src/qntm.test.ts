import {
  base64UrlDecode,
  computePayloadHash,
  hashRequest,
  openSecret,
  publicKeyToString,
  verifyApproval,
  verifyRequest,
} from '@corpollc/qntm'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as store from './store'
import {
  createInviteForProfile,
  gateApproveRequest,
  gatePromoteRequest,
  gateRunRequest,
  gateSecretRequest,
  generateIdentityForProfile,
  hexToBytes,
  receiveMessages,
  sendMessageToConversation,
  acceptInviteForProfile,
} from './qntm'

class MemoryStorage implements Storage {
  private data = new Map<string, string>()

  get length(): number {
    return this.data.size
  }

  clear(): void {
    this.data.clear()
  }

  getItem(key: string): string | null {
    return this.data.has(key) ? this.data.get(key)! : null
  }

  key(index: number): string | null {
    return Array.from(this.data.keys())[index] ?? null
  }

  removeItem(key: string): void {
    this.data.delete(key)
  }

  setItem(key: string, value: string): void {
    this.data.set(key, value)
  }
}

class FakeDropboxRelay {
  private conversations = new Map<string, Array<{ seq: number; envelope_b64: string }>>()

  async handleFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url

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
        .filter((message) => message.seq > request.from_seq)
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

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function createProfile(name: string): { id: string; name: string } {
  const profile = store.createProfile(name)
  generateIdentityForProfile(profile.id)
  return profile
}

function identityFor(profileId: string) {
  const identity = store.getIdentity(profileId)
  if (!identity) {
    throw new Error(`Missing identity for ${profileId}`)
  }
  return identity
}

async function createConversationPair() {
  const alice = createProfile('Alice')
  const bob = createProfile('Bob')
  const invite = createInviteForProfile(alice.id, 'Alice/Bob')
  acceptInviteForProfile(bob.id, invite.inviteToken, 'Alice/Bob')
  return { alice, bob, conversationId: invite.conversationId }
}

describe('browser qntm adapter', () => {
  let relay: FakeDropboxRelay

  beforeEach(() => {
    relay = new FakeDropboxRelay()
    vi.stubGlobal('localStorage', new MemoryStorage())
    vi.stubGlobal('fetch', vi.fn((input: string | URL | Request, init?: RequestInit) => relay.handleFetch(input, init)))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('suppresses self echoes when polling sent messages', async () => {
    const alice = createProfile('Alice')
    const invite = createInviteForProfile(alice.id, 'Solo')

    await sendMessageToConversation(alice.id, alice.name, invite.conversationId, 'hello')
    const received = await receiveMessages(alice.id, alice.name, invite.conversationId)

    expect(received.messages).toEqual([])
    expect(store.getHistory(alice.id, invite.conversationId)).toHaveLength(1)
  })

  it('uses payload for gate request signing and approval hashing', async () => {
    const alice = createProfile('Alice')
    const invite = createInviteForProfile(alice.id, 'Ops')
    const aliceIdentity = identityFor(alice.id)
    const alicePublicKey = hexToBytes(aliceIdentity.publicKey)

    const requestMessage = await gateRunRequest(
      alice.id,
      alice.name,
      invite.conversationId,
      {
        name: 'deploy.app',
        description: 'Deploy an application',
        verb: 'POST',
        service: 'deploy',
        endpoint: '/apps/{app}/deploy',
        target_url: 'https://api.example.test/apps/{app}/deploy',
        risk_tier: 'write',
        threshold: 1,
        query_params: [{ name: 'env', description: 'Environment', required: false, default: 'prod', type: 'string' }],
        body_schema: {
          type: 'object',
          properties: {
            version: { type: 'string' },
            force: { type: 'string' },
          },
          required: ['version'],
        },
      },
      'deploy.app',
      'org-1',
      '',
      { app: 'qntm', version: '1.2.3', force: 'true' },
    )

    const request = JSON.parse(requestMessage.text) as {
      conv_id: string
      request_id: string
      verb: string
      target_endpoint: string
      target_service: string
      target_url: string
      expires_at: string
      signature: string
      payload?: unknown
      eligible_signer_kids: string[]
      required_approvals: number
    }
    expect(request.payload).toEqual({ version: '1.2.3', force: 'true' })
    expect(request).not.toHaveProperty('request_body')
    expect(request.target_url).toBe('https://api.example.test/apps/qntm/deploy?env=prod')
    expect(request.eligible_signer_kids).toBeDefined()
    expect(request.required_approvals).toBeDefined()

    const requestPayloadHash = computePayloadHash(request.payload ?? null)
    const requestSignable = {
      conv_id: request.conv_id,
      request_id: request.request_id,
      verb: request.verb,
      target_endpoint: request.target_endpoint,
      target_service: request.target_service,
      target_url: request.target_url,
      expires_at_unix: Math.floor(new Date(request.expires_at).getTime() / 1000),
      payload_hash: requestPayloadHash,
      eligible_signer_kids: request.eligible_signer_kids,
      required_approvals: request.required_approvals,
    }
    expect(verifyRequest(alicePublicKey, requestSignable, base64UrlDecode(request.signature))).toBe(true)

    const approvalMessage = await gateApproveRequest(
      alice.id,
      alice.name,
      invite.conversationId,
      request.request_id,
    )
    const approval = JSON.parse(approvalMessage.text) as {
      conv_id: string
      request_id: string
      signature: string
    }
    // Build the same signable used for signing (includes eligible_signer_kids and required_approvals)
    const requestHash = hashRequest(requestSignable)
    const approvalSignable = {
      conv_id: approval.conv_id,
      request_id: approval.request_id,
      request_hash: requestHash,
    }

    expect(verifyApproval(alicePublicKey, approvalSignable, base64UrlDecode(approval.signature))).toBe(true)
  })

  it('learns participant public keys and emits participants map on promote', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    const aliceIdentity = identityFor(alice.id)
    const bobIdentity = identityFor(bob.id)

    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hello from bob')
    await receiveMessages(alice.id, alice.name, conversationId)

    const gatewayKid = 'gateway-kid-placeholder'
    const promoteMessage = await gatePromoteRequest(alice.id, alice.name, conversationId, gatewayKid, 2)
    const payload = JSON.parse(promoteMessage.text) as {
      type: string
      participants: Record<string, string>
      rules: Array<{ m: number }>
      floor: number
    }

    expect(payload.type).toBe('gate.promote')
    expect(payload.rules[0]).toMatchObject({ m: 2 })
    expect(payload.floor).toBe(2)

    // Participant map keys must be base64url KIDs (matching gateway-worker wire format)
    const aliceKidB64 = publicKeyToString(hexToBytes(aliceIdentity.keyId))  // publicKeyToString is base64UrlEncode
    const bobKidB64 = publicKeyToString(hexToBytes(bobIdentity.keyId))
    expect(payload.participants).toEqual({
      [aliceKidB64]: publicKeyToString(hexToBytes(aliceIdentity.publicKey)),
      [bobKidB64]: publicKeyToString(hexToBytes(bobIdentity.publicKey)),
    })
  })

  it('encrypts gate secrets with the known participant public key using base64url', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    const aliceIdentity = identityFor(alice.id)
    const bobIdentity = identityFor(bob.id)

    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hello from bob')
    await receiveMessages(alice.id, alice.name, conversationId)

    const secretMessage = await gateSecretRequest(
      alice.id,
      alice.name,
      conversationId,
      'stripe',
      'sk_test_123',
      'Authorization',
      'Bearer {value}',
    )
    const payload = JSON.parse(secretMessage.text) as {
      type: string
      sender_kid: string
      encrypted_blob: string
    }

    expect(payload.type).toBe('gate.secret')
    // sender_kid is now base64url, not hex
    const aliceSenderKidB64 = publicKeyToString(hexToBytes(aliceIdentity.keyId))
    expect(payload.sender_kid).toBe(aliceSenderKidB64)

    const decrypted = openSecret(
      hexToBytes(bobIdentity.privateKey),
      hexToBytes(aliceIdentity.publicKey),
      base64UrlDecode(payload.encrypted_blob),
    )
    expect(new TextDecoder().decode(decrypted)).toBe('sk_test_123')
  })

  it('accepts a provided base64url gateway public key for gate secrets', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    const aliceIdentity = identityFor(alice.id)
    const bobIdentity = identityFor(bob.id)

    const secretMessage = await gateSecretRequest(
      alice.id,
      alice.name,
      conversationId,
      'stripe',
      'sk_test_explicit',
      'Authorization',
      'Bearer {value}',
      publicKeyToString(hexToBytes(bobIdentity.publicKey)),
    )
    const payload = JSON.parse(secretMessage.text) as {
      sender_kid: string
      encrypted_blob: string
    }

    const aliceSenderKidB64 = publicKeyToString(hexToBytes(aliceIdentity.keyId))
    expect(payload.sender_kid).toBe(aliceSenderKidB64)

    const decrypted = openSecret(
      hexToBytes(bobIdentity.privateKey),
      hexToBytes(aliceIdentity.publicKey),
      base64UrlDecode(payload.encrypted_blob),
    )
    expect(new TextDecoder().decode(decrypted)).toBe('sk_test_explicit')
  })
})
