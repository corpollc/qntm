import {
  generateIdentity, base64UrlEncode, createMessage, serializeEnvelope, gatewayInvitationHash,
  base64UrlDecode,
  computePayloadHash,
  createInvite,
  inviteToToken,
  hashProposal,
  hashRequest,
  openSecret,
  publicKeyToString,
  verifyGovApproval,
  verifyProposal,
  verifyApproval,
  verifyRequest,
  createGroupGenesisBody, parseGroupGenesisBody, createGroupRemoveBody, parseGroupRemoveBody,
  GroupState, createRekey, applyRekey,
} from '@corpollc/qntm'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import * as store from './store'
import {
  createInviteForProfile,
  gateApproveRequest,
  gateDisapproveRequest,
  gatePromoteRequest,
  gateRunRequest,
  gateSecretRequest,
  generateIdentityForProfile,
  govApproveProposal,
  govDisapproveProposal,
  govProposeFloorChange,
  govProposeMemberAdd,
  govProposeMemberRemove,
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
  readonly gateway = generateIdentity()
  readonly receipts: Array<Record<string, unknown>> = []

  replay(convId: string, fromSeq: number): Array<{ seq: number; envelope_b64: string }> {
    return (this.conversations.get(convId) || []).filter((message) => message.seq > fromSeq)
  }

  headSeq(convId: string, fromSeq: number): number {
    return this.conversations.get(convId)?.at(-1)?.seq || fromSeq
  }

  async handleFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url

    if (url.endsWith('/v1/invitations')) {
      const body = JSON.parse(String(init?.body))
      return Response.json({ ...body, gateway_public_key: base64UrlEncode(this.gateway.publicKey), gateway_kid: base64UrlEncode(this.gateway.keyID), expires_at: Math.floor(Date.now() / 1000) + 600 })
    }
    if (url.endsWith('/v1/promote')) return Response.json({ status: 'joined' })

    if (url.endsWith('/v1/send')) {
      const body = JSON.parse(String(init?.body || '{}')) as { conv_id: string; envelope_b64: string }
      const messages = this.conversations.get(body.conv_id) || []
      const seq = messages.length + 1
      messages.push({ seq, envelope_b64: body.envelope_b64 })
      this.conversations.set(body.conv_id, messages)
      return new Response(JSON.stringify({ seq }), { status: 200 })
    }

    if (url.endsWith('/v1/receipt')) {
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>
      this.receipts.push(body)
      return new Response(JSON.stringify({
        recorded: true,
        deleted: false,
        receipts: 1,
        required_acks: body.required_acks ?? 1,
      }), { status: 200 })
    }

    throw new Error(`Unexpected fetch URL: ${url}`)
  }
}

function createFakeWebSocket(relay: FakeDropboxRelay): typeof WebSocket {
  return class FakeWebSocket {
    private readonly listeners = new Map<string, Array<(event?: any) => void>>()
    readonly url: string

    constructor(url: string) {
      this.url = url
      queueMicrotask(() => {
        this.emit('open')
        const parsed = new URL(url)
        const convId = parsed.searchParams.get('conv_id') || ''
        const fromSeq = Number(parsed.searchParams.get('from_seq') || '0')
        for (const message of relay.replay(convId, fromSeq)) {
          this.emit('message', { data: JSON.stringify({ type: 'message', ...message }) })
        }
        this.emit('message', {
          data: JSON.stringify({ type: 'ready', head_seq: relay.headSeq(convId, fromSeq) }),
        })
      })
    }

    addEventListener(type: string, handler: (event?: any) => void): void {
      const handlers = this.listeners.get(type) || []
      handlers.push(handler)
      this.listeners.set(type, handlers)
    }

    close(code = 1000, reason = ''): void {
      this.emit('close', { code, reason, wasClean: true })
    }

    private emit(type: string, event?: any): void {
      for (const handler of this.listeners.get(type) || []) {
        handler(event)
      }
    }
  } as unknown as typeof WebSocket
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
    vi.stubGlobal('WebSocket', createFakeWebSocket(relay))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('stores invite token at creation and retrieves it for re-sharing', () => {
    const alice = createProfile('Alice')
    const invite = createInviteForProfile(alice.id, 'Test Room')

    // The stored conversation should have the invite token
    const conv = store.findConversation(alice.id, invite.conversationId)
    expect(conv).not.toBeNull()
    expect(conv!.inviteToken).toBeDefined()
    expect(typeof conv!.inviteToken).toBe('string')
    expect(conv!.inviteToken!.length).toBeGreaterThan(0)

    // A second user can join using the stored token
    const bob = createProfile('Bob')
    const result = acceptInviteForProfile(bob.id, conv!.inviteToken!, 'Test Room')
    expect(result.conversationId).toBe(invite.conversationId)
  })

  it('suppresses self echoes when polling sent messages', async () => {
    const alice = createProfile('Alice')
    const invite = createInviteForProfile(alice.id, 'Solo')

    const sent = await sendMessageToConversation(alice.id, alice.name, invite.conversationId, 'hello')
    expect(relay.receipts).toHaveLength(1)
    expect(relay.receipts[0].msg_id).toBe(sent.id)
    expect(relay.receipts[0].required_acks).toBe(2)

    const received = await receiveMessages(alice.id, alice.name, invite.conversationId)

    expect(received.messages).toEqual([])
    expect(store.getHistory(alice.id, invite.conversationId)).toHaveLength(1)
    expect(relay.receipts).toHaveLength(1)
  })

  it('counts the sender toward cleanup quorum at send time', async () => {
    const { alice, conversationId } = await createConversationPair()

    const sent = await sendMessageToConversation(alice.id, alice.name, conversationId, 'hello bob')

    expect(relay.receipts).toHaveLength(1)
    expect(relay.receipts[0].msg_id).toBe(sent.id)
    expect(relay.receipts[0].required_acks).toBe(2)
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

  it('raises request approvals to the current conversation floor', async () => {
    const alice = createProfile('Alice')
    const invite = createInviteForProfile(alice.id, 'Ops')

    const requestMessage = await gateRunRequest(
      alice.id,
      alice.name,
      invite.conversationId,
      {
        name: 'hn.top-stories',
        description: 'Top stories',
        verb: 'GET',
        service: 'hackernews',
        endpoint: '/topstories.json',
        target_url: 'https://hacker-news.firebaseio.com/v0/topstories.json',
        risk_tier: 'read',
        threshold: 1,
      },
      'hn.top-stories',
      '',
      {},
      2,
    )

    const request = JSON.parse(requestMessage.text) as { required_approvals: number }
    expect(request.required_approvals).toBe(2)
  })

  it('learns participant public keys and emits participants map on promote', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    const aliceIdentity = identityFor(alice.id)
    const bobIdentity = identityFor(bob.id)

    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hello from bob')
    await receiveMessages(alice.id, alice.name, conversationId)

    const gatewayKid = 'http://gateway.test'
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

  it('builds signed governance proposals and approvals from the browser client', async () => {
    const alice = createProfile('Alice')
    const invite = createInviteForProfile(alice.id, 'Ops')
    const aliceIdentity = identityFor(alice.id)
    const alicePublicKey = hexToBytes(aliceIdentity.publicKey)

    const proposalMessage = await govProposeFloorChange(
      alice.id,
      alice.name,
      invite.conversationId,
      3,
    )
    const proposal = JSON.parse(proposalMessage.text) as {
      conv_id: string
      proposal_id: string
      proposal_type: 'floor_change'
      proposed_floor: number
      eligible_signer_kids: string[]
      required_approvals: number
      expires_at: string
      signature: string
    }

    const proposalSignable = {
      conv_id: proposal.conv_id,
      proposal_id: proposal.proposal_id,
      proposal_type: proposal.proposal_type,
      proposed_floor: proposal.proposed_floor,
      proposed_rules: undefined,
      proposed_members: undefined,
      removed_member_kids: undefined,
      eligible_signer_kids: proposal.eligible_signer_kids,
      required_approvals: proposal.required_approvals,
      expires_at_unix: Math.floor(new Date(proposal.expires_at).getTime() / 1000),
    }
    expect(verifyProposal(alicePublicKey, proposalSignable, base64UrlDecode(proposal.signature))).toBe(true)

    const approvalMessage = await govApproveProposal(
      alice.id,
      alice.name,
      invite.conversationId,
      proposal.proposal_id,
    )
    const approval = JSON.parse(approvalMessage.text) as {
      conv_id: string
      proposal_id: string
      signature: string
    }
    const proposalHash = hashProposal(proposalSignable)
    expect(verifyGovApproval(alicePublicKey, {
      conv_id: approval.conv_id,
      proposal_id: approval.proposal_id,
      proposal_hash: proposalHash,
    }, base64UrlDecode(approval.signature))).toBe(true)
  })

  it('builds member-change proposals and deny messages for browser governance flows', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    const bobIdentity = identityFor(bob.id)
    const charlie = createProfile('Charlie')
    const charlieIdentity = identityFor(charlie.id)

    const addProposalMessage = await govProposeMemberAdd(
      alice.id,
      alice.name,
      conversationId,
      charlieIdentity.publicKey,
    )
    const addProposal = JSON.parse(addProposalMessage.text) as {
      proposal_type: string
      proposed_members: Array<{ public_key: string }>
    }
    expect(addProposal.proposal_type).toBe('member_add')
    expect(addProposal.proposed_members[0].public_key).toBe(publicKeyToString(hexToBytes(charlieIdentity.publicKey)))

    const removeProposalMessage = await govProposeMemberRemove(
      alice.id,
      alice.name,
      conversationId,
      bobIdentity.keyId,
    )
    const removeProposal = JSON.parse(removeProposalMessage.text) as {
      proposal_id: string
      proposal_type: string
      removed_member_kids: string[]
    }
    expect(removeProposal.proposal_type).toBe('member_remove')
    expect(removeProposal.removed_member_kids).toHaveLength(1)

    const disapprovalMessage = await govDisapproveProposal(
      alice.id,
      alice.name,
      conversationId,
      removeProposal.proposal_id,
    )
    const disapproval = JSON.parse(disapprovalMessage.text) as {
      type: string
      proposal_id: string
    }
    expect(disapproval.type).toBe('gov.disapprove')
    expect(disapproval.proposal_id).toBe(removeProposal.proposal_id)

    const gateDisapprovalMessage = await gateDisapproveRequest(
      alice.id,
      alice.name,
      conversationId,
      'req-123',
    )
    const gateDisapproval = JSON.parse(gateDisapprovalMessage.text) as {
      type: string
      request_id: string
    }
    expect(gateDisapproval.type).toBe('gate.disapproval')
    expect(gateDisapproval.request_id).toBe('req-123')
  })

  it('defaults governance approvals to current participants and remaining members', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    const bobIdentity = identityFor(bob.id)
    const charlie = createProfile('Charlie')
    const charlieIdentity = identityFor(charlie.id)

    store.updateConversation(alice.id, conversationId, (conv) => ({
      ...conv,
      participants: [...conv.participants, bobIdentity.keyId],
      participantPublicKeys: [...(conv.participantPublicKeys || []), bobIdentity.publicKey],
    }))

    store.addHistoryMessage(alice.id, conversationId, {
      id: crypto.randomUUID(),
      conversationId,
      direction: 'incoming',
      sender: 'gateway',
      senderKey: 'gateway',
      bodyType: 'gate.promote',
      text: JSON.stringify({
        type: 'gate.promote',
        conv_id: conversationId,
        floor: 3,
        rules: [{ service: '*', endpoint: '*', verb: '*', m: 3 }],
      }),
      createdAt: new Date().toISOString(),
    })

    const floorProposalMessage = await govProposeFloorChange(
      alice.id,
      alice.name,
      conversationId,
      4,
    )
    const floorProposal = JSON.parse(floorProposalMessage.text) as { required_approvals: number }
    expect(floorProposal.required_approvals).toBe(2)

    store.updateConversation(alice.id, conversationId, (conv) => ({
      ...conv,
      participants: [...conv.participants, charlieIdentity.keyId],
      participantPublicKeys: [...(conv.participantPublicKeys || []), charlieIdentity.publicKey],
    }))

    const removeProposalMessage = await govProposeMemberRemove(
      alice.id,
      alice.name,
      conversationId,
      bobIdentity.keyId,
    )
    const removeProposal = JSON.parse(removeProposalMessage.text) as { required_approvals: number }
    expect(removeProposal.required_approvals).toBe(2)
  })

  it('never guesses a gateway key from another conversation participant', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hello from bob')
    await receiveMessages(alice.id, alice.name, conversationId)
    const before = relay.headSeq(conversationId, 0)
    await expect(gateSecretRequest(alice.id, alice.name, conversationId, 'stripe', 'sk_test_123', 'Authorization', 'Bearer {value}')).rejects.toThrow('No gateway public key configured')
    expect(relay.headSeq(conversationId, 0)).toBe(before)
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

  it('keeps HTTP success pending until a matching gateway signature arrives, then encrypts secrets to that gateway', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hello')
    await receiveMessages(alice.id, alice.name, conversationId)
    const invitationMessage = await gatePromoteRequest(alice.id, alice.name, conversationId, 'http://gateway.test', 2)
    const gateway = store.findConversation(alice.id, conversationId)!.gateway!
    expect(gateway.status).toBe('pending')
    const capsule = JSON.parse(new TextDecoder().decode(openSecret(relay.gateway.privateKey, hexToBytes(identityFor(alice.id).publicKey), base64UrlDecode(gateway.pending!.request.sealed))))
    expect(capsule).toMatchObject({ conv_id: conversationId, invitation_msg_id: invitationMessage.id, conv_epoch: 0 })
    await expect(gateSecretRequest(alice.id, alice.name, conversationId, 'stripe', 'secret', 'Authorization', 'Bearer {value}')).rejects.toThrow('Waiting')
    const invitation = JSON.parse(invitationMessage.text)
    const acceptance = { type: 'gate.accept', invitation_id: invitation.invitation_id, invitation_msg_id: invitationMessage.id,
      invitation_hash: gatewayInvitationHash(invitationMessage.text), conv_id: conversationId, conv_epoch: 0,
      gateway_kid: invitation.gateway_kid, gateway_public_key: invitation.gateway_public_key }
    await sendMessageToConversation(bob.id, bob.name, conversationId, JSON.stringify(acceptance), 'gate.accept')
    await receiveMessages(alice.id, alice.name, conversationId)
    expect(store.findConversation(alice.id, conversationId)!.gateway!.status).toBe('pending')
    const stored = store.findConversation(alice.id, conversationId)!
    const conv = { id: hexToBytes(conversationId), type: 'group' as const, keys: { root: hexToBytes(stored.keys.root), aeadKey: hexToBytes(stored.keys.aeadKey), nonceKey: hexToBytes(stored.keys.nonceKey) }, participants: [], currentEpoch: 0, createdAt: new Date() }
    const envelope = createMessage(relay.gateway, conv, 'gate.accept', new TextEncoder().encode(JSON.stringify(acceptance)), undefined, 3600)
    await relay.handleFetch('http://relay.test/v1/send', { body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...serializeEnvelope(envelope))) }) })
    await receiveMessages(alice.id, alice.name, conversationId)
    expect(store.findConversation(alice.id, conversationId)!.gateway!.status).toBe('active')
    expect(store.findConversation(alice.id, conversationId)!.participants).not.toContain(Array.from(relay.gateway.keyID, b => b.toString(16).padStart(2, '0')).join(''))
    const beforeSecret = relay.headSeq(conversationId, 0)
    await expect(gateSecretRequest(alice.id, alice.name, conversationId, 'stripe', 'secret', 'Authorization', 'Bearer {value}', publicKeyToString(hexToBytes(identityFor(bob.id).publicKey)))).rejects.toThrow('does not match')
    expect(relay.headSeq(conversationId, 0)).toBe(beforeSecret)
    const secret = await gateSecretRequest(alice.id, alice.name, conversationId, 'stripe', 'secret', 'Authorization', 'Bearer {value}')
    const payload = JSON.parse(secret.text)
    expect(payload.gateway_kid).toBe(invitation.gateway_kid)
    expect(new TextDecoder().decode(openSecret(relay.gateway.privateKey, hexToBytes(identityFor(alice.id).publicKey), base64UrlDecode(payload.encrypted_blob)))).toBe('secret')
  })

  it('keeps the receive roster current through genesis, gateway admission and a membership rekey in one batch', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    for (const profile of [alice, bob]) store.updateConversation(profile.id, conversationId, c => ({ ...c, type: 'group' }))
    const saved = identityFor(alice.id)
    const creator = { privateKey: hexToBytes(saved.privateKey), publicKey: hexToBytes(saved.publicKey), keyID: hexToBytes(saved.keyId) }
    const removed = generateIdentity(), retained = generateIdentity()
    const stored = store.findConversation(alice.id, conversationId)!
    const conv = { id: hexToBytes(conversationId), type: 'group' as const,
      keys: { root: hexToBytes(stored.keys.root), aeadKey: hexToBytes(stored.keys.aeadKey), nonceKey: hexToBytes(stored.keys.nonceKey) },
      participants: [creator.keyID, hexToBytes(identityFor(bob.id).keyId), removed.keyID, retained.keyID], currentEpoch: 0, createdAt: new Date() }
    const publish = async (sender: typeof creator, type: string, body: Uint8Array) => {
      const wire = serializeEnvelope(createMessage(sender, conv, type, body))
      await relay.handleFetch('http://relay.test/v1/send', { body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...wire)) }) })
    }
    const genesis = createGroupGenesisBody('Founding roster', '', creator, [hexToBytes(identityFor(bob.id).publicKey), removed.publicKey, retained.publicKey])
    const roster = new GroupState(); roster.applyGenesis(parseGroupGenesisBody(genesis))
    await publish(creator, 'group_genesis', genesis)
    await receiveMessages(alice.id, alice.name, conversationId)
    const offered = await gatePromoteRequest(alice.id, alice.name, conversationId, 'http://gateway.test', 2)
    const invitation = JSON.parse(offered.text)
    await publish(relay.gateway, 'gate.accept', new TextEncoder().encode(JSON.stringify({
      type: 'gate.accept', invitation_id: invitation.invitation_id, invitation_msg_id: offered.id,
      invitation_hash: gatewayInvitationHash(offered.text), conv_id: conversationId, conv_epoch: 0,
      gateway_kid: invitation.gateway_kid, gateway_public_key: invitation.gateway_public_key,
    })))
    const removal = createGroupRemoveBody([removed.keyID])
    roster.applyRemove(parseGroupRemoveBody(removal))
    await publish(relay.gateway, 'group_remove', removal)
    const rekey = createRekey(relay.gateway, conv, roster)
    await publish(relay.gateway, 'group_rekey', rekey.bodyBytes)
    applyRekey(conv, rekey.newGroupKey, 1)
    await publish(creator, 'text', new TextEncoder().encode('after rekey'))
    const result = await receiveMessages(bob.id, bob.name, conversationId)
    expect(store.findConversation(bob.id, conversationId)!.currentEpoch).toBe(1)
    expect(result.messages.map(m => m.bodyType)).toContain('group_remove')
    expect(result.messages.at(-1)?.text).toBe('after rekey')
    expect(store.findConversation(bob.id, conversationId)!.participants).not.toContain(Array.from(removed.keyID, b => b.toString(16).padStart(2, '0')).join(''))
  })

  it('populates allowed_origins on gate.secret, applies service header defaults, and rejects unresolvable services', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hi')
    await receiveMessages(alice.id, alice.name, conversationId)
    const promo = await gatePromoteRequest(alice.id, alice.name, conversationId, 'http://gateway.test', 1)
    const inv = JSON.parse(promo.text)
    const stored = store.findConversation(alice.id, conversationId)!
    const conv = {
      id: hexToBytes(conversationId),
      type: 'direct' as const,
      keys: {
        root: hexToBytes(stored.keys.root),
        aeadKey: hexToBytes(stored.keys.aeadKey),
        nonceKey: hexToBytes(stored.keys.nonceKey),
      },
      participants: [],
      currentEpoch: 0,
      createdAt: new Date(),
    }
    const acceptWire = serializeEnvelope(
      createMessage(
        relay.gateway,
        conv,
        'gate.accept',
        new TextEncoder().encode(
          JSON.stringify({
            type: 'gate.accept',
            invitation_id: inv.invitation_id,
            invitation_msg_id: promo.id,
            invitation_hash: gatewayInvitationHash(promo.text),
            conv_id: conversationId,
            conv_epoch: 0,
            gateway_kid: inv.gateway_kid,
            gateway_public_key: inv.gateway_public_key,
          }),
        ),
        undefined,
        3600,
      ),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...acceptWire)) }),
    })
    await receiveMessages(alice.id, alice.name, conversationId)

    const secretMsg = await gateSecretRequest(alice.id, alice.name, conversationId, 'anthropic', 'sk-ant-test', '', '')
    const parsed = JSON.parse(secretMsg.text) as {
      allowed_origins: string[]
      header_name: string
      header_template: string
    }
    expect(parsed.allowed_origins).toEqual(['https://api.anthropic.com'])
    expect(parsed.header_name).toBe('x-api-key')
    expect(parsed.header_template).toBe('{value}')

    const hostSecretMsg = await gateSecretRequest(
      alice.id,
      alice.name,
      conversationId,
      'api.partner.example.com',
      'sk-partner',
      'Authorization',
      'Bearer {value}',
    )
    expect((JSON.parse(hostSecretMsg.text) as { allowed_origins: string[] }).allowed_origins).toEqual([
      'https://api.partner.example.com',
    ])

    await expect(
      gateSecretRequest(alice.id, alice.name, conversationId, 'unknownservice', 'sk-bad', 'Authorization', 'Bearer {value}'),
    ).rejects.toThrow('known service name')
  })

  it('pins groupControl.creator on group invite import and blocks pre-genesis gate.promote from non-creators', async () => {
    const creatorIdentity = generateIdentity()
    const bob = createProfile('Bob')
    const mallory = createProfile('Mallory')
    const groupInvite = createInvite(creatorIdentity, 'group')
    const token = inviteToToken(groupInvite)
    const { conversationId } = acceptInviteForProfile(bob.id, token, 'Pinned Group')
    acceptInviteForProfile(mallory.id, token, 'Pinned Group')

    const bobConv = store.findConversation(bob.id, conversationId)!
    expect(bobConv.groupControl).toEqual({
      creator: base64UrlEncode(creatorIdentity.keyID),
      needsRekey: false,
      removed: false,
    })

    // Mallory (a non-creator member) attempts to promote a rogue gateway before group_genesis
    store.updateConversation(mallory.id, conversationId, (c) => ({
      ...c,
      groupControl: {
        creator: base64UrlEncode(hexToBytes(identityFor(mallory.id).keyId)),
        needsRekey: false,
        removed: false,
      },
    }))
    const malloryPromote = await gatePromoteRequest(mallory.id, mallory.name, conversationId, 'http://gateway.test', 1)
    const inv = JSON.parse(malloryPromote.text)

    // Even if gateway posts gate.accept, Bob rejects both Mallory's gate.promote and gate.accept!
    const conv = {
      id: hexToBytes(conversationId),
      type: 'group' as const,
      keys: {
        root: hexToBytes(bobConv.keys.root),
        aeadKey: hexToBytes(bobConv.keys.aeadKey),
        nonceKey: hexToBytes(bobConv.keys.nonceKey),
      },
      participants: [],
      currentEpoch: 0,
      createdAt: new Date(),
    }
    const acceptWire = serializeEnvelope(
      createMessage(
        relay.gateway,
        conv,
        'gate.accept',
        new TextEncoder().encode(
          JSON.stringify({
            type: 'gate.accept',
            invitation_id: inv.invitation_id,
            invitation_msg_id: malloryPromote.id,
            invitation_hash: gatewayInvitationHash(malloryPromote.text),
            conv_id: conversationId,
            conv_epoch: 0,
            gateway_kid: inv.gateway_kid,
            gateway_public_key: inv.gateway_public_key,
          }),
        ),
        undefined,
        3600,
      ),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...acceptWire)) }),
    })

    const received = await receiveMessages(bob.id, bob.name, conversationId)
    expect(received.messages).toEqual([])
    expect(store.findConversation(bob.id, conversationId)!.gateway).toBeFalsy()
    expect(store.findConversation(bob.id, conversationId)!.groupControl?.creator).toBe(
      base64UrlEncode(creatorIdentity.keyID),
    )
  })

  it('rejects wrong conv_epoch, forged peer gateway events, and forged vote signatures while applying valid gov.applied membership updates', async () => {
    const { alice, bob, conversationId } = await createConversationPair()
    await sendMessageToConversation(bob.id, bob.name, conversationId, 'hello')
    await receiveMessages(alice.id, alice.name, conversationId)

    const stored = store.findConversation(alice.id, conversationId)!
    const conv = {
      id: hexToBytes(conversationId),
      type: 'direct' as const,
      keys: {
        root: hexToBytes(stored.keys.root),
        aeadKey: hexToBytes(stored.keys.aeadKey),
        nonceKey: hexToBytes(stored.keys.nonceKey),
      },
      participants: [],
      currentEpoch: 0,
      createdAt: new Date(),
    }
    const bobId = {
      privateKey: hexToBytes(identityFor(bob.id).privateKey),
      publicKey: hexToBytes(identityFor(bob.id).publicKey),
      keyID: hexToBytes(identityFor(bob.id).keyId),
    }

    // 1. Wrong conv_epoch on direct chat is rejected
    const wrongEpochWire = serializeEnvelope(
      createMessage(bobId, { ...conv, currentEpoch: 1 }, 'text', new TextEncoder().encode('wrong epoch')),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...wrongEpochWire)) }),
    })

    // 2. Peer-forged gate.executed before gateway activation is rejected
    const forgedBeforeActive = serializeEnvelope(
      createMessage(
        bobId,
        conv,
        'gate.executed',
        new TextEncoder().encode(
          JSON.stringify({
            type: 'gate.executed',
            request_id: 'req-forged',
            executed_at: new Date().toISOString(),
            execution_status_code: 200,
          }),
        ),
      ),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...forgedBeforeActive)) }),
    })

    const beforeRes = await receiveMessages(alice.id, alice.name, conversationId)
    expect(beforeRes.messages).toEqual([])

    // Activate gateway
    const promo = await gatePromoteRequest(alice.id, alice.name, conversationId, 'http://gateway.test', 2)
    const inv = JSON.parse(promo.text)
    const acceptWire = serializeEnvelope(
      createMessage(
        relay.gateway,
        conv,
        'gate.accept',
        new TextEncoder().encode(
          JSON.stringify({
            type: 'gate.accept',
            invitation_id: inv.invitation_id,
            invitation_msg_id: promo.id,
            invitation_hash: gatewayInvitationHash(promo.text),
            conv_id: conversationId,
            conv_epoch: 0,
            gateway_kid: inv.gateway_kid,
            gateway_public_key: inv.gateway_public_key,
          }),
        ),
      ),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...acceptWire)) }),
    })
    await receiveMessages(alice.id, alice.name, conversationId)
    await receiveMessages(bob.id, bob.name, conversationId)

    // 3. Forged gate.approval signature from Bob is rejected
    const recipe = {
      name: 'repo_info',
      description: 'Repo info',
      service: 'github',
      verb: 'GET' as const,
      endpoint: '/repos/{owner}',
      target_url: 'https://api.github.com/repos/{owner}',
      risk_tier: 'read',
      threshold: 2,
      path_params: [{ name: 'owner', type: 'string', description: 'owner', required: true }],
    }
    const reqMsg = await gateRunRequest(
      alice.id,
      alice.name,
      conversationId,
      recipe,
      'repo_info',
      'http://gateway.test',
      { owner: 'acme/sub' },
    )
    const reqBody = JSON.parse(reqMsg.text) as {
      gateway_kid?: string
      request_id: string
      target_endpoint: string
      target_url: string
      expires_at: string
      eligible_signer_kids: string[]
      required_approvals: number
    }
    expect(reqBody.target_endpoint).toBe('/repos/acme%2Fsub')
    expect(reqBody.target_url).toBe('https://api.github.com/repos/acme%2Fsub')

    await expect(
      gateRunRequest(
        alice.id,
        alice.name,
        conversationId,
        recipe,
        'repo_info',
        'http://gateway.test',
        { owner: '..' },
      ),
    ).rejects.toThrow(/dot segments|invalid path parameter/)

    const reqSignable = {
      ...(reqBody.gateway_kid ? { gateway_kid: reqBody.gateway_kid } : {}),
      conv_id: conversationId,
      request_id: reqBody.request_id,
      verb: 'GET',
      target_endpoint: reqBody.target_endpoint,
      target_service: 'github',
      target_url: reqBody.target_url,
      expires_at_unix: Math.floor(new Date(reqBody.expires_at).getTime() / 1000),
      payload_hash: computePayloadHash(null),
      eligible_signer_kids: reqBody.eligible_signer_kids,
      required_approvals: reqBody.required_approvals,
    }
    const forgedApprovalWire = serializeEnvelope(
      createMessage(
        bobId,
        conv,
        'gate.approval',
        new TextEncoder().encode(
          JSON.stringify({
            type: 'gate.approval',
            request_id: reqBody.request_id,
            request_hash: hashRequest(reqSignable),
            conv_id: conversationId,
            conv_epoch: 0,
            gateway_kid: inv.gateway_kid,
            gateway_public_key: inv.gateway_public_key,
            approved_at: new Date().toISOString(),
            signer_kid: base64UrlEncode(bobId.keyID),
            signature: base64UrlEncode(new Uint8Array(64)),
          }),
        ),
      ),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...forgedApprovalWire)) }),
    })

    // 4. Valid gateway gov.applied member_add updates participants & public keys
    const newcomer = generateIdentity()
    const govAppliedWire = serializeEnvelope(
      createMessage(
        relay.gateway,
        conv,
        'gov.applied',
        new TextEncoder().encode(
          JSON.stringify({
            type: 'gov.applied',
            proposal_id: 'prop-add-1',
            proposal_type: 'member_add',
            applied_at: new Date().toISOString(),
            applied_members: [
              {
                kid: base64UrlEncode(newcomer.keyID),
                public_key: base64UrlEncode(newcomer.publicKey),
              },
            ],
          }),
        ),
      ),
    )
    await relay.handleFetch('http://relay.test/v1/send', {
      body: JSON.stringify({ conv_id: conversationId, envelope_b64: btoa(String.fromCharCode(...govAppliedWire)) }),
    })

    const afterRes = await receiveMessages(alice.id, alice.name, conversationId)
    expect(afterRes.messages.some((m) => m.bodyType === 'gate.approval')).toBe(false)
    expect(afterRes.messages.some((m) => m.bodyType === 'gov.applied')).toBe(true)
    const updatedAliceConv = store.findConversation(alice.id, conversationId)!
    const newcomerKidHex = Array.from(newcomer.keyID, (b) => b.toString(16).padStart(2, '0')).join('')
    expect(updatedAliceConv.participants).toContain(newcomerKidHex)
  })
})
