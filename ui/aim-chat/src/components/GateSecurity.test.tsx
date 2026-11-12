import { createRef, useState } from 'react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { base64UrlEncode, generateIdentity } from '@corpollc/qntm'
import { GatePanel } from './GatePanel'
import { ChatPane } from './ChatPane'
import { GuidancePage } from './GuidancePage'
import { api } from '../api'
import * as store from '../store'
import * as guidance from '../guidance'
import type { ChatMessage, Conversation } from '../types'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('GatePanel P0-2 zero-extra-input origin binding UI', () => {
  function GatePanelHarness() {
    const [secretService, setSecretService] = useState('')
    const [secretValue, setSecretValue] = useState('sk-test-123')
    const [secretHeaderName, setSecretHeaderName] = useState('Authorization')
    const [secretHeaderTemplate, setSecretHeaderTemplate] = useState('Bearer {value}')
    return (
      <GatePanel
        gateStatus={{ promoted: true, threshold: 2, signerCount: 2 }}
        gateRecipes={[]}
        selectedRecipe=""
        activeRecipe={null}
        gateServerUrl="https://gateway.corpo.llc"
        setGateServerUrl={() => {}}
        gateArgs={{}}
        gatePromoteThreshold={2}
        setGatePromoteThreshold={() => {}}
        resolvedGateUrl=""
        participantKids={[]}
        secretService={secretService}
        setSecretService={setSecretService}
        secretValue={secretValue}
        setSecretValue={setSecretValue}
        secretHeaderName={secretHeaderName}
        setSecretHeaderName={setSecretHeaderName}
        secretHeaderTemplate={secretHeaderTemplate}
        setSecretHeaderTemplate={setSecretHeaderTemplate}
        isWorking={false}
        onRecipeChange={() => {}}
        onGateArgChange={() => {}}
        onGateRun={() => {}}
        onGatePromote={() => {}}
        onGateSecret={() => {}}
        onGovProposeFloorChange={() => {}}
        onGovProposeMemberAdd={() => {}}
        onGovProposeMemberRemove={() => {}}
      />
    )
  }

  it('uses zero extra inputs, renders resolved origin hint, auto-defaults headers, and disables submit on unknown services', async () => {
    render(<GatePanelHarness />)
    await userEvent.click(screen.getByText('API Keys'))

    // Exactly 4 inputs in API Keys form: service, header name, header template, secret value
    const inputs = document.querySelectorAll('#secret-service, #secret-header-name, #secret-header-template, #secret-value')
    expect(inputs).toHaveLength(4)
    expect(inputs[0].parentElement!.querySelectorAll('input')).toHaveLength(4)

    const serviceInput = screen.getByLabelText('Service or API host')
    const submitBtn = screen.getByRole('button', { name: 'Add API key' }) as HTMLButtonElement
    expect(submitBtn.disabled).toBe(true)

    await userEvent.type(serviceInput, 'demo')
    expect(submitBtn.disabled).toBe(true)
    expect(screen.getByText(/Enter a known service/i)).toBeTruthy()

    await userEvent.clear(serviceInput)
    await userEvent.type(serviceInput, 'anthropic')
    expect(screen.getByText('Sends key only to https://api.anthropic.com')).toBeTruthy()
    expect((screen.getByLabelText('Header name') as HTMLInputElement).value).toBe('x-api-key')
    expect((screen.getByLabelText('Header template') as HTMLInputElement).value).toBe('{value}')
    expect(submitBtn.disabled).toBe(false)
  })
})

describe('ChatPane P1-4a vote deduplication, withdrawal, and aged-out gate.promote threshold', () => {
  const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

  it('deduplicates duplicate peer approvals by signer_kid, honors gate.disapproval withdrawal, and preserves non-zero threshold without gate.promote', () => {
    const me = generateIdentity()
    const peer = generateIdentity()
    const gateway = generateIdentity()
    const meKidB64 = base64UrlEncode(me.keyID)
    const peerKidB64 = base64UrlEncode(peer.keyID)
    const peerKidHex = hex(peer.keyID)
    const meKidHex = hex(me.keyID)

    const conversation: Conversation = {
      id: 'aa'.repeat(16),
      name: 'Ops',
      type: 'group',
      participants: [meKidHex, peerKidHex],
      createdAt: new Date().toISOString(),
      gateway: {
        status: 'active',
        keyId: base64UrlEncode(gateway.keyID),
        floor: 2,
      },
    }

    const requestId = 'req-dedup-1'
    const baseRequest = {
      type: 'gate.request',
      request_id: requestId,
      service: 'github',
      endpoint: '/repos/acme/app',
      verb: 'GET',
      target_url: 'https://api.github.com/repos/acme/app',
      required_approvals: 2,
      eligible_signer_kids: [meKidB64, peerKidB64],
      signer_kid: peerKidB64,
      signature: 'c2ln',
    }
    const peerApproval = {
      type: 'gate.approval',
      request_id: requestId,
      signer_kid: peerKidB64,
      signature: 'c2ln',
    }

    // Notice NO gate.promote message in history (simulating >1,000-message age-out),
    // PLUS peer spams 3 duplicate gate.approval messages!
    const spamMessages: ChatMessage[] = [
      {
        id: 'm1',
        conversationId: conversation.id,
        direction: 'incoming',
        sender: 'Peer',
        senderKey: peerKidHex,
        bodyType: 'gate.request',
        text: JSON.stringify(baseRequest),
        createdAt: new Date().toISOString(),
      },
      ...['m2', 'm3', 'm4'].map((id) => ({
        id,
        conversationId: conversation.id,
        direction: 'incoming' as const,
        sender: 'Peer',
        senderKey: peerKidHex,
        bodyType: 'gate.approval',
        text: JSON.stringify(peerApproval),
        createdAt: new Date().toISOString(),
      })),
    ]

    const { rerender } = render(
      <ChatPane
        selectedConversation={conversation}
        messages={spamMessages}
        composer=""
        setComposer={() => {}}
        isWorking={false}
        isSending={false}
        isLoadingMessages={false}
        showGatePanel={false}
        setShowGatePanel={() => {}}
        messageTailRef={createRef<HTMLDivElement>()}
        onSendMessage={() => {}}
        onCheckMessages={() => {}}
        onGateApprove={() => {}}
        onGateDisapprove={() => {}}
        onGovApprove={() => {}}
        onGovDisapprove={() => {}}
        conversationCount={1}
        onOpenInvites={() => {}}
        onCopyInviteLink={() => {}}
      />,
    )

    // Approval count must remain 1 of 2 (NOT 4 of 2 or 4 of 0), keeping Approve & Deny buttons visible!
    expect(screen.getByText('(1 of 2 approvals)')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Approve' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Deny' })).toBeTruthy()

    // Peer sends gate.disapproval -> withdraws their prior approval (0 of 2 approvals)
    const withdrawnMessages: ChatMessage[] = [
      ...spamMessages,
      {
        id: 'm5',
        conversationId: conversation.id,
        direction: 'incoming',
        sender: 'Peer',
        senderKey: peerKidHex,
        bodyType: 'gate.disapproval',
        text: JSON.stringify({
          type: 'gate.disapproval',
          request_id: requestId,
          signer_kid: peerKidB64,
          signature: 'c2ln',
        }),
        createdAt: new Date().toISOString(),
      },
    ]

    rerender(
      <ChatPane
        selectedConversation={conversation}
        messages={withdrawnMessages}
        composer=""
        setComposer={() => {}}
        isWorking={false}
        isSending={false}
        isLoadingMessages={false}
        showGatePanel={false}
        setShowGatePanel={() => {}}
        messageTailRef={createRef<HTMLDivElement>()}
        onSendMessage={() => {}}
        onCheckMessages={() => {}}
        onGateApprove={() => {}}
        onGateDisapprove={() => {}}
        onGovApprove={() => {}}
        onGovDisapprove={() => {}}
        conversationCount={1}
        onOpenInvites={() => {}}
        onCopyInviteLink={() => {}}
      />,
    )
    expect(screen.getByText('(0 of 2 approvals)')).toBeTruthy()
    expect(screen.getByText('1 disapproval')).toBeTruthy()
  })
})

describe('GuidancePage P2-1c conversation refresh and open-conversation navigation', () => {
  it('notifies onConversationsChanged after sending guidance and passes conversationId to onOpenConversation', async () => {
    const data = new Map<string, string>()
    vi.stubGlobal('localStorage', {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => data.set(key, value),
      removeItem: (key: string) => data.delete(key),
      clear: () => data.clear(),
    })

    const profileId = api.createProfile('Operator').profile.id
    const convId = api.createInvite(profileId, 'Counsel Chat').conversationId
    const peerKid = 'cd'.repeat(16)
    store.updateConversation(profileId, convId, (c) => ({ ...c, participants: [...c.participants, peerKid] }))
    const contact = guidance.pinGuidanceContact(profileId, {
      category: 'legal',
      name: 'Counsel',
      kind: 'human',
      conversationId: convId,
      recipientKeyId: peerKid,
    })
    expect(contact.id).toBeTruthy()
    vi.spyOn(guidance, 'sendGuidance').mockResolvedValue({ conversationId: convId, id: 'msg-123' } as never)

    const onOpenConversation = vi.fn()
    const onConversationsChanged = vi.fn()

    render(
      <MemoryRouter>
        <GuidancePage
          profileId={profileId}
          profileName="Operator"
          onOpenConversation={onOpenConversation}
          onConversationsChanged={onConversationsChanged}
        />
      </MemoryRouter>,
    )

    await userEvent.click(screen.getByRole('radio', { name: /Counsel/i }))
    await userEvent.type(screen.getByLabelText('What do you need guidance on?'), 'Is this compliant?')
    await userEvent.click(screen.getByRole('button', { name: 'Review request' }))
    await userEvent.click(screen.getByRole('button', { name: 'Send guidance request' }))

    expect(onConversationsChanged).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Open conversation' }))
    expect(onOpenConversation).toHaveBeenCalledWith(convId)
  })
})
