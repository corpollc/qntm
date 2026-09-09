import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { InvitePanel } from './InvitePanel'
import type { InvitePanelProps } from './InvitePanel'

function makeProps(overrides?: Partial<InvitePanelProps>): InvitePanelProps {
  return {
    inviteToken: '',
    setInviteToken: vi.fn(),
    createdInviteToken: '',
    identity: { exists: true, publicKey: 'pk', keyId: 'kid' },
    isWorking: false,
    onCreateInvite: vi.fn(),
    onAcceptInvite: vi.fn(),
    ...overrides,
  }
}

afterEach(() => {
  cleanup()
})

describe('InvitePanel', () => {
  it('passes the typed name to onCreateInvite', async () => {
    const onCreateInvite = vi.fn()
    render(<InvitePanel {...makeProps({ onCreateInvite })} />)

    const nameInput = screen.getByPlaceholderText('Name your conversation')
    await userEvent.clear(nameInput)
    await userEvent.type(nameInput, 'My Group')
    await userEvent.click(screen.getByRole('button', { name: 'Create' }))

    expect(onCreateInvite).toHaveBeenCalledWith('My Group')
  })

  it('passes the typed label to onAcceptInvite', async () => {
    const onAcceptInvite = vi.fn()
    render(<InvitePanel {...makeProps({
      onAcceptInvite,
      inviteToken: 'some-token',
    })} />)

    const labelInput = screen.getByPlaceholderText('Label for this conversation (optional)')
    await userEvent.clear(labelInput)
    await userEvent.type(labelInput, 'Work Chat')
    await userEvent.click(screen.getByRole('button', { name: 'Join' }))

    expect(onAcceptInvite).toHaveBeenCalledWith('Work Chat')
  })

  it('passes empty string when no label is provided for join', async () => {
    const onAcceptInvite = vi.fn()
    render(<InvitePanel {...makeProps({
      onAcceptInvite,
      inviteToken: 'some-token',
    })} />)

    await userEvent.click(screen.getByRole('button', { name: 'Join' }))

    expect(onAcceptInvite).toHaveBeenCalledWith('')
  })
})
