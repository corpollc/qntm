import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { JoinModal } from './JoinModal'

afterEach(() => cleanup())

describe('JoinModal', () => {
  it('calls onJoin with typed name on submit', async () => {
    const onJoin = vi.fn()
    render(<JoinModal inviteToken="tok" isWorking={false} onJoin={onJoin} onCancel={vi.fn()} />)
    await userEvent.type(screen.getByPlaceholderText('e.g. Team Chat, Project Alpha'), 'My Chat')
    await userEvent.click(screen.getByRole('button', { name: 'Join' }))
    expect(onJoin).toHaveBeenCalledWith('My Chat')
  })

  it('calls onJoin with empty string when no name provided', async () => {
    const onJoin = vi.fn()
    render(<JoinModal inviteToken="tok" isWorking={false} onJoin={onJoin} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: 'Join' }))
    expect(onJoin).toHaveBeenCalledWith('')
  })

  it('calls onCancel on backdrop click', async () => {
    const onCancel = vi.fn()
    render(<JoinModal inviteToken="tok" isWorking={false} onJoin={vi.fn()} onCancel={onCancel} />)
    const backdrop = document.querySelector('.join-modal-backdrop')!
    await userEvent.click(backdrop)
    expect(onCancel).toHaveBeenCalled()
  })
})
