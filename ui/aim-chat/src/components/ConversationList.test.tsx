import { describe, it, expect, vi } from 'vitest'
import { render, screen, within, cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'
import userEvent from '@testing-library/user-event'
import { ConversationList } from './ConversationList'
import type { ConversationListProps } from './ConversationList'
import type { Conversation } from '../types'

afterEach(() => cleanup())

function makeConversation(id: string, name: string): Conversation {
  return { id, name, type: 'direct', participants: [], createdAt: new Date().toISOString() }
}

function makeProps(overrides?: Partial<ConversationListProps>): ConversationListProps {
  return {
    visibleConversations: [
      makeConversation('conv-1', 'Alpha'),
      makeConversation('conv-2', 'Beta'),
    ],
    selectedConversationId: '',
    setSelectedConversationId: vi.fn(),
    hiddenConversations: new Set(),
    unreadCounts: {},
    hiddenCount: 0,
    showHidden: false,
    setShowHidden: vi.fn(),
    toggleHideConversation: vi.fn(),
    conversationFilter: '',
    setConversationFilter: vi.fn(),
    onRenameConversation: vi.fn(),
    onDeleteConversation: vi.fn(),
    ...overrides,
  }
}

describe('ConversationList rename', () => {
  it('renders conversation names', () => {
    render(<ConversationList {...makeProps()} />)
    expect(screen.getByText('Alpha')).toBeTruthy()
    expect(screen.getByText('Beta')).toBeTruthy()
  })

  it('enters edit mode on edit button click', async () => {
    render(<ConversationList {...makeProps()} />)
    const editButtons = screen.getAllByLabelText('Rename conversation')
    await userEvent.click(editButtons[0])
    expect(screen.getByDisplayValue('Alpha')).toBeTruthy()
  })

  it('saves new name on Enter', async () => {
    const onRenameConversation = vi.fn()
    render(<ConversationList {...makeProps({ onRenameConversation })} />)
    await userEvent.click(screen.getAllByLabelText('Rename conversation')[0])
    const input = screen.getByDisplayValue('Alpha')
    await userEvent.clear(input)
    await userEvent.type(input, 'Renamed{Enter}')
    expect(onRenameConversation).toHaveBeenCalledWith('conv-1', 'Renamed')
  })

  it('cancels edit on Escape', async () => {
    const onRenameConversation = vi.fn()
    render(<ConversationList {...makeProps({ onRenameConversation })} />)
    await userEvent.click(screen.getAllByLabelText('Rename conversation')[0])
    const input = screen.getByDisplayValue('Alpha')
    await userEvent.clear(input)
    await userEvent.type(input, 'Changed{Escape}')
    expect(onRenameConversation).not.toHaveBeenCalled()
    expect(screen.getByText('Alpha')).toBeTruthy()
  })

  it('rejects empty name', async () => {
    const onRenameConversation = vi.fn()
    render(<ConversationList {...makeProps({ onRenameConversation })} />)
    await userEvent.click(screen.getAllByLabelText('Rename conversation')[0])
    const input = screen.getByDisplayValue('Alpha')
    await userEvent.clear(input)
    await userEvent.type(input, '{Enter}')
    expect(onRenameConversation).not.toHaveBeenCalled()
  })
})

describe('ConversationList delete', () => {
  it('calls onDeleteConversation when delete button clicked', async () => {
    const onDeleteConversation = vi.fn()
    render(<ConversationList {...makeProps({ onDeleteConversation })} />)
    const deleteButtons = screen.getAllByLabelText('Delete conversation')
    await userEvent.click(deleteButtons[0])
    expect(onDeleteConversation).toHaveBeenCalledWith('conv-1')
  })

  it('does not call onDeleteConversation for a different conversation', async () => {
    const onDeleteConversation = vi.fn()
    render(<ConversationList {...makeProps({ onDeleteConversation })} />)
    const deleteButtons = screen.getAllByLabelText('Delete conversation')
    await userEvent.click(deleteButtons[1])
    expect(onDeleteConversation).toHaveBeenCalledWith('conv-2')
  })
})
