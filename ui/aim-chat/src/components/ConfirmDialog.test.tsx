import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConfirmDialog } from './ConfirmDialog'

afterEach(() => cleanup())

describe('ConfirmDialog', () => {
  it('renders nothing when not open', () => {
    const { container } = render(
      <ConfirmDialog open={false} title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={vi.fn()} />
    )
    expect(container.innerHTML).toBe('')
  })

  it('renders title, message, and confirm label', () => {
    render(
      <ConfirmDialog open title="Delete?" message="Are you sure?" confirmLabel="Yes, delete" onConfirm={vi.fn()} onCancel={vi.fn()} />
    )
    expect(screen.getByText('Delete?')).toBeTruthy()
    expect(screen.getByText('Are you sure?')).toBeTruthy()
    expect(screen.getByText('Yes, delete')).toBeTruthy()
  })

  it('calls onConfirm when confirm clicked', async () => {
    const onConfirm = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={onConfirm} onCancel={vi.fn()} />
    )
    await userEvent.click(screen.getByText('OK'))
    expect(onConfirm).toHaveBeenCalledOnce()
  })

  it('calls onCancel when cancel clicked', async () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={onCancel} />
    )
    await userEvent.click(screen.getByText('Cancel'))
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it('calls onCancel on Escape key', async () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={onCancel} />
    )
    await userEvent.keyboard('{Escape}')
    expect(onCancel).toHaveBeenCalledOnce()
  })

  it('calls onCancel on backdrop click', async () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" confirmLabel="OK" onConfirm={vi.fn()} onCancel={onCancel} />
    )
    const overlay = screen.getByRole('dialog')
    await userEvent.click(overlay)
    expect(onCancel).toHaveBeenCalled()
  })
})
