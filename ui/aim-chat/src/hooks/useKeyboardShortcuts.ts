import { useEffect } from 'react'

export interface KeyboardShortcutActions {
  focusConversationFilter: () => void
  toggleSettings: () => void
  closeOverlay: () => void
  focusNewConversation: () => void
  switchConversation: (index: number) => void
  toggleShortcutsHelp: () => void
}

function isInputFocused(): boolean {
  const tag = document.activeElement?.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT'
}

export function useKeyboardShortcuts(actions: KeyboardShortcutActions) {
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const mod = e.metaKey || e.ctrlKey

      // Cmd/Ctrl + K — Focus conversation filter
      if (mod && e.key === 'k') {
        e.preventDefault()
        actions.focusConversationFilter()
        return
      }

      // Cmd/Ctrl + , — Toggle settings
      if (mod && e.key === ',') {
        e.preventDefault()
        actions.toggleSettings()
        return
      }

      // Cmd/Ctrl + Shift + N — Focus new conversation input
      if (mod && e.shiftKey && (e.key === 'N' || e.key === 'n')) {
        e.preventDefault()
        actions.focusNewConversation()
        return
      }

      // Cmd/Ctrl + / — Toggle shortcuts help
      if (mod && e.key === '/') {
        e.preventDefault()
        actions.toggleShortcutsHelp()
        return
      }

      // Escape — Close overlays or blur input
      if (e.key === 'Escape') {
        actions.closeOverlay()
        if (isInputFocused()) {
          ;(document.activeElement as HTMLElement)?.blur()
        }
        return
      }

      // Shortcuts below only fire when not in an input
      if (isInputFocused()) return

      // ? — Toggle shortcuts help (when not in an input)
      if (e.key === '?' && !mod) {
        e.preventDefault()
        actions.toggleShortcutsHelp()
        return
      }

      // Alt/Option + 1-9 — Switch conversation by number
      if (e.altKey && e.key >= '1' && e.key <= '9') {
        e.preventDefault()
        actions.switchConversation(parseInt(e.key, 10) - 1)
        return
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [actions])
}
