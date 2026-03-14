const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.userAgent)
const MOD = isMac ? '\u2318' : 'Ctrl'

interface Shortcut {
  keys: string[]
  description: string
}

const shortcuts: Shortcut[] = [
  { keys: [MOD, 'K'], description: 'Focus conversation search' },
  { keys: [MOD, ','], description: 'Toggle settings' },
  { keys: ['Escape'], description: 'Close panel / blur input' },
  { keys: [MOD, 'Shift', 'N'], description: 'New conversation' },
  { keys: ['Alt', '1\u20139'], description: 'Switch conversation' },
  { keys: [MOD, '/'], description: 'Show this help' },
  { keys: ['?'], description: 'Show this help (when not in input)' },
]

export interface ShortcutsHelpProps {
  onClose: () => void
}

export function ShortcutsHelp({ onClose }: ShortcutsHelpProps) {
  return (
    <div className="shortcuts-backdrop" onClick={onClose} role="dialog" aria-modal="true" aria-labelledby="shortcuts-dialog-title">
      <div className="shortcuts-card" onClick={(e) => e.stopPropagation()}>
        <div className="shortcuts-header">
          <h2 id="shortcuts-dialog-title">Keyboard Shortcuts</h2>
          <button className="shortcuts-close" type="button" onClick={onClose} aria-label="Close keyboard shortcuts">
            &times;
          </button>
        </div>
        <div className="shortcuts-grid">
          {shortcuts.map((s) => (
            <div key={s.description} className="shortcuts-row">
              <span className="shortcuts-keys">
                {s.keys.map((k, i) => (
                  <span key={i}>
                    {i > 0 && <span className="shortcuts-plus">+</span>}
                    <kbd>{k}</kbd>
                  </span>
                ))}
              </span>
              <span className="shortcuts-desc">{s.description}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
