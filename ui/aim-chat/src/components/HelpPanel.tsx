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
  { keys: [MOD, '/'], description: 'Show keyboard shortcuts' },
  { keys: ['?'], description: 'Show keyboard shortcuts (when not in input)' },
]

interface GlossaryEntry {
  term: string
  definition: string
}

const glossary: GlossaryEntry[] = [
  { term: 'Profile', definition: 'Your named account within qntm Messenger.' },
  { term: 'Key ID', definition: 'Your unique cryptographic identifier, derived from your keypair.' },
  { term: 'Public Key', definition: 'Shareable key that others use to encrypt messages to you.' },
  { term: 'Conversation', definition: 'An encrypted chat between two or more participants.' },
  { term: 'Invite Token', definition: 'A code you share with others so they can join your conversation.' },
  { term: 'API Gateway', definition: 'Group-approved API call system requiring multiple signers.' },
  { term: 'Required Approvals', definition: 'The number of signers who must approve a request before it executes.' },
  { term: 'API Template', definition: 'A pre-configured API endpoint pattern with method, URL, and parameters.' },
  { term: 'Message Relay', definition: 'Server that routes encrypted messages between participants.' },
]

export function HelpPanel() {
  return (
    <div className="help-page">
      <h2 className="panel-heading">Help</h2>

      <section className="help-section">
        <h3>Getting Started</h3>
        <ul className="help-bullets">
          <li>Generate a keypair in the Identities panel to create your cryptographic identity.</li>
          <li>Create a new conversation from the Invites panel and share the invite token with others.</li>
          <li>To join an existing conversation, paste an invite token and click Join.</li>
          <li>Select a conversation in the sidebar, then type a message and press Enter to send.</li>
          <li>Assign display names to contacts in the Contacts panel so you can recognize message senders.</li>
          <li>Use the API Gateway panel to submit group-approved API calls from within a conversation.</li>
        </ul>
      </section>

      <section className="help-section">
        <h3>Keyboard Shortcuts</h3>
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
      </section>

      <section className="help-section">
        <h3>Glossary</h3>
        <dl className="glossary-list">
          {glossary.map((entry) => (
            <div key={entry.term} className="glossary-item">
              <dt className="glossary-term">{entry.term}</dt>
              <dd className="glossary-definition">{entry.definition}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="help-section">
        <h3>Documentation</h3>
        <p className="help-links">
          Full documentation available at <code>docs/getting-started.md</code> and <code>docs/api-gateway.md</code>.
        </p>
      </section>
    </div>
  )
}
