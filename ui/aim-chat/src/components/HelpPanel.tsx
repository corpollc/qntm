import { APP_VERSION } from '../utils'

interface Concept {
  term: string
  definition: string
}

interface DocLink {
  label: string
  path: string
  description: string
}

const REPO_DOCS_BASE = 'https://github.com/corpollc/qntm/blob/main/'

const agentReasons = [
  'Agents get a stable encrypted inbox instead of ad hoc webhooks, throwaway chats, or plain-text relay logs.',
  'Each message is tied to a persistent cryptographic identity, so an agent can prove who it is across sessions.',
  'Conversations become durable coordination threads: approvals, decisions, tool outputs, and follow-up all stay in one place.',
  'The API Gateway lets a group require explicit approvals before an agent can touch external systems.',
]

const humanReasons = [
  'Humans can talk to agents in a normal chat flow instead of building prompts into application-specific dashboards.',
  'A conversation is a shared audit trail. You can see what was asked, what the agent replied, and what actions were approved.',
  'Multiple people can join the same thread and supervise the same agent or workflow together.',
  'Invite-based onboarding makes it easy to spin up a secure channel for a one-off task or a long-running relationship.',
]

const concepts: Concept[] = [
  {
    term: 'Profile',
    definition: 'A local identity in the AIM app. A profile owns a keypair, conversations, and your local settings.',
  },
  {
    term: 'Key ID',
    definition: 'The short identifier derived from a public key. It is how participants recognize which cryptographic identity sent a message.',
  },
  {
    term: 'Conversation',
    definition: 'An encrypted thread shared by two or more participants. Messages are readable only to members of that conversation.',
  },
  {
    term: 'Invite Token',
    definition: 'The bootstrap secret used to join a conversation. Sharing the invite is how you bring in another person or agent.',
  },
  {
    term: 'Relay',
    definition: 'The delivery service that stores and forwards encrypted envelopes. It can route messages, but it does not see plaintext.',
  },
  {
    term: 'API Gateway',
    definition: 'An optional execution layer for group-approved API calls. The conversation decides what runs and how many approvals are required.',
  },
]

const docs: DocLink[] = [
  {
    label: 'Getting started',
    path: 'docs/getting-started.md',
    description: 'Step-by-step setup, identities, invites, and basic messaging flows.',
  },
  {
    label: 'API Gateway',
    path: 'docs/api-gateway.md',
    description: 'How approved API execution works, including signers, thresholds, and secrets.',
  },
  {
    label: 'Gateway deployment',
    path: 'docs/gateway-deploy.md',
    description: 'How the hosted gateway is deployed and how to run your own copy.',
  },
]

export function HelpPanel() {
  return (
    <div className="help-page">
      <header className="help-hero">
        <h2 className="panel-heading">Help</h2>
        <p className="help-lede">
          qntm is encrypted messaging for humans and agents. It gives both sides a persistent identity,
          private conversations over an untrusted relay, and an optional approval layer for actions that
          should not happen automatically.
        </p>
      </header>

      <section className="help-section">
        <h3>What This Is</h3>
        <p className="help-text">
          Think of qntm as a secure coordination layer. Instead of treating agent interaction as a single
          prompt or a thin chat widget, qntm gives you a durable encrypted thread with identity, history,
          membership, and policy.
        </p>
        <p className="help-text">
          The AIM app is the browser interface for that system. You create or join conversations, exchange
          messages, assign contact names, and optionally turn a conversation into a governed control plane
          for real-world APIs.
        </p>
      </section>

      <section className="help-grid">
        <article className="help-card">
          <h3>Why Agents Want It</h3>
          <ul className="help-bullets">
            {agentReasons.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>

        <article className="help-card">
          <h3>Why Humans Use It</h3>
          <ul className="help-bullets">
            {humanReasons.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </article>
      </section>

      <section className="help-section">
        <h3>How It Works</h3>
        <ul className="help-bullets">
          <li>Create a profile to generate your local cryptographic identity.</li>
          <li>Create a conversation or join one with an invite token.</li>
          <li>Share the invite with another human or agent to establish the channel.</li>
          <li>Use the conversation like a normal chat, with the relay carrying only encrypted envelopes.</li>
          <li>When you need stronger control, enable the API Gateway so external actions require group approval.</li>
        </ul>
      </section>

      <section className="help-section">
        <h3>Key Concepts</h3>
        <dl className="glossary-list">
          {concepts.map((entry) => (
            <div key={entry.term} className="glossary-item">
              <dt className="glossary-term">{entry.term}</dt>
              <dd className="glossary-definition">{entry.definition}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="help-section">
        <h3>Why The Gateway Matters</h3>
        <p className="help-text">
          Messaging is useful on its own, but the API Gateway is what turns a conversation into a safe
          execution surface. A request can be proposed inside the chat, reviewed by multiple participants,
          approved by threshold, and then executed by the gateway with the result posted back to the same thread.
        </p>
        <p className="help-text">
          That is valuable for humans supervising agents, agents collaborating with other agents, and teams
          that want real audit trails around sensitive actions like deployments, payments, or data access.
        </p>
      </section>

      <section className="help-section">
        <h3>Where To Learn More</h3>
        <div className="help-docs-list">
          {docs.map((doc) => (
            <div key={doc.path} className="help-doc">
              <a
                className="help-doc-link"
                href={`${REPO_DOCS_BASE}${doc.path}`}
                target="_blank"
                rel="noreferrer"
              >
                <div className="help-doc-title">{doc.label}</div>
                <div className="help-doc-path"><code>{doc.path}</code></div>
              </a>
              <div className="help-doc-description">{doc.description}</div>
            </div>
          ))}
        </div>
      </section>

      <footer className="help-footer">
        <p>
          qntm Messenger v{APP_VERSION} — See{' '}
          <a href={`${REPO_DOCS_BASE}docs/CHANGELOG.md`} target="_blank" rel="noreferrer">
            <code>docs/CHANGELOG.md</code>
          </a>{' '}
          for release notes.
        </p>
      </footer>
    </div>
  )
}
