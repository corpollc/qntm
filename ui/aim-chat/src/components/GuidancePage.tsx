import { FormEvent, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { GUIDANCE_CATEGORIES, pinGuidanceContact, prepareGuidance, sendGuidance } from '../guidance'
import type { GuidanceCategory, GuidanceContact, GuidanceDraft } from '../guidance'
import * as store from '../store'

export function GuidancePage({ profileId, profileName, onOpenConversation }: {
  profileId: string
  profileName: string
  onOpenConversation: (id: string) => void
}) {
  const [contacts, setContacts] = useState(() => store.listGuidanceContacts(profileId))
  const [category, setCategory] = useState<GuidanceCategory>('legal')
  const [contactId, setContactId] = useState('')
  const [adding, setAdding] = useState(false)
  const [name, setName] = useState('')
  const [kind, setKind] = useState<GuidanceContact['kind']>('human')
  const [conversationId, setConversationId] = useState('')
  const [recipientKeyId, setRecipientKeyId] = useState('')
  const [question, setQuestion] = useState('')
  const [context, setContext] = useState('')
  const [draft, setDraft] = useState<GuidanceDraft | null>(null)
  const [error, setError] = useState('')
  const [sent, setSent] = useState<{ conversationId: string; messageId: string } | null>(null)
  const [sending, setSending] = useState(false)
  const sendingRef = useRef(false)
  const reviewRef = useRef<HTMLElement>(null)
  const conversations = store.listConversations(profileId)
  const choices = contacts.filter(c => c.category === category)
  const selected = choices.find(c => c.id === contactId)
  const selectedConv = conversations.find(c => c.id === conversationId)
  const self = store.getIdentity(profileId)?.keyId

  function fail(err: unknown) { setError(err instanceof Error ? err.message : 'The guidance request failed.') }
  function pin(event: FormEvent) {
    event.preventDefault()
    try {
      const contact = pinGuidanceContact(profileId, { category, name, kind, conversationId, recipientKeyId })
      setContacts(store.listGuidanceContacts(profileId))
      setContactId(contact.id)
      setAdding(false)
      setName('')
      setError('')
      setDraft(null)
    } catch (err) { fail(err) }
  }

  function review(event: FormEvent) {
    event.preventDefault()
    try {
      setDraft(prepareGuidance(profileId, contactId, question, context))
      setError('')
      setSent(null)
      requestAnimationFrame(() => reviewRef.current?.focus())
    } catch (err) { fail(err) }
  }

  async function send() {
    if (!draft || sendingRef.current) return
    sendingRef.current = true
    setSending(true)
    try {
      const message = await sendGuidance(draft, profileName)
      setSent({ conversationId: draft.contact.conversationId, messageId: message.id })
      setDraft(null)
      setQuestion('')
      setContext('')
      setError('')
    } catch (err) { fail(err); setDraft(null) }
    finally { sendingRef.current = false; setSending(false) }
  }

  return <main id="chat-pane" className="guidance-page" aria-labelledby="guidance-title">
    <header className="guidance-header">
      <div>
        <div className="guidance-eyebrow">A second perspective</div>
        <h1 id="guidance-title">Request guidance</h1>
        <p>Ask a person, an agent, or an organization you choose. Only the question and context you enter will be sent.</p>
      </div>
      <Link className="button" to="/">Back to conversations</Link>
    </header>
    <p className="guidance-note">Contacts are pinned locally for {profileName || 'this profile'}. A category does not verify credentials or authority. This is not an emergency service.</p>

    <div className="guidance-categories" aria-label="Guidance categories">
      {GUIDANCE_CATEGORIES.map(c => <button type="button" key={c.id}
        className={`guidance-category${category === c.id ? ' selected' : ''}`}
        aria-pressed={category === c.id} disabled={sending}
        onClick={() => { setCategory(c.id); setContactId(''); setDraft(null); setError(''); setAdding(false); setSent(null) }}>
        <strong>{c.label}</strong><span>{c.description}</span>
        <small>{contacts.filter(p => p.category === c.id).length} pinned {contacts.filter(p => p.category === c.id).length === 1 ? 'contact' : 'contacts'}</small>
      </button>)}
    </div>

    {!profileId ? <p>Create a profile in <Link to="/">conversations</Link> to pin guidance contacts.</p> : <div className="guidance-columns">
      <section className="panel guidance-panel" aria-labelledby="guidance-contacts-title">
        <h2 id="guidance-contacts-title">Pinned contacts</h2>
        {choices.length === 0 && <div className="guidance-empty">
          <strong>No contact pinned yet</strong>
          <p>Join a conversation with your chosen contact, then pin their full key ID here. No requests are routed until you configure a contact.</p>
          <Link to="/">Go to conversations</Link>
        </div>}
        {choices.map(c => <div key={c.id} className="guidance-contact">
          <label><input type="radio" name="guidance-contact" value={c.id} checked={contactId === c.id} disabled={sending}
            onChange={() => { setContactId(c.id); setDraft(null); setError(''); setSent(null) }} /> <strong>{c.name}</strong> · {c.kind}</label>
          <code>{c.recipientKeyId}</code>
          <span>Conversation: {conversations.find(conv => conv.id === c.conversationId)?.name || c.conversationId}</span>
          <button className="button" type="button" disabled={sending} onClick={() => {
            store.removeGuidanceContact(profileId, c.id)
            setContacts(store.listGuidanceContacts(profileId))
            setDraft(null)
            if (contactId === c.id) setContactId('')
          }} aria-label={`Unpin ${c.name}`}>Unpin</button>
        </div>)}
        <button className="button" type="button" disabled={sending} onClick={() => { setAdding(!adding); setDraft(null) }}>
          {adding ? 'Cancel pin' : 'Pin a contact'}
        </button>
        {adding && <form onSubmit={pin} className="guidance-form">
          <label htmlFor="guidance-name">Contact name</label>
          <input className="input" id="guidance-name" value={name} maxLength={120} required onChange={e => setName(e.target.value)} />
          <label htmlFor="guidance-kind">Contact type (self-declared)</label>
          <select className="input" id="guidance-kind" value={kind} onChange={e => setKind(e.target.value as GuidanceContact['kind'])}>
            <option value="human">Human</option><option value="agent">Agent</option><option value="organization">Organization</option>
          </select>
          <label htmlFor="guidance-conversation">Conversation</label>
          <select className="input" id="guidance-conversation" required value={conversationId} onChange={e => { setConversationId(e.target.value); setRecipientKeyId('') }}>
            <option value="">Choose a conversation</option>
            {conversations.map(c => <option key={c.id} value={c.id}>{c.name || c.id} · {c.id}</option>)}
          </select>
          <label htmlFor="guidance-recipient">Recipient key ID</label>
          <select className="input" id="guidance-recipient" required value={recipientKeyId} onChange={e => setRecipientKeyId(e.target.value)}>
            <option value="">Choose a known participant</option>
            {(selectedConv?.participants || []).filter(key => key !== self).map(key => <option key={key} value={key}>{store.resolveContactAlias(profileId, key) || 'Participant'} · {key}</option>)}
          </select>
          <p className="guidance-note">Verify this key with the contact through a trusted channel. Names and contact types are local labels.</p>
          <button className="button primary" type="submit">Save pin</button>
        </form>}
      </section>

      <section className="panel guidance-panel" aria-labelledby="guidance-question-title">
        <h2 id="guidance-question-title">Your question</h2>
        <form className="guidance-form" onSubmit={review}>
          <fieldset disabled={!selected || sending || !!draft}>
            <label htmlFor="guidance-question">What do you need guidance on?</label>
            <textarea className="input" id="guidance-question" rows={4} required maxLength={4000} value={question} onChange={e => setQuestion(e.target.value)} placeholder="Describe the decision and what is uncertain." />
            <label htmlFor="guidance-context">Context to share (optional)</label>
            <textarea className="input" id="guidance-context" rows={4} maxLength={8000} value={context} onChange={e => setContext(e.target.value)} placeholder="Include only what the contact needs to understand the question." />
            <p className="guidance-note">No transcript, credentials, invite tokens, or attachments are added automatically. Remove secrets and unnecessary personal data.</p>
            <button className="button primary" type="submit" disabled={!question.trim()}>Review request</button>
          </fieldset>
        </form>
        {!selected && <p className="guidance-note">Select a pinned contact to prepare a request.</p>}

        {draft && <section className="guidance-review" ref={reviewRef} tabIndex={-1} aria-labelledby="guidance-review-title">
          <h2 id="guidance-review-title">Review before sending</h2>
          <dl>
            <dt>Recipient</dt><dd>{draft.contact.name} · {draft.contact.kind}<code>{draft.contact.recipientKeyId}</code></dd>
            <dt>From</dt><dd>{profileName}<code>{draft.senderKeyId}</code></dd>
            <dt>Conversation</dt><dd>{draft.conversationName}<code>{draft.contact.conversationId}</code></dd>
            <dt>Relay</dt><dd>{draft.contact.relayUrl}</dd>
            <dt>Known participants ({draft.audience.length})</dt><dd>{draft.audience.map(key => <code key={key}>{key}</code>)}</dd>
          </dl>
          <p className="guidance-note">Everyone with this conversation’s keys can read the request, including invite holders{draft.gateway ? ' and the gateway' : ''}. It is not a private message to one participant.</p>
          <h3>Exact message</h3><pre>{draft.text}</pre>
          <p className="guidance-note">Sending requests advice. It does not authorize an action, file a formal report, or guarantee a response.</p>
          <div className="row">
            <button className="button" type="button" disabled={sending} onClick={() => setDraft(null)}>Edit request</button>
            <button className="button primary" type="button" disabled={sending} onClick={() => void send()}>{sending ? 'Sending…' : 'Send guidance request'}</button>
          </div>
        </section>}
        {sent && <div className="guidance-success" role="status">
          <strong>Request sent to the relay</strong>
          <p>Delivery and a response are not confirmed. Replies will appear in the conversation.</p>
          <code>Message: {sent.messageId}</code>
          <button className="button" type="button" onClick={() => onOpenConversation(sent.conversationId)}>Open conversation</button>
        </div>}
        {error && <p className="error-banner" role="alert">{error}</p>}
      </section>
    </div>}
    <p className="guidance-note">For agents: use <code>qntm guidance list</code> or the MCP <code>guidance_contacts</code> tool. Browser and CLI pins use separate local stores.</p>
  </main>
}
