import { useState } from 'react'
import { changeContactGroup, createContactGroup, pinContact, publicGroupLink, retryContactGroup, releaseContactGroupRetry } from '../contact-groups'
import * as store from '../store'
import { base64UrlDecode, parseGroupGenesisBody } from '@corpollc/qntm'
import { shortId } from '../utils'

export function ContactGroupPanel({ profileId, conversationId, onChange }: { profileId: string; conversationId: string; onChange: (id?: string) => void }) {
  const [name, setName] = useState(''), [publicKey, setPublicKey] = useState(''), [verified, setVerified] = useState(false)
  const [groupName, setGroupName] = useState(''), [selected, setSelected] = useState(''), [challenge, setChallenge] = useState('')
  const [working, setWorking] = useState(false), [error, setError] = useState(''), [link, setLink] = useState(''), [notice, setNotice] = useState('')
  const [releaseUnderstood, setReleaseUnderstood] = useState(false)
  const pins = store.listContactPins(profileId), conversation = store.findConversation(profileId, conversationId), host = conversation?.group
  const blocked = !!host && (host.session.removed || !!host.session.recovery || !!host.operation)
  async function run(action: () => Promise<void> | void) {
    setWorking(true); setError(''); setNotice('')
    try { await action(); onChange() } catch (e) { setError(e instanceof Error ? e.message : String(e)); onChange() } finally { setWorking(false) }
  }
  const contact = pins.find(pin => pin.key === selected)
  const creator = host ? Array.from(parseGroupGenesisBody(base64UrlDecode(host.session.snapshot)).founding_members[0].key_id, b => b.toString(16).padStart(2, '0')).join('') : ''
  const member = !!host?.session && conversation!.participants.includes(selected)
  return <section className="contact-groups" aria-label="Contact groups">
    <h3>Verified contacts</h3>
    <p>Pin a contact’s full public key after checking it with them. Names from messages are display labels only.</p>
    <form onSubmit={event => { event.preventDefault(); void run(() => { pinContact(profileId, name, publicKey); setName(''); setPublicKey(''); setVerified(false); setNotice('Contact pinned') }) }}>
      <label>Contact name<input className="input" value={name} onChange={e => setName(e.target.value)} required /></label>
      <label>Full public key<input className="input" value={publicKey} onChange={e => { setPublicKey(e.target.value); setVerified(false) }} required spellCheck={false} /></label>
      <label className="contact-verification"><input type="checkbox" checked={verified} onChange={e => setVerified(e.target.checked)} /> I checked this key with the contact</label>
      <button className="button" disabled={!profileId || working || !verified}>Pin contact</button>
    </form>
    <h3>Create a contact group</h3>
    <form onSubmit={event => { event.preventDefault(); void run(async () => { const id = await createContactGroup(profileId, groupName); setGroupName(''); setLink(''); onChange(id); setNotice('Group created. Select a pinned contact to add them.') }) }}>
      <label>Group name<input className="input" value={groupName} onChange={e => setGroupName(e.target.value)} required /></label>
      <button className="button" disabled={!profileId || working}>Create contact group</button>
    </form>
    {!!pins.length && <><label>Pinned contact<select className="input" aria-label="Pinned contact" value={selected} onChange={e => { setSelected(e.target.value); setLink('') }}>
      <option value="">Choose a contact</option>{pins.map(pin => <option key={pin.key} value={pin.key}>{pin.name}</option>)}
    </select></label>
      {contact && <><code className="contact-full-key">{contact.publicKey}</code><button className="button button-secondary" disabled={working} onClick={() => void run(() => { store.removeContactPin(profileId, contact.key); setSelected(''); setNotice('Contact pin removed; group membership is unchanged.') })}>Remove contact pin</button></>}
    </>}
    {host ? <div className="contact-group-actions">
      <h3>{conversation!.name}</h3>
      <p>{conversation!.participants.length} members · key epoch {host.session.epoch}</p>
      <ul className="contact-group-roster" aria-label="Group members">{conversation!.participants.map(key => <li key={key} title={key}>{pins.find(pin => pin.key === key)?.name || shortId(key)}{key === creator ? ' (creator)' : ''}</li>)}</ul>
      {host.session.removed && <p role="status">You were removed from this group. New messages and membership changes are disabled.</p>}
      {host.session.recovery && <div role="status"><strong>Group recovery required</strong><p>Ask a current member to refresh your welcome with this challenge, then open their returned group link.</p><code className="contact-full-key">{host.session.recovery.challenge}</code><button className="button" onClick={() => void run(async () => { await navigator.clipboard.writeText(host.session.recovery!.challenge); setNotice('Recovery challenge copied') })}>Copy recovery challenge</button></div>}
      {host.operation && <><p>A group operation is saved. Retry checks delivery progress. An already admitted contact may receive a new welcome with current keys.</p><button className="button" disabled={working || ((!!host.session.recovery || host.session.removed) && !(host.operation.welcomes.length > 0 && host.operation.delivered === host.operation.welcomes.length))} onClick={() => void run(async () => { setLink(await retryContactGroup(profileId, conversationId)); setNotice('Saved operation completed') })}>Retry saved operation</button></>}
      {host.operation && (host.operation.kind === 'remove' || host.operation.kind === 'removal_rekey') && <div className="contact-group-release">
        <p>If this saved removal was never verified in replay and can no longer be retried exactly, you can release the local retry. Release checks the relay again first. It stops only this browser’s retry, keeps the uncertain encrypted controls as private evidence, does not undo anything already delivered, and does not change membership. Nothing is sent. Remove the contact again later if you still want them out.</p>
        <label className="contact-verification"><input type="checkbox" checked={releaseUnderstood} onChange={e => setReleaseUnderstood(e.target.checked)} /> I understand this only stops the local retry</label>
        <button className="button button-secondary" disabled={working || !releaseUnderstood} onClick={() => void run(async () => { const result = await releaseContactGroupRetry(profileId, conversationId); setReleaseUnderstood(false); setNotice(`Local retry released (${result.reason.replace(/_/g, ' ')}). The saved removal was never verified; membership is unchanged and its ciphertext is kept privately.`) })}>Release saved retry</button>
      </div>}
      {host.session.needsRekey && <button className="button" disabled={working || blocked} onClick={() => void run(async () => { await changeContactGroup(profileId, conversationId, 'rekey'); setNotice('Group keys rotated') })}>Finish key rotation</button>}
      <label>Recipient recovery challenge (optional)<input className="input" value={challenge} onChange={e => setChallenge(e.target.value)} placeholder="64 hexadecimal characters" spellCheck={false} /></label>
      <div className="contact-action-buttons">
        <button className="button" disabled={working || blocked || host.session.needsRekey || !contact || member} onClick={() => void run(async () => { setLink(await changeContactGroup(profileId, conversationId, 'add', selected, challenge)); setNotice(`${contact!.name} added. Share the group link with them.`) })}>Add to group</button>
        <button className="button" disabled={working || blocked || host.session.needsRekey || !contact || !member} onClick={() => void run(async () => { setLink(await changeContactGroup(profileId, conversationId, 'refresh', selected, challenge)); setNotice('Current welcome sent. Membership is unchanged.') })}>Refresh welcome</button>
        <button className="button button-danger" disabled={working || blocked || host.session.needsRekey || !contact || !member || selected === creator} title={selected === creator ? 'The group creator cannot be removed' : undefined} onClick={() => void run(async () => { await changeContactGroup(profileId, conversationId, 'remove', selected); setLink(''); setNotice(`${contact!.name} removed and keys rotated`) })}>Remove from group</button>
        <button className="button" disabled={working || blocked} onClick={() => void run(() => { setLink(publicGroupLink(profileId, conversationId)) })}>Show public group link</button>
      </div>
      <p>Adding a contact grants membership and sends new keys only to that identity. Share your link after adding them. The link contains no group keys and has no expiry.</p>
    </div> : conversation && <p>{conversation.gateway ? 'This conversation uses gateway governance for membership.' : 'This conversation uses legacy invites. Create a contact group for verified-contact additions.'}</p>}
    {link && <div><label>Public group link<textarea className="input" aria-label="Public group link" readOnly value={link} rows={3} /></label><button className="button" onClick={() => void run(async () => { await navigator.clipboard.writeText(link); setNotice('Public group link copied') })}>Copy public group link</button></div>}
    {notice && <p role="status">{notice}</p>}{error && <p role="alert" className="error">{error}</p>}
  </section>
}
