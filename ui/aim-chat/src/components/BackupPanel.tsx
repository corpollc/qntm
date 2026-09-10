import { useState } from 'react'
import { MAX_BACKUP_BYTES, exportEncryptedBackup, prepareBackup, restoreBackup } from '../backup'
import type { BackupReview, BackupSummary } from '../backup'

export function BackupPanel({ setStatus, setError }: { setStatus: (s: string) => void; setError: (s: string) => void }) {
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [importPassword, setImportPassword] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [review, setReview] = useState<BackupReview | null>(null)
  const [trusted, setTrusted] = useState(false)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState('')
  const fail = (err: unknown) => {
    const message = err instanceof Error ? err.message : 'Backup operation failed.'
    setProblem(message); setError(message)
  }
  async function exportFile() {
    setBusy(true); setProblem(''); setError('')
    try {
      if (password !== confirmation) throw new Error('The backup passwords do not match.')
      const data = await exportEncryptedBackup(password)
      const url = URL.createObjectURL(new Blob([data], { type: 'application/json' }))
      const link = document.createElement('a')
      link.href = url; link.download = `qntm-backup-${new Date().toISOString().slice(0, 10)}.json`
      link.click(); URL.revokeObjectURL(url)
      setPassword(''); setConfirmation(''); setStatus('Encrypted backup exported')
    } catch (err) { fail(err) } finally { setBusy(false) }
  }
  async function reviewFile() {
    if (!file) return
    setBusy(true); setReview(null); setTrusted(false); setProblem(''); setError('')
    try {
      if (file.size > MAX_BACKUP_BYTES) throw new Error('Backup files must be at most 10 MiB.')
      const next = await prepareBackup(await file.text(), importPassword)
      setReview(next); setImportPassword('')
      setStatus('Backup validated. Review the replacement before restoring.')
    } catch (err) { fail(err) } finally { setBusy(false) }
  }
  function restore() {
    if (!review || !trusted) return
    try {
      restoreBackup(review)
      setReview(null); setFile(null); setImportPassword('')
      setStatus('Backup restored — reloading…')
      window.location.reload()
    } catch (err) { fail(err); setReview(null); setTrusted(false) }
  }
  return <div className="panel backup-panel">
    <h2>Backup &amp; Restore</h2>
    <p className="settings-description">Back up profiles, private keys, conversations, messages and guidance contacts. Downloads are encrypted with your password. Keep the password separately; it cannot be recovered.</p>
    <label className="label" htmlFor="backup-password">New backup password (at least 12 characters)</label>
    <input id="backup-password" className="input" type="password" autoComplete="new-password" maxLength={1024} value={password} onChange={e => setPassword(e.target.value)} disabled={busy} />
    <label className="label" htmlFor="backup-confirm">Confirm backup password</label>
    <input id="backup-confirm" className="input" type="password" autoComplete="new-password" maxLength={1024} value={confirmation} onChange={e => setConfirmation(e.target.value)} disabled={busy} />
    <div className="row"><button className="button" type="button" onClick={() => void exportFile()} disabled={busy || password.length < 12 || !confirmation}>Export encrypted backup</button></div>
    <hr className="settings-divider" />
    <h3>Restore a backup</h3>
    <p className="settings-description">Import only a trusted backup. Legacy JSON files contain unencrypted private keys. Restoring replaces this browser’s profiles, history, relay settings and contact destinations.</p>
    <label className="label" htmlFor="backup-file">Backup file (up to 10 MiB)</label>
    <input id="backup-file" className="input" type="file" accept=".json,application/json" disabled={busy} onChange={e => { setFile(e.target.files?.[0] ?? null); setReview(null); setTrusted(false); setProblem(''); setImportPassword('') }} />
    <label className="label" htmlFor="restore-password">Password for encrypted backup</label>
    <input id="restore-password" className="input" type="password" autoComplete="off" maxLength={1024} value={importPassword} onChange={e => setImportPassword(e.target.value)} disabled={busy} aria-describedby="restore-password-help" />
    <p id="restore-password-help" className="settings-description">Leave empty for a legacy unencrypted backup. The file is checked locally; nothing is uploaded.</p>
    <div className="row"><button className="button" type="button" disabled={busy || !file} onClick={() => void reviewFile()}>{busy ? 'Working…' : 'Review backup'}</button></div>
    {problem && <p role="alert" className="error-banner">{problem}</p>}
    {review && <section className="backup-review" aria-label="Backup replacement review">
      <h3>Review replacement</h3>
      <p>{review.encrypted ? 'Password-encrypted backup.' : 'Legacy unencrypted backup.'} Nothing has been replaced yet.</p>
      <table className="backup-counts"><thead><tr><th>Data</th><th>Current browser</th><th>After restore</th></tr></thead><tbody>
        <tr><th>Profiles</th><td>{review.current?.profiles.length ?? 'Unreadable'}</td><td>{review.incoming.profiles.length}</td></tr>
        <tr><th>Conversations</th><td>{review.current?.conversations ?? 'Unreadable'}</td><td>{review.incoming.conversations}</td></tr>
        <tr><th>Messages</th><td>{review.current?.messages ?? 'Unreadable'}</td><td>{review.incoming.messages}</td></tr>
        <tr><th>Contact pins</th><td>{review.current?.contactPins.length ?? 'Unreadable'}</td><td>{review.incoming.contactPins.length}</td></tr>
        <tr><th>Contact groups</th><td>{review.current?.contactGroups.length ?? 'Unreadable'}</td><td>{review.incoming.contactGroups.length}</td></tr>
        <tr><th>Guidance contacts</th><td>{review.current?.guidance.length ?? 'Unreadable'}</td><td>{review.incoming.guidance.length}</td></tr>
      </tbody></table>
      <p><strong>Current relay:</strong> {review.current?.relayUrl ?? 'Unreadable'}</p>
      <BackupDestinations data={review.incoming} />
      <label className="backup-trust"><input type="checkbox" checked={trusted} onChange={e => setTrusted(e.target.checked)} /> I trust this backup and understand that my current messaging data will be replaced.</label>
      <div className="row"><button className="button" type="button" onClick={() => { setReview(null); setTrusted(false) }}>Cancel restore</button><button className="confirm-btn-danger" type="button" disabled={!trusted || busy} onClick={restore}>Replace browser data</button></div>
    </section>}
  </div>
}

function BackupDestinations({ data }: { data: BackupSummary }) {
  return <div className="backup-destinations">
    <p><strong>Restored relay:</strong> {data.relayUrl}</p>
    <h4>Restored identities</h4>
    <ul>{data.profiles.map(p => <li key={p.id}>{p.name} — <code>{p.keyId ?? 'No identity'}</code></li>)}</ul>
    <h4>Restored contact pins</h4>
    {data.contactPins.length ? <ul>{data.contactPins.map((c, i) => <li key={i}>{c.profile}: {c.name}<br /><code>{c.publicKey}</code></li>)}</ul> : <p>None.</p>}
    <h4>Restored contact groups</h4>
    {data.contactGroups.length ? <ul>{data.contactGroups.map((c, i) => <li key={i}>{c.profile}: {c.name}<br />Relay {c.relayUrl}{c.removed && ' · Removed'}{c.recovery && ' · Recovery required'}</li>)}</ul> : <p>None.</p>}
    <h4>Restored guidance destinations</h4>
    {data.guidance.length ? <ul>{data.guidance.map((c, i) => <li key={i}><strong>{c.profile}: {c.name}</strong> ({c.category})<br />Recipient <code>{c.recipientKeyId}</code><br />Conversation <code>{c.conversationId}</code><br />Relay {c.relayUrl}</li>)}</ul> : <p>None.</p>}
    <h4>Restored gateways</h4>
    {data.gateways.length ? <ul>{data.gateways.map((g, i) => <li key={i}>{g.profile}: <code>{g.keyId}</code> ({g.status})<br />Conversation <code>{g.conversationId}</code>{g.url && <><br />Endpoint {g.url}</>}</li>)}</ul> : <p>None.</p>}
  </div>
}
