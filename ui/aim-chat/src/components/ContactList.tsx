import { shortId } from '../utils'

export interface ContactListProps {
  visibleContactKeys: string[]
  contactDrafts: Record<string, string>
  contactNameByKey: Record<string, string>
  isWorking: boolean
  onContactDraftChange: (key: string, value: string) => void
  onSaveContact: (key: string) => void
}

export function ContactList({
  visibleContactKeys,
  contactDrafts,
  contactNameByKey,
  isWorking,
  onContactDraftChange,
  onSaveContact,
}: ContactListProps) {
  return (
    <>
      <h3 className="contact-alias-heading">Display aliases</h3>
      <div className="contact-list">
        {visibleContactKeys.length === 0 && (
          <div className="empty">Sender aliases appear here when messages arrive. An alias does not pin or verify a public key.</div>
        )}
        {visibleContactKeys.map((key) => (
          <div className="contact-row" key={key}>
            <div className="contact-key">{shortId(key)}</div>
            <input
              className="input"
              placeholder="Display name"
              value={contactDrafts[key] ?? contactNameByKey[key] ?? ''}
              onChange={(event) => onContactDraftChange(key, event.target.value)}
            />
            <button
              className="button"
              type="button"
              disabled={isWorking}
              onClick={() => void onSaveContact(key)}
            >
              Save
            </button>
          </div>
        ))}
      </div>
    </>
  )
}
