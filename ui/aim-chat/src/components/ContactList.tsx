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
    <section className="panel">
      <h2>Contacts</h2>
      <div className="contact-list">
        {visibleContactKeys.length === 0 && (
          <div className="empty">No contacts yet</div>
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
    </section>
  )
}
