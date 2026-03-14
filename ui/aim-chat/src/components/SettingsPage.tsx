import { api } from '../api'

export interface SettingsPageProps {
  dropboxUrl: string
  defaultDropboxUrl: string
  dropboxDraft: string
  setDropboxDraft: (value: string) => void
  isWorking: boolean
  onSaveSettings: () => void
  error: string
  setStatus: (value: string) => void
  setError: (value: string) => void
}

export function SettingsPage({
  dropboxUrl,
  defaultDropboxUrl,
  dropboxDraft,
  setDropboxDraft,
  isWorking,
  onSaveSettings,
  error,
  setStatus,
  setError,
}: SettingsPageProps) {
  return (
    <div className="settings-page">
      <section className="panel">
        <h2>Message Relay</h2>
        <p className="settings-description">
          The relay server stores and delivers your encrypted messages.
        </p>

        <label className="label" htmlFor="dropbox-url">Relay URL</label>
        <input
          id="dropbox-url"
          className="input"
          placeholder={defaultDropboxUrl}
          value={dropboxDraft}
          onChange={(event) => setDropboxDraft(event.target.value)}
        />

        <div className="row">
          <button
            className="button"
            type="button"
            disabled={isWorking}
            onClick={() => void onSaveSettings()}
          >
            Save
          </button>
          <button
            className="button"
            type="button"
            disabled={isWorking || dropboxDraft === defaultDropboxUrl}
            onClick={() => {
              setDropboxDraft(defaultDropboxUrl)
            }}
          >
            Reset to default
          </button>
        </div>

        <div className="meta">
          <div><strong>Current:</strong> {dropboxUrl}</div>
          <div><strong>Default:</strong> {defaultDropboxUrl}</div>
        </div>
      </section>

      <section className="panel">
        <h2>Backup &amp; Restore</h2>
        <p className="settings-description">
          All data (profiles, conversations, keys, messages) is stored in your browser.
          Export a backup to save it, or import to restore.
        </p>
        <div className="row">
          <button
            className="button"
            type="button"
            onClick={() => {
              const data = api.exportBackup()
              const blob = new Blob([data], { type: 'application/json' })
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = `aim-backup-${new Date().toISOString().slice(0, 10)}.json`
              a.click()
              URL.revokeObjectURL(url)
              setStatus('Backup exported')
            }}
          >
            Export backup
          </button>
          <label className="button" style={{ cursor: 'pointer' }}>
            Import backup
            <input
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (!file) return
                const reader = new FileReader()
                reader.onload = () => {
                  try {
                    api.importBackup(reader.result as string)
                    setStatus('Backup restored — reloading...')
                    setTimeout(() => window.location.reload(), 500)
                  } catch (err) {
                    setError(err instanceof Error ? err.message : 'Invalid backup file')
                  }
                }
                reader.readAsText(file)
              }}
            />
          </label>
        </div>
      </section>

      {error && <div className="error-banner">{error}</div>}
    </div>
  )
}
