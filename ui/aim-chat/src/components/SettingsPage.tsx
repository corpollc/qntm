import { BackupPanel } from './BackupPanel'
import { APP_VERSION } from '../utils'

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
  onShowShortcuts?: () => void
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
  onShowShortcuts,
}: SettingsPageProps) {
  return (
    <div className="settings-page">
      <section className="settings-section">
        <h2 className="settings-section-title">Network</h2>
        <div className="panel">
          <h2>Message Relay</h2>
          <p className="settings-description">
            The relay server stores and delivers your encrypted messages.
          </p>
          <p className="settings-description" style={{ fontSize: '0.85em', opacity: 0.7 }}>
            Configuration is stored in your browser's local storage.
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
        </div>
      </section>

      <div className="settings-divider" />

      <section className="settings-section">
        <h2 className="settings-section-title">Data</h2>
        <BackupPanel setStatus={setStatus} setError={setError} />
      </section>

      <div className="settings-divider" />

      <section className="settings-section">
        <h2 className="settings-section-title">About</h2>
        <div className="panel">
          <h2>qntm Messenger</h2>
          <div className="meta">
            <div><strong>Version:</strong> v{APP_VERSION}</div>
          </div>
          <div className="settings-about-links">
            <a className="settings-about-link" href="https://github.com/corpollc/qntm/blob/main/docs/getting-started.md" target="_blank" rel="noreferrer">Getting Started Guide</a>
            <a className="settings-about-link" href="https://github.com/corpollc/qntm/blob/main/docs/api-gateway.md" target="_blank" rel="noreferrer">API Gateway Documentation</a>
            {onShowShortcuts && (
              <button
                className="settings-about-link settings-about-link-button"
                type="button"
                onClick={onShowShortcuts}
              >
                Keyboard Shortcuts
              </button>
            )}
          </div>
        </div>
      </section>

      {error && <div className="error-banner">{error}</div>}
    </div>
  )
}
