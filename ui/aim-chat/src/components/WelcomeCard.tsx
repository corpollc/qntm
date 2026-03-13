export interface WelcomeCardProps {
  identityExists: boolean
  conversationCount: number
  isWorking: boolean
  onGenerateIdentity: () => void
  onOpenInvites: () => void
}

export function WelcomeCard({
  identityExists,
  conversationCount,
  isWorking,
  onGenerateIdentity,
  onOpenInvites,
}: WelcomeCardProps) {
  const hasConversation = conversationCount > 0

  return (
    <div className="welcome-card">
      <h2 className="welcome-heading">Welcome to qntm Messenger</h2>
      <p className="welcome-description">
        End-to-end encrypted messaging with built-in API Gateway.
      </p>

      <ol className="welcome-steps">
        <li className={`welcome-step ${identityExists ? 'completed' : 'active'}`}>
          <span className="welcome-step-indicator">
            {identityExists ? '\u2713' : '1'}
          </span>
          <div className="welcome-step-content">
            <strong>Generate your keypair</strong>
            {identityExists ? (
              <span className="welcome-step-done">Keypair created</span>
            ) : (
              <>
                <span className="welcome-step-hint">
                  Create a cryptographic identity for secure messaging.
                </span>
                <button
                  className="button"
                  type="button"
                  disabled={isWorking}
                  onClick={onGenerateIdentity}
                >
                  Generate keypair
                </button>
              </>
            )}
          </div>
        </li>

        <li
          className={`welcome-step ${
            !identityExists ? 'locked' : hasConversation ? 'completed' : 'active'
          }`}
        >
          <span className="welcome-step-indicator">
            {hasConversation ? '\u2713' : '2'}
          </span>
          <div className="welcome-step-content">
            <strong>Start a conversation</strong>
            {hasConversation ? (
              <span className="welcome-step-done">Conversation joined</span>
            ) : identityExists ? (
              <>
                <span className="welcome-step-hint">
                  Create a new conversation or join one with an invite token.
                </span>
                <button
                  className="button"
                  type="button"
                  onClick={onOpenInvites}
                >
                  Open Invites panel
                </button>
              </>
            ) : (
              <span className="welcome-step-hint">
                Complete step 1 first.
              </span>
            )}
          </div>
        </li>

        <li
          className={`welcome-step ${
            !hasConversation ? 'locked' : 'active'
          }`}
        >
          <span className="welcome-step-indicator">3</span>
          <div className="welcome-step-content">
            <strong>Send your first message</strong>
            {hasConversation ? (
              <span className="welcome-step-hint">
                Select a conversation and type a message below.
              </span>
            ) : (
              <span className="welcome-step-hint">
                Complete step 2 first.
              </span>
            )}
          </div>
        </li>
      </ol>
    </div>
  )
}
