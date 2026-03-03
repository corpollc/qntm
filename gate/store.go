package gate

// OrganizationStore is the persistence interface for org metadata and credentials.
type OrganizationStore interface {
	Create(org *Org) error
	Get(orgID string) (*Org, error)
	AddCredential(orgID string, cred *Credential) error
	GetCredentialByService(orgID, service string) (*Credential, error)
}

// MessageStore is the persistence interface for gate conversation messages.
type MessageStore interface {
	ConversationReader
	ConversationWriter
}
