package gate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
)

// ThresholdRule defines M-of-N threshold for a verb/endpoint/service combination.
type ThresholdRule struct {
	Service  string `json:"service"`  // target service, "*" = any
	Endpoint string `json:"endpoint"` // target endpoint, "*" = any
	Verb     string `json:"verb"`     // HTTP verb, "*" = any
	M        int    `json:"m"`        // required signatures
	N        int    `json:"n"`        // total possible (informational)
}

// Credential stores an API credential for a target service.
// TODO(v1): integrate Vault encryption at rest per qntm-gate-spec.md §3.
type Credential struct {
	ID          string `json:"id"`
	Service     string `json:"service"`
	Value       string `json:"value"`        // plaintext for v0.1; see Scrub()
	HeaderName  string `json:"header_name"`  // e.g. "Authorization"
	HeaderValue string `json:"header_value"` // template: {value} gets replaced
	Description string `json:"description"`
}

// Scrub zeros the credential Value in memory after use.
// This is a best-effort defense for v0.1; Go strings are immutable so the
// original backing bytes may still exist until GC. v1 will use Vault / memguard.
func (c *Credential) Scrub() {
	if c == nil {
		return
	}
	c.Value = ""
	c.HeaderValue = ""
}

// Signer represents a member of the org's signer set.
type Signer struct {
	KID       string            `json:"kid"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Label     string            `json:"label"`
}

// Org represents an organization in qntm-gate.
type Org struct {
	ID          string                 `json:"id"`
	Signers     []Signer               `json:"signers"`
	Rules       []ThresholdRule        `json:"rules"`
	Credentials map[string]*Credential `json:"credentials"`
}

// OrgStore is a thread-safe in-memory org store.
type OrgStore struct {
	mu   sync.RWMutex
	orgs map[string]*Org
}

// NewOrgStore creates a new org store.
func NewOrgStore() *OrgStore {
	return &OrgStore{orgs: make(map[string]*Org)}
}

// Create creates a new org.
func (s *OrgStore) Create(org *Org) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.orgs[org.ID]; exists {
		return fmt.Errorf("org %q already exists", org.ID)
	}
	if org.Credentials == nil {
		org.Credentials = make(map[string]*Credential)
	}
	s.orgs[org.ID] = org
	return nil
}

// Get returns an org by ID.
func (s *OrgStore) Get(orgID string) (*Org, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	org, ok := s.orgs[orgID]
	if !ok {
		return nil, fmt.Errorf("org %q not found", orgID)
	}
	return org, nil
}

// AddCredential adds a credential to an org.
func (s *OrgStore) AddCredential(orgID string, cred *Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	org, ok := s.orgs[orgID]
	if !ok {
		return fmt.Errorf("org %q not found", orgID)
	}
	org.Credentials[cred.ID] = cred
	return nil
}

// GetCredentialByService returns a credential by service name.
func (s *OrgStore) GetCredentialByService(orgID, service string) (*Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	org, ok := s.orgs[orgID]
	if !ok {
		return nil, fmt.Errorf("org %q not found", orgID)
	}
	for _, c := range org.Credentials {
		if c.Service == service {
			cp := *c
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("no credential for service %q in org %q", service, orgID)
}

// LookupThreshold finds the best matching threshold rule.
// Priority: exact service+endpoint+verb > service+verb > service > default.
func (o *Org) LookupThreshold(service, endpoint, verb string) (int, error) {
	bestScore := -1
	bestM := 0

	for _, r := range o.Rules {
		score := 0
		if r.Service != "*" {
			if r.Service != service {
				continue
			}
			score += 4
		}
		if r.Endpoint != "*" {
			if r.Endpoint != endpoint {
				continue
			}
			score += 2
		}
		if r.Verb != "*" {
			if r.Verb != verb {
				continue
			}
			score += 1
		}
		if score > bestScore {
			bestScore = score
			bestM = r.M
		}
	}

	if bestScore < 0 {
		return 0, fmt.Errorf("no threshold rule matches %s %s on %s", verb, endpoint, service)
	}
	return bestM, nil
}

// FindSignerByKID returns the signer with the given KID, or nil.
func (o *Org) FindSignerByKID(kid string) *Signer {
	for i := range o.Signers {
		if o.Signers[i].KID == kid {
			return &o.Signers[i]
		}
	}
	return nil
}

// KIDFromPublicKey computes the KID string from an Ed25519 public key.
// Same as qntm: Trunc16(SHA-256(pubkey)), base64url encoded (no padding).
func KIDFromPublicKey(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
