// Package naming implements local address book / nickname system.
// Names are LOCAL ONLY — never transmitted, never shared.
package naming

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store is a local name store backed by a JSON file.
type Store struct {
	mu   sync.RWMutex
	path string
	data *storeData
}

type storeData struct {
	// Identity names: hex kid -> local name
	Identities map[string]string `json:"identities"`
	// Conversation names: hex conv_id -> local name
	Conversations map[string]string `json:"conversations"`
}

// NewStore creates or loads a name store at the given path.
func NewStore(dir string) (*Store, error) {
	path := filepath.Join(dir, "names.json")
	s := &Store{
		path: path,
		data: &storeData{
			Identities:    make(map[string]string),
			Conversations: make(map[string]string),
		},
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, s.data); err != nil {
			return nil, fmt.Errorf("corrupt names.json: %w", err)
		}
	}
	return s, nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// SetIdentityName assigns a local name to a kid (hex).
func (s *Store) SetIdentityName(hexKID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Check for name collision
	for k, v := range s.data.Identities {
		if v == name && k != hexKID {
			return fmt.Errorf("name %q already used for %s", name, k)
		}
	}
	s.data.Identities[hexKID] = name
	return s.save()
}

// SetConversationName assigns a local name to a conv_id (hex).
func (s *Store) SetConversationName(hexConvID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.data.Conversations {
		if v == name && k != hexConvID {
			return fmt.Errorf("name %q already used for %s", name, k)
		}
	}
	s.data.Conversations[hexConvID] = name
	return s.save()
}

// RemoveIdentityName removes a name by name string.
func (s *Store) RemoveIdentityName(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.data.Identities {
		if v == name {
			delete(s.data.Identities, k)
			return s.save()
		}
	}
	return fmt.Errorf("name %q not found", name)
}

// RemoveConversationName removes a conversation name by name string.
func (s *Store) RemoveConversationName(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.data.Conversations {
		if v == name {
			delete(s.data.Conversations, k)
			return s.save()
		}
	}
	return fmt.Errorf("name %q not found", name)
}

// GetIdentityName returns the local name for a kid, or "" if none.
func (s *Store) GetIdentityName(hexKID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Identities[hexKID]
}

// GetConversationName returns the local name for a conv_id, or "" if none.
func (s *Store) GetConversationName(hexConvID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Conversations[hexConvID]
}

// ListIdentities returns all identity name mappings.
func (s *Store) ListIdentities() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.data.Identities))
	for k, v := range s.data.Identities {
		result[k] = v
	}
	return result
}

// ListConversations returns all conversation name mappings.
func (s *Store) ListConversations() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.data.Conversations))
	for k, v := range s.data.Conversations {
		result[k] = v
	}
	return result
}

// ResolveIdentityByName finds a kid hex by its local name.
func (s *Store) ResolveIdentityByName(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.data.Identities {
		if v == name {
			return k, true
		}
	}
	return "", false
}

// ResolveConversationByName finds a conv_id hex by its local name.
func (s *Store) ResolveConversationByName(name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.data.Conversations {
		if v == name {
			return k, true
		}
	}
	return "", false
}
