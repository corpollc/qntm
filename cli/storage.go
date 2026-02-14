package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/group"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/types"
)

// Storage and configuration management

func ensureConfigDir() error {
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	return nil
}

func getIdentityPath() string {
	if identityFile != "" {
		return identityFile
	}
	return filepath.Join(configDir, "identity.json")
}

func getConversationsPath() string {
	return filepath.Join(configDir, "conversations.json")
}

func getGroupStatesPath() string {
	return filepath.Join(configDir, "groups.json")
}

func getSeenMessagesPath() string {
	return filepath.Join(configDir, "seen_messages.json")
}

func getStorageDir() string {
	if storageDir != "" {
		return storageDir
	}
	return filepath.Join(configDir, "storage")
}

// Identity management

func saveIdentity(id *types.Identity) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}
	
	identityMgr := identity.NewManager()
	data, err := identityMgr.SerializeIdentity(id)
	if err != nil {
		return fmt.Errorf("failed to serialize identity: %w", err)
	}
	
	return os.WriteFile(getIdentityPath(), data, 0600)
}

func loadIdentity() (*types.Identity, error) {
	data, err := os.ReadFile(getIdentityPath())
	if err != nil {
		return nil, fmt.Errorf("identity not found (run 'qntm identity generate' first): %w", err)
	}
	
	identityMgr := identity.NewManager()
	return identityMgr.DeserializeIdentity(data)
}

// Conversation management

func saveConversation(conv *types.Conversation) error {
	conversations, err := loadConversations()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	
	// Update or add conversation
	found := false
	for i, existing := range conversations {
		if existing.ID == conv.ID {
			conversations[i] = conv
			found = true
			break
		}
	}
	
	if !found {
		conversations = append(conversations, conv)
	}
	
	return saveConversations(conversations)
}

func saveConversations(conversations []*types.Conversation) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}
	
	data, err := json.MarshalIndent(conversations, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal conversations: %w", err)
	}
	
	return os.WriteFile(getConversationsPath(), data, 0600)
}

func loadConversations() ([]*types.Conversation, error) {
	data, err := os.ReadFile(getConversationsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []*types.Conversation{}, nil
		}
		return nil, err
	}
	
	var conversations []*types.Conversation
	if err := json.Unmarshal(data, &conversations); err != nil {
		return nil, fmt.Errorf("failed to unmarshal conversations: %w", err)
	}
	
	return conversations, nil
}

func findConversation(convID types.ConversationID) (*types.Conversation, error) {
	conversations, err := loadConversations()
	if err != nil {
		return nil, err
	}
	
	for _, conv := range conversations {
		if conv.ID == convID {
			return conv, nil
		}
	}
	
	return nil, fmt.Errorf("conversation not found")
}

// Group state management

type groupStatesFile struct {
	Groups map[string]*group.GroupState `json:"groups"`
}

func saveGroupState(convID types.ConversationID, state *group.GroupState) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}
	
	// Load existing groups
	groupStates, err := loadAllGroupStates()
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	
	if groupStates == nil {
		groupStates = &groupStatesFile{
			Groups: make(map[string]*group.GroupState),
		}
	}
	
	convIDStr := fmt.Sprintf("%x", convID[:])
	groupStates.Groups[convIDStr] = state
	
	data, err := json.MarshalIndent(groupStates, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal group states: %w", err)
	}
	
	return os.WriteFile(getGroupStatesPath(), data, 0600)
}

func loadGroupState(convID types.ConversationID) (*group.GroupState, error) {
	groupStates, err := loadAllGroupStates()
	if err != nil {
		return nil, err
	}
	
	convIDStr := fmt.Sprintf("%x", convID[:])
	state, exists := groupStates.Groups[convIDStr]
	if !exists {
		return nil, fmt.Errorf("group state not found")
	}
	
	return state, nil
}

func loadAllGroupStates() (*groupStatesFile, error) {
	data, err := os.ReadFile(getGroupStatesPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &groupStatesFile{Groups: make(map[string]*group.GroupState)}, nil
		}
		return nil, err
	}
	
	var groupStates groupStatesFile
	if err := json.Unmarshal(data, &groupStates); err != nil {
		return nil, fmt.Errorf("failed to unmarshal group states: %w", err)
	}
	
	return &groupStates, nil
}

// Seen messages management (for replay protection)

func saveSeenMessages(seenMessages map[types.ConversationID]map[types.MessageID]bool) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}
	
	// Convert to serializable format
	serializable := make(map[string]map[string]bool)
	for convID, messages := range seenMessages {
		convIDStr := fmt.Sprintf("%x", convID[:])
		serializable[convIDStr] = make(map[string]bool)
		
		for msgID, seen := range messages {
			msgIDStr := fmt.Sprintf("%x", msgID[:])
			serializable[convIDStr][msgIDStr] = seen
		}
	}
	
	data, err := json.MarshalIndent(serializable, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal seen messages: %w", err)
	}
	
	return os.WriteFile(getSeenMessagesPath(), data, 0600)
}

func loadSeenMessages() map[types.ConversationID]map[types.MessageID]bool {
	data, err := os.ReadFile(getSeenMessagesPath())
	if err != nil {
		// Return empty map if file doesn't exist
		return make(map[types.ConversationID]map[types.MessageID]bool)
	}
	
	var serializable map[string]map[string]bool
	if err := json.Unmarshal(data, &serializable); err != nil {
		// Return empty map on error
		return make(map[types.ConversationID]map[types.MessageID]bool)
	}
	
	// Convert back to typed format
	result := make(map[types.ConversationID]map[types.MessageID]bool)
	for convIDStr, messages := range serializable {
		convIDBytes, err := hex.DecodeString(convIDStr)
		if err != nil || len(convIDBytes) != 16 {
			continue
		}
		
		var convID types.ConversationID
		copy(convID[:], convIDBytes)
		
		result[convID] = make(map[types.MessageID]bool)
		
		for msgIDStr, seen := range messages {
			msgIDBytes, err := hex.DecodeString(msgIDStr)
			if err != nil || len(msgIDBytes) != 16 {
				continue
			}
			
			var msgID types.MessageID
			copy(msgID[:], msgIDBytes)
			
			result[convID][msgID] = seen
		}
	}
	
	return result
}

// Storage provider

func getStorageProvider() dropbox.StorageProvider {
	// For now, use file-based storage
	// In production, this would connect to actual storage backends
	storageDir := getStorageDir()
	if err := os.MkdirAll(storageDir, 0700); err != nil {
		// Fallback to memory storage
		return dropbox.NewMemoryStorageProvider()
	}
	
	return NewFileStorageProvider(storageDir)
}

// Simple file-based storage provider for CLI
type FileStorageProvider struct {
	baseDir string
}

func NewFileStorageProvider(baseDir string) *FileStorageProvider {
	return &FileStorageProvider{
		baseDir: baseDir,
	}
}

func (f *FileStorageProvider) Store(key string, data []byte) error {
	// Convert key to file path
	filePath := filepath.Join(f.baseDir, filepath.Clean(key))
	
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	
	return os.WriteFile(filePath, data, 0600)
}

func (f *FileStorageProvider) Retrieve(key string) ([]byte, error) {
	filePath := filepath.Join(f.baseDir, filepath.Clean(key))
	return os.ReadFile(filePath)
}

func (f *FileStorageProvider) List(prefix string) ([]string, error) {
	var keys []string
	err := filepath.Walk(f.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		
		if !info.IsDir() {
			relPath, err := filepath.Rel(f.baseDir, path)
			if err != nil {
				return nil
			}
			
			// Convert back to key format
			key := filepath.ToSlash(relPath)
			if len(key) > 0 && key[0] != '/' {
				key = "/" + key
			}
			
			// Check if it matches prefix
			if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
				keys = append(keys, key)
			}
		}
		
		return nil
	})
	
	return keys, err
}

func (f *FileStorageProvider) Delete(key string) error {
	filePath := filepath.Join(f.baseDir, filepath.Clean(key))
	return os.Remove(filePath)
}

func (f *FileStorageProvider) Exists(key string) (bool, error) {
	filePath := filepath.Join(f.baseDir, filepath.Clean(key))
	_, err := os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Unsafe development functions

func createTestIdentity(name string) error {
	identityMgr := identity.NewManager()
	testIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		return err
	}
	
	if err := saveIdentity(testIdentity); err != nil {
		return err
	}
	
	fmt.Printf("Created unsafe test identity for %s:\n", name)
	fmt.Printf("Key ID: %s\n", identityMgr.KeyIDToString(testIdentity.KeyID))
	fmt.Printf("Public Key: %s\n", identityMgr.PublicKeyToString(testIdentity.PublicKey))
	fmt.Println("⚠️  This is an UNSAFE test identity! Do not use in production!")
	
	return nil
}

func clearAllData() error {
	fmt.Println("⚠️  Clearing all qntm data...")
	
	if err := os.RemoveAll(configDir); err != nil {
		return fmt.Errorf("failed to clear data: %w", err)
	}
	
	fmt.Println("✓ All data cleared")
	return nil
}