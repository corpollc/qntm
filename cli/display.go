package cli

import (
	"encoding/hex"
	"fmt"

	"github.com/corpo/qntm/handle"
	"github.com/corpo/qntm/naming"
	"github.com/corpo/qntm/pkg/types"
	"github.com/corpo/qntm/shortref"
)

// DisplayContext holds resolved naming/shortref/handle stores for display formatting.
type DisplayContext struct {
	Names   *naming.Store
	Trie    *shortref.Trie
	Handles *handle.Store
}

// NewDisplayContext creates a display context from the current config.
// Returns a valid (possibly empty) context even on errors.
func NewDisplayContext() *DisplayContext {
	dc := &DisplayContext{}
	dc.Names, _ = naming.NewStore(configDir)
	dc.Trie = buildTrie()
	dc.Handles, _ = handle.NewStore(configDir)
	return dc
}

// FormatKID formats a KeyID for display using priority:
// local name > revealed handle (in conv context) > short ref > full hex.
func (dc *DisplayContext) FormatKID(kid types.KeyID, convIDHex string) string {
	hexKID := hex.EncodeToString(kid[:])
	return dc.FormatKIDHex(hexKID, convIDHex)
}

// FormatKIDHex formats a hex KID string for display.
func (dc *DisplayContext) FormatKIDHex(hexKID, convIDHex string) string {
	shortID := dc.shortRef(hexKID)

	// 1. Local name
	if dc.Names != nil {
		if name := dc.Names.GetIdentityName(hexKID); name != "" {
			return fmt.Sprintf("%s (%s)", name, shortID)
		}
	}

	// 2. Revealed handle (if conversation context provided)
	if convIDHex != "" && dc.Handles != nil {
		if h := dc.Handles.GetRevealedHandle(convIDHex, hexKID); h != "" {
			return fmt.Sprintf("@%s (%s)", h, shortID)
		}
	}

	// 3. Short ref if shorter than full
	if len(shortID) < len(hexKID) {
		return shortID
	}

	// 4. Full hex
	return hexKID
}

// FormatConvID formats a ConversationID for display using priority:
// local name > short ref > full hex.
func (dc *DisplayContext) FormatConvID(convID types.ConversationID) string {
	hexID := hex.EncodeToString(convID[:])
	return dc.FormatConvIDHex(hexID)
}

// FormatConvIDHex formats a hex conversation ID string for display.
func (dc *DisplayContext) FormatConvIDHex(hexID string) string {
	shortID := dc.shortRef(hexID)

	// 1. Local name
	if dc.Names != nil {
		if name := dc.Names.GetConversationName(hexID); name != "" {
			return fmt.Sprintf("%s (%s)", name, shortID)
		}
	}

	// 2. Short ref if shorter
	if len(shortID) < len(hexID) {
		return shortID
	}

	return hexID
}

func (dc *DisplayContext) shortRef(hexID string) string {
	if dc.Trie != nil {
		return dc.Trie.ShortRef(hexID)
	}
	return hexID
}
