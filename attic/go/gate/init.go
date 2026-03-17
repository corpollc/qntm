package gate

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/types"
)

// InitResult holds the output of a gateway init operation.
type InitResult struct {
	Identity     *types.Identity
	IdentityPath string
	VaultDir     string
	KeyID        string
	PublicKey    string
}

// InitGateway generates a new gateway identity and sets up the config
// directory structure. If an identity already exists at the given path it
// returns an error so callers can decide whether to overwrite.
func InitGateway(configDir string) (*InitResult, error) {
	// Create config directory (0700 — owner only)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("create config directory %s: %w", configDir, err)
	}

	identityPath := filepath.Join(configDir, "identity.json")

	// Check for existing identity
	if _, err := os.Stat(identityPath); err == nil {
		return nil, fmt.Errorf("identity already exists at %s (use --force to overwrite)", identityPath)
	}

	// Generate a new Ed25519 identity
	idMgr := identity.NewManager()
	newID, err := idMgr.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}

	// Serialize and save
	data, err := idMgr.SerializeIdentity(newID)
	if err != nil {
		return nil, fmt.Errorf("serialize identity: %w", err)
	}
	if err := os.WriteFile(identityPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write identity file: %w", err)
	}

	// Create vault directory
	vaultDir := filepath.Join(configDir, "vault")
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return nil, fmt.Errorf("create vault directory: %w", err)
	}

	// Create conversations file (empty array)
	convsPath := filepath.Join(configDir, "conversations.json")
	if _, err := os.Stat(convsPath); os.IsNotExist(err) {
		if err := os.WriteFile(convsPath, []byte("[]"), 0600); err != nil {
			return nil, fmt.Errorf("write conversations file: %w", err)
		}
	}

	return &InitResult{
		Identity:     newID,
		IdentityPath: identityPath,
		VaultDir:     vaultDir,
		KeyID:        idMgr.KeyIDToString(newID.KeyID),
		PublicKey:    idMgr.PublicKeyToString(newID.PublicKey),
	}, nil
}

// InitGatewayForce is like InitGateway but overwrites an existing identity.
func InitGatewayForce(configDir string) (*InitResult, error) {
	identityPath := filepath.Join(configDir, "identity.json")
	_ = os.Remove(identityPath)
	return InitGateway(configDir)
}
