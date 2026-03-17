package announce

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/pkg/types"
)

// ChannelKeys holds the two key pairs for an announce channel.
// The master key can rotate the posting key and create/delete channels.
// The posting key signs envelopes so the worker can gate writes.
type ChannelKeys struct {
	MasterPrivate  ed25519.PrivateKey `json:"master_private"`
	MasterPublic   ed25519.PublicKey  `json:"master_public"`
	MasterKID      types.KeyID        `json:"master_kid"`
	PostingPrivate ed25519.PrivateKey `json:"posting_private"`
	PostingPublic  ed25519.PublicKey  `json:"posting_public"`
	PostingKID     types.KeyID        `json:"posting_kid"`
}

// ChannelMeta is the public metadata stored at the worker for an announce channel.
type ChannelMeta struct {
	Name      string `json:"name"`
	ConvID    string `json:"conv_id"`    // 32-char hex
	MasterPK  string `json:"master_pk"`  // base64url Ed25519 public key
	PostingPK string `json:"posting_pk"` // base64url Ed25519 public key
}

// RegisterRequest is what the CLI sends to POST /v1/announce/register.
type RegisterRequest struct {
	Name      string `json:"name"`
	ConvID    string `json:"conv_id"`
	MasterPK  string `json:"master_pk"`
	PostingPK string `json:"posting_pk"`
	Sig       string `json:"sig"` // hex Ed25519 sig over pipe-delimited signable by master key
}

// RotateRequest is what the CLI sends to POST /v1/announce/rotate.
type RotateRequest struct {
	ConvID       string `json:"conv_id"`
	NewPostingPK string `json:"new_posting_pk"`
	MasterPK     string `json:"master_pk"`
	Sig          string `json:"sig"`
}

// DeleteRequest is what the CLI sends to POST /v1/announce/delete.
type DeleteRequest struct {
	ConvID   string `json:"conv_id"`
	MasterPK string `json:"master_pk"`
	Sig      string `json:"sig"`
}

const Proto = "qntm-announce-v1"

// Manager handles announce channel operations.
type Manager struct {
	idMgr *identity.Manager
}

func NewManager() *Manager {
	return &Manager{idMgr: identity.NewManager()}
}

// GenerateChannelKeys creates a fresh master + posting key pair.
func (m *Manager) GenerateChannelKeys() (*ChannelKeys, error) {
	masterID, err := m.idMgr.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate master key: %w", err)
	}
	postingID, err := m.idMgr.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("generate posting key: %w", err)
	}
	return &ChannelKeys{
		MasterPrivate:  masterID.PrivateKey,
		MasterPublic:   masterID.PublicKey,
		MasterKID:      masterID.KeyID,
		PostingPrivate: postingID.PrivateKey,
		PostingPublic:  postingID.PublicKey,
		PostingKID:     postingID.KeyID,
	}, nil
}

// --- Pipe-delimited signables (no CBOR, so the worker can reconstruct) ---

// buildRegisterSignable returns the canonical signable string for register.
func buildRegisterSignable(name, convID, postingPK string) string {
	return fmt.Sprintf("%s|register|%s|%s|%s", Proto, name, convID, postingPK)
}

// buildRotateSignable returns the canonical signable string for rotate.
func buildRotateSignable(convID, newPostingPK string) string {
	return fmt.Sprintf("%s|rotate|%s|%s", Proto, convID, newPostingPK)
}

// buildDeleteSignable returns the canonical signable string for delete.
func buildDeleteSignable(convID string) string {
	return fmt.Sprintf("%s|delete|%s", Proto, convID)
}

// SignRegister signs a register request with the master private key.
func (m *Manager) SignRegister(masterPriv ed25519.PrivateKey, name, convID, postingPK string) (string, error) {
	return signString(masterPriv, buildRegisterSignable(name, convID, postingPK)), nil
}

// VerifyRegister verifies the register request signature.
func (m *Manager) VerifyRegister(masterPK ed25519.PublicKey, name, convID, postingPK, sigHex string) error {
	return verifyString(masterPK, buildRegisterSignable(name, convID, postingPK), sigHex)
}

// SignRotate signs a rotate request with the master private key.
func (m *Manager) SignRotate(masterPriv ed25519.PrivateKey, convID, newPostingPK string) (string, error) {
	return signString(masterPriv, buildRotateSignable(convID, newPostingPK)), nil
}

// VerifyRotate verifies the rotate request signature.
func (m *Manager) VerifyRotate(masterPK ed25519.PublicKey, convID, newPostingPK, sigHex string) error {
	return verifyString(masterPK, buildRotateSignable(convID, newPostingPK), sigHex)
}

// SignDelete signs a delete request with the master private key.
func (m *Manager) SignDelete(masterPriv ed25519.PrivateKey, convID string) (string, error) {
	return signString(masterPriv, buildDeleteSignable(convID)), nil
}

// VerifyDelete verifies the delete request signature.
func (m *Manager) VerifyDelete(masterPK ed25519.PublicKey, convID, sigHex string) error {
	return verifyString(masterPK, buildDeleteSignable(convID), sigHex)
}

// SignEnvelope creates a transport-layer signature over raw envelope bytes
// using the posting private key. The worker verifies this on /v1/send for
// announce channels.
func (m *Manager) SignEnvelope(postingPriv ed25519.PrivateKey, envelopeB64 string) string {
	return signString(postingPriv, envelopeB64)
}

// VerifyEnvelope verifies a transport-layer envelope signature.
func (m *Manager) VerifyEnvelope(postingPK ed25519.PublicKey, envelopeB64, sigHex string) error {
	return verifyString(postingPK, envelopeB64, sigHex)
}

// signString SHA-256 hashes the input string, signs the hash with Ed25519,
// and returns the hex-encoded signature.
func signString(priv ed25519.PrivateKey, msg string) string {
	digest := sha256.Sum256([]byte(msg))
	sig := ed25519.Sign(priv, digest[:])
	return hex.EncodeToString(sig)
}

// verifyString verifies a hex-encoded Ed25519 signature over the SHA-256
// hash of the input string.
func verifyString(pub ed25519.PublicKey, msg, sigHex string) error {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d", len(sigBytes))
	}
	digest := sha256.Sum256([]byte(msg))
	if !ed25519.Verify(pub, digest[:], sigBytes) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
