package types

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"
)

// QSP version constants
const (
	ProtocolVersion = 1
	DefaultSuite    = "QSP-1"
)

// Core identifiers
type ConversationID [16]byte
type MessageID [16]byte
type KeyID [16]byte

// MarshalText implements encoding.TextMarshaler for KeyID.
func (k KeyID) MarshalText() ([]byte, error) {
	return []byte(base64.RawURLEncoding.EncodeToString(k[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for KeyID.
func (k *KeyID) UnmarshalText(text []byte) error {
	b, err := base64.RawURLEncoding.DecodeString(string(text))
	if err != nil {
		return fmt.Errorf("invalid KeyID encoding: %w", err)
	}
	if len(b) != 16 {
		return fmt.Errorf("invalid KeyID length: got %d, want 16", len(b))
	}
	copy(k[:], b)
	return nil
}

// Identity represents an agent's identity key pair
type Identity struct {
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	KeyID      KeyID              `json:"key_id"`
}

// InvitePayload represents the CBOR-encoded invite structure
type InvitePayload struct {
	Version      int             `cbor:"v"`
	Suite        string          `cbor:"suite"`
	Type         string          `cbor:"type"` // "direct" or "group"
	ConvID       ConversationID  `cbor:"conv_id"`
	InviterIKPK  ed25519.PublicKey `cbor:"inviter_ik_pk"`
	InviteSalt   []byte          `cbor:"invite_salt"`
	InviteSecret []byte          `cbor:"invite_secret"`
}

// OuterEnvelope represents the public, stored envelope structure
type OuterEnvelope struct {
	Version    int             `cbor:"v"`
	Suite      string          `cbor:"suite"`
	ConvID     ConversationID  `cbor:"conv_id"`
	MsgID      MessageID       `cbor:"msg_id"`
	CreatedTS  int64           `cbor:"created_ts"`
	ExpiryTS   int64           `cbor:"expiry_ts"`
	Ciphertext []byte          `cbor:"ciphertext"`
	AADHash    []byte          `cbor:"aad_hash,omitempty"`
}

// InnerPayload represents the encrypted payload structure
type InnerPayload struct {
	SenderIKPK  ed25519.PublicKey `cbor:"sender_ik_pk"`
	SenderKID   KeyID             `cbor:"sender_kid"`
	BodyType    string            `cbor:"body_type"`
	Body        []byte            `cbor:"body"`
	Refs        []interface{}     `cbor:"refs,omitempty"`
	SigAlg      string            `cbor:"sig_alg"`
	Signature   []byte            `cbor:"signature"`
}

// AADStruct represents the additional authenticated data
type AADStruct struct {
	Version   int            `cbor:"v"`
	Suite     string         `cbor:"suite"`
	ConvID    ConversationID `cbor:"conv_id"`
	MsgID     MessageID      `cbor:"msg_id"`
	CreatedTS int64          `cbor:"created_ts"`
	ExpiryTS  int64          `cbor:"expiry_ts"`
}

// Signable represents the structure that gets signed
type Signable struct {
	Proto     string         `cbor:"proto"`
	Suite     string         `cbor:"suite"`
	ConvID    ConversationID `cbor:"conv_id"`
	MsgID     MessageID      `cbor:"msg_id"`
	CreatedTS int64          `cbor:"created_ts"`
	ExpiryTS  int64          `cbor:"expiry_ts"`
	SenderKID KeyID          `cbor:"sender_kid"`
	BodyHash  []byte         `cbor:"body_hash"`
}

// ConversationKeys represents derived conversation keys
type ConversationKeys struct {
	Root     []byte `json:"root"`
	AEADKey  []byte `json:"aead_key"`
	NonceKey []byte `json:"nonce_key"`
}

// Message represents a complete decrypted message
type Message struct {
	Envelope *OuterEnvelope `json:"envelope"`
	Inner    *InnerPayload  `json:"inner"`
	Verified bool           `json:"verified"`
}

// ConversationType represents the type of conversation
type ConversationType string

const (
	ConversationTypeDirect ConversationType = "direct"
	ConversationTypeGroup  ConversationType = "group"
)

// Conversation represents a messaging conversation
type Conversation struct {
	ID           ConversationID   `json:"id"`
	Type         ConversationType `json:"type"`
	Keys         ConversationKeys `json:"keys"`
	Participants []KeyID          `json:"participants"`
	CreatedAt    time.Time        `json:"created_at"`
}