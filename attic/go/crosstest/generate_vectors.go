// generate_vectors produces JSON test vectors for cross-client compatibility testing.
// Run: go run ./crosstest/generate_vectors.go > client/tests/vectors.json
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

type TestVectors struct {
	// Fixed seed for deterministic key generation
	Seed            string `json:"seed"`
	IdentityVectors struct {
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
	} `json:"identity_vectors"`

	// CBOR encoding vectors
	CBORVectors []struct {
		Name    string `json:"name"`
		Input   any    `json:"input"`
		Encoded string `json:"encoded"` // hex
	} `json:"cbor_vectors"`

	// Key derivation vectors
	KeyDerivation struct {
		InviteSecret string `json:"invite_secret"`
		InviteSalt   string `json:"invite_salt"`
		ConvID       string `json:"conv_id"`
		RootKey      string `json:"root_key"`
		AEADKey      string `json:"aead_key"`
		NonceKey     string `json:"nonce_key"`
	} `json:"key_derivation"`

	// Signing vector
	SigningVector struct {
		Seed      string `json:"seed"`
		PublicKey string `json:"public_key"`
		Message   string `json:"message"` // hex
		Signature string `json:"signature"`
	} `json:"signing_vector"`

	// Hash vector
	HashVector struct {
		Input  string `json:"input"` // hex
		Output string `json:"output"`
	} `json:"hash_vector"`

	// Nonce derivation vector
	NonceVector struct {
		NonceKey string `json:"nonce_key"`
		MsgID    string `json:"msg_id"`
		Nonce    string `json:"nonce"`
	} `json:"nonce_vector"`

	// AEAD vector
	AEADVector struct {
		Key        string `json:"key"`
		Nonce      string `json:"nonce"`
		Plaintext  string `json:"plaintext"` // hex
		AAD        string `json:"aad"`       // hex
		Ciphertext string `json:"ciphertext"`
	} `json:"aead_vector"`

	// Full E2E message vector
	E2EVector struct {
		SenderSeed     string `json:"sender_seed"`
		SenderPubKey   string `json:"sender_pub_key"`
		SenderKeyID    string `json:"sender_key_id"`
		InviteSecret   string `json:"invite_secret"`
		InviteSalt     string `json:"invite_salt"`
		ConvID         string `json:"conv_id"`
		MsgID          string `json:"msg_id"`
		CreatedTS      int64  `json:"created_ts"`
		ExpiryTS       int64  `json:"expiry_ts"`
		BodyType       string `json:"body_type"`
		Body           string `json:"body"` // hex
		EnvelopeCBOR   string `json:"envelope_cbor"`
		InnerCBOR      string `json:"inner_cbor"`
		RootKey        string `json:"root_key"`
		AEADKey        string `json:"aead_key"`
		NonceKey       string `json:"nonce_key"`
	} `json:"e2e_vector"`

	// X25519 conversion vector
	X25519Vector struct {
		Ed25519Seed      string `json:"ed25519_seed"`
		Ed25519PublicKey string `json:"ed25519_public_key"`
		X25519PublicKey  string `json:"x25519_public_key"`
		X25519PrivateKey string `json:"x25519_private_key"`
	} `json:"x25519_vector"`

	// Epoch key derivation vectors
	EpochVectors struct {
		GroupKey string `json:"group_key"`
		ConvID   string `json:"conv_id"`
		Epochs   []struct {
			Epoch    uint   `json:"epoch"`
			AEADKey  string `json:"aead_key"`
			NonceKey string `json:"nonce_key"`
		} `json:"epochs"`
	} `json:"epoch_vectors"`
}

func main() {
	suite := crypto.NewQSP1Suite()
	idMgr := identity.NewManager()
	invMgr := invite.NewManager()
	msgMgr := message.NewManager()

	vectors := TestVectors{}

	// 1. Identity vectors with fixed seed
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	vectors.Seed = hex.EncodeToString(seed)

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	keyID := suite.ComputeKeyID(pubKey)

	vectors.IdentityVectors.PublicKey = hex.EncodeToString(pubKey)
	vectors.IdentityVectors.KeyID = hex.EncodeToString(keyID[:])

	// 2. CBOR encoding vectors
	type cborTest struct {
		name  string
		input any
	}
	cborTests := []cborTest{
		{"simple_map", map[string]interface{}{"a": 1, "b": 2}},
		{"nested_map", map[string]interface{}{"x": map[string]interface{}{"y": 3}}},
		{"with_bytes", map[string]interface{}{"data": []byte{0xde, 0xad, 0xbe, 0xef}}},
		{"mixed_keys", map[string]interface{}{"bb": 2, "a": 1, "ccc": 3}},
	}

	for _, t := range cborTests {
		encoded, err := cbor.MarshalCanonical(t.input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "CBOR encode error for %s: %v\n", t.name, err)
			os.Exit(1)
		}
		vectors.CBORVectors = append(vectors.CBORVectors, struct {
			Name    string `json:"name"`
			Input   any    `json:"input"`
			Encoded string `json:"encoded"`
		}{
			Name:    t.name,
			Input:   t.input,
			Encoded: hex.EncodeToString(encoded),
		})
	}

	// 3. Key derivation vector
	invSecret := make([]byte, 32)
	invSalt := make([]byte, 32)
	convIDBytes := make([]byte, 16)
	for i := range invSecret {
		invSecret[i] = byte(0x10 + i)
	}
	for i := range invSalt {
		invSalt[i] = byte(0x20 + i)
	}
	for i := range convIDBytes {
		convIDBytes[i] = byte(0x30 + i)
	}

	rootKey, err := suite.DeriveRootKey(invSecret, invSalt, convIDBytes)
	if err != nil {
		panic(err)
	}
	aeadKey, nonceKey, err := suite.DeriveConversationKeys(rootKey, convIDBytes)
	if err != nil {
		panic(err)
	}

	vectors.KeyDerivation.InviteSecret = hex.EncodeToString(invSecret)
	vectors.KeyDerivation.InviteSalt = hex.EncodeToString(invSalt)
	vectors.KeyDerivation.ConvID = hex.EncodeToString(convIDBytes)
	vectors.KeyDerivation.RootKey = hex.EncodeToString(rootKey)
	vectors.KeyDerivation.AEADKey = hex.EncodeToString(aeadKey)
	vectors.KeyDerivation.NonceKey = hex.EncodeToString(nonceKey)

	// 4. Signing vector
	vectors.SigningVector.Seed = hex.EncodeToString(seed)
	vectors.SigningVector.PublicKey = hex.EncodeToString(pubKey)
	testMsg := []byte("cross-client test message")
	sig, err := suite.Sign(privKey, testMsg)
	if err != nil {
		panic(err)
	}
	vectors.SigningVector.Message = hex.EncodeToString(testMsg)
	vectors.SigningVector.Signature = hex.EncodeToString(sig)

	// 5. Hash vector
	hashInput := []byte("hash test input")
	hashOutput := suite.Hash(hashInput)
	vectors.HashVector.Input = hex.EncodeToString(hashInput)
	vectors.HashVector.Output = hex.EncodeToString(hashOutput)

	// 6. Nonce derivation vector
	nonceKeyFixed := make([]byte, 32)
	msgIDFixed := make([]byte, 16)
	for i := range nonceKeyFixed {
		nonceKeyFixed[i] = byte(0x40 + i)
	}
	for i := range msgIDFixed {
		msgIDFixed[i] = byte(0x50 + i)
	}
	derivedNonce, err := suite.DeriveNonce(nonceKeyFixed, msgIDFixed)
	if err != nil {
		panic(err)
	}
	vectors.NonceVector.NonceKey = hex.EncodeToString(nonceKeyFixed)
	vectors.NonceVector.MsgID = hex.EncodeToString(msgIDFixed)
	vectors.NonceVector.Nonce = hex.EncodeToString(derivedNonce[:])

	// 7. AEAD vector
	aeadKeyFixed := make([]byte, 32)
	var nonceFixed [24]byte
	for i := range aeadKeyFixed {
		aeadKeyFixed[i] = byte(0x60 + i)
	}
	for i := range nonceFixed {
		nonceFixed[i] = byte(0x70 + i)
	}
	plaintext := []byte("AEAD test plaintext")
	aad := []byte("AEAD test AAD")
	ct, err := suite.Encrypt(aeadKeyFixed, nonceFixed, plaintext, aad)
	if err != nil {
		panic(err)
	}
	vectors.AEADVector.Key = hex.EncodeToString(aeadKeyFixed)
	vectors.AEADVector.Nonce = hex.EncodeToString(nonceFixed[:])
	vectors.AEADVector.Plaintext = hex.EncodeToString(plaintext)
	vectors.AEADVector.AAD = hex.EncodeToString(aad)
	vectors.AEADVector.Ciphertext = hex.EncodeToString(ct)

	// 8. X25519 conversion vector
	x25519PK, err := crypto.Ed25519PublicKeyToX25519(pubKey)
	if err != nil {
		panic(err)
	}
	x25519SK, err := crypto.Ed25519PrivateKeyToX25519(privKey)
	if err != nil {
		panic(err)
	}
	vectors.X25519Vector.Ed25519Seed = hex.EncodeToString(seed)
	vectors.X25519Vector.Ed25519PublicKey = hex.EncodeToString(pubKey)
	vectors.X25519Vector.X25519PublicKey = hex.EncodeToString(x25519PK)
	vectors.X25519Vector.X25519PrivateKey = hex.EncodeToString(x25519SK)

	// 9. Epoch key vectors
	groupKey := make([]byte, 32)
	epochConvID := make([]byte, 16)
	for i := range groupKey {
		groupKey[i] = byte(0xA0 + i)
	}
	for i := range epochConvID {
		epochConvID[i] = byte(0xB0 + i)
	}
	vectors.EpochVectors.GroupKey = hex.EncodeToString(groupKey)
	vectors.EpochVectors.ConvID = hex.EncodeToString(epochConvID)

	for _, epoch := range []uint{0, 1, 2, 5, 100} {
		ea, en, err := suite.DeriveEpochKeys(groupKey, epochConvID, epoch)
		if err != nil {
			panic(err)
		}
		vectors.EpochVectors.Epochs = append(vectors.EpochVectors.Epochs, struct {
			Epoch    uint   `json:"epoch"`
			AEADKey  string `json:"aead_key"`
			NonceKey string `json:"nonce_key"`
		}{
			Epoch:    epoch,
			AEADKey:  hex.EncodeToString(ea),
			NonceKey: hex.EncodeToString(en),
		})
	}

	// 10. Full E2E vector
	// Create identity from fixed seed
	senderPriv := ed25519.NewKeyFromSeed(seed)
	senderPub := senderPriv.Public().(ed25519.PublicKey)
	senderKID := idMgr.KeyIDFromPublicKey(senderPub)
	senderIdentity := &types.Identity{
		PrivateKey: senderPriv,
		PublicKey:  senderPub,
		KeyID:      senderKID,
	}

	// Create invite with fixed values
	var convID types.ConversationID
	copy(convID[:], convIDBytes)

	inv := &types.InvitePayload{
		Version:      types.ProtocolVersion,
		Suite:        types.DefaultSuite,
		Type:         string(types.ConversationTypeDirect),
		ConvID:       convID,
		InviterIKPK:  senderPub,
		InviteSalt:   invSalt,
		InviteSecret: invSecret,
	}

	keys, err := invMgr.DeriveConversationKeys(inv)
	if err != nil {
		panic(err)
	}
	conv, err := invMgr.CreateConversation(inv, keys)
	if err != nil {
		panic(err)
	}

	// Create message with fixed timestamp
	body := []byte("Hello from Go!")
	bodyType := "text/plain"
	ttl := int64(86400 * 30) // 30 days

	envelope, err := msgMgr.CreateMessage(senderIdentity, conv, bodyType, body, nil, ttl)
	if err != nil {
		panic(err)
	}

	envelopeBytes, err := msgMgr.SerializeEnvelope(envelope)
	if err != nil {
		panic(err)
	}

	// Decrypt to get inner payload for the vector
	msg, err := msgMgr.DecryptMessage(envelope, conv)
	if err != nil {
		panic(err)
	}

	innerBytes, err := cbor.MarshalCanonical(msg.Inner)
	if err != nil {
		panic(err)
	}

	vectors.E2EVector.SenderSeed = hex.EncodeToString(seed)
	vectors.E2EVector.SenderPubKey = hex.EncodeToString(senderPub)
	vectors.E2EVector.SenderKeyID = hex.EncodeToString(senderKID[:])
	vectors.E2EVector.InviteSecret = hex.EncodeToString(invSecret)
	vectors.E2EVector.InviteSalt = hex.EncodeToString(invSalt)
	vectors.E2EVector.ConvID = hex.EncodeToString(convID[:])
	vectors.E2EVector.MsgID = hex.EncodeToString(envelope.MsgID[:])
	vectors.E2EVector.CreatedTS = envelope.CreatedTS
	vectors.E2EVector.ExpiryTS = envelope.ExpiryTS
	vectors.E2EVector.BodyType = bodyType
	vectors.E2EVector.Body = hex.EncodeToString(body)
	vectors.E2EVector.EnvelopeCBOR = hex.EncodeToString(envelopeBytes)
	vectors.E2EVector.InnerCBOR = hex.EncodeToString(innerBytes)
	vectors.E2EVector.RootKey = hex.EncodeToString(keys.Root)
	vectors.E2EVector.AEADKey = hex.EncodeToString(keys.AEADKey)
	vectors.E2EVector.NonceKey = hex.EncodeToString(keys.NonceKey)

	// Ensure msgMgr is used (was already used above)
	_ = msgMgr
	_ = time.Now()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(vectors); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
		os.Exit(1)
	}
}
