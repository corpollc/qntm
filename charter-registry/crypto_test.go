package charter

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedSignatureProfile(t *testing.T) {
	data, err := os.ReadFile("../specs/test-vectors/ed25519-verification.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key_hex"`
			Message   string `json:"message_hex"`
			Signature string `json:"signature_hex"`
			KeyValid  bool   `json:"key_valid"`
			Valid     bool   `json:"valid"`
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Cases {
		t.Run(v.Name, func(t *testing.T) {
			decode := func(s string) []byte {
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			key, message, signature := decode(v.PublicKey), decode(v.Message), decode(v.Signature)
			if validPublicKey(key) != v.KeyValid {
				t.Fatal("key admission differs from shared profile")
			}
			if got := validPublicKey(key) && ed25519.Verify(key, message, signature); got != v.Valid {
				t.Fatalf("signature valid=%v, want %v", got, v.Valid)
			}
		})
	}
}
