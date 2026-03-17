package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func genTestIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(pub)
	kid := hex.EncodeToString(hash[:16])
	return pub, priv, kid
}

func signMsg(priv ed25519.PrivateKey, msg string) string {
	return hex.EncodeToString(ed25519.Sign(priv, []byte(msg)))
}

func doRegister(t *testing.T, ts *httptest.Server, pub ed25519.PublicKey, priv ed25519.PrivateKey, kid, handle string) (*http.Response, RegisterResponse) {
	t.Helper()
	sig := signMsg(priv, "register:"+kid+":"+handle)
	body, _ := json.Marshal(RegisterRequest{
		KID:       kid,
		IKPK:      hex.EncodeToString(pub),
		Handle:    handle,
		Signature: sig,
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var result RegisterResponse
	if resp.StatusCode == 200 {
		json.NewDecoder(resp.Body).Decode(&result)
	}
	resp.Body.Close()
	return resp, result
}

func TestRegisterAndLookup(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pub, priv, kid := genTestIdentity(t)
	resp, regResp := doRegister(t, ts, pub, priv, kid, "alice")
	if resp.StatusCode != 200 {
		t.Fatalf("register failed: %d", resp.StatusCode)
	}
	if regResp.Salt == "" {
		t.Fatal("no salt returned")
	}

	// Verify commitment
	salt, _ := hex.DecodeString(regResp.Salt)
	commitment, _ := ComputeCommitment("alice", pub, salt)

	// Lookup
	lookupResp, err := http.Get(ts.URL + "/commitment/" + kid)
	if err != nil {
		t.Fatal(err)
	}
	defer lookupResp.Body.Close()
	var entry Table1Entry
	json.NewDecoder(lookupResp.Body).Decode(&entry)

	if entry.HandleCommitment != hex.EncodeToString(commitment) {
		t.Errorf("commitment mismatch: got %s, want %s", entry.HandleCommitment, hex.EncodeToString(commitment))
	}
}

func TestUniqueness(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pub1, priv1, kid1 := genTestIdentity(t)
	pub2, priv2, kid2 := genTestIdentity(t)

	resp1, _ := doRegister(t, ts, pub1, priv1, kid1, "alice")
	if resp1.StatusCode != 200 {
		t.Fatalf("first register failed: %d", resp1.StatusCode)
	}

	resp2, _ := doRegister(t, ts, pub2, priv2, kid2, "alice")
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", resp2.StatusCode)
	}
}

func TestBadSignature(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pub, _, kid := genTestIdentity(t)
	_, otherPriv, _ := genTestIdentity(t) // wrong key

	sig := signMsg(otherPriv, "register:"+kid+":alice")
	body, _ := json.Marshal(RegisterRequest{
		KID:       kid,
		IKPK:      hex.EncodeToString(pub),
		Handle:    "alice",
		Signature: sig,
	})
	resp, err := http.Post(ts.URL+"/register", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestChange(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pub, priv, kid := genTestIdentity(t)
	doRegister(t, ts, pub, priv, kid, "alice")

	// Change handle
	sig := signMsg(priv, "change:"+kid+":bob")
	body, _ := json.Marshal(ChangeRequest{
		KID:       kid,
		IKPK:      hex.EncodeToString(pub),
		NewHandle: "bob",
		Signature: sig,
	})
	resp, err := http.Post(ts.URL+"/change", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("change failed: %d", resp.StatusCode)
	}

	// Old handle should be free now
	pub2, priv2, kid2 := genTestIdentity(t)
	resp2, _ := doRegister(t, ts, pub2, priv2, kid2, "alice")
	if resp2.StatusCode != 200 {
		t.Fatalf("registering freed handle failed: %d", resp2.StatusCode)
	}
}

func TestDelete(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pub, priv, kid := genTestIdentity(t)
	doRegister(t, ts, pub, priv, kid, "alice")

	sig := signMsg(priv, "delete:"+kid)
	body, _ := json.Marshal(DeleteRequest{
		KID:       kid,
		IKPK:      hex.EncodeToString(pub),
		Signature: sig,
	})
	req, _ := http.NewRequest("DELETE", ts.URL+"/handle", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", resp.StatusCode)
	}

	// Lookup should 404
	lookupResp, _ := http.Get(ts.URL + "/commitment/" + kid)
	lookupResp.Body.Close()
	if lookupResp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", lookupResp.StatusCode)
	}
}

func TestCommitmentScheme(t *testing.T) {
	// Verify the commitment is deterministic given same inputs
	pub, _, _ := genTestIdentity(t)
	salt := make([]byte, 32)
	rand.Read(salt)

	c1, _ := ComputeCommitment("alice", pub, salt)
	c2, _ := ComputeCommitment("alice", pub, salt)
	if !bytes.Equal(c1, c2) {
		t.Error("commitment not deterministic")
	}

	// Different salt -> different commitment
	salt2 := make([]byte, 32)
	rand.Read(salt2)
	c3, _ := ComputeCommitment("alice", pub, salt2)
	if bytes.Equal(c1, c3) {
		t.Error("different salt produced same commitment")
	}
}

func TestNotFound(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	srv := NewServer(store)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/commitment/nonexistent")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = body
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}
