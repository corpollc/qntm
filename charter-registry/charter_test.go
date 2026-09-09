package charter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestSharedVectors(t *testing.T) {
	b, err := os.ReadFile("../specs/test-vectors/charter-registry-v02.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name     string
			Valid    bool
			Registry string
			AgentID  string `json:"agent_id"`
			HeadHash string `json:"head_hash"`
			Chain    []json.RawMessage
		}
		JSON []struct {
			Name      string
			Input     string
			Canonical *string
		}
	}
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Cases {
		t.Run(v.Name, func(t *testing.T) {
			var state *State
			var err error
			for _, raw := range v.Chain {
				var s Statement
				s, err = ParseStatement(raw)
				if err != nil {
					break
				}
				state, err = Advance(state, s, v.Registry)
				if err != nil {
					break
				}
			}
			if v.Valid {
				if err != nil {
					t.Fatal(err)
				}
				if state.HeadHash != v.HeadHash || state.AgentID != v.AgentID {
					t.Fatal("cross-language hash or agent mismatch")
				}
			} else if err == nil {
				t.Fatal("accepted invalid vector")
			}
		})
	}
	for _, v := range vectors.JSON {
		t.Run(v.Name, func(t *testing.T) {
			got, err := CanonicalJSON([]byte(v.Input))
			if v.Canonical == nil {
				if err == nil {
					t.Fatal("accepted invalid JSON")
				}
			} else if err != nil || string(got) != *v.Canonical {
				t.Fatalf("got %s, err %v", got, err)
			}
		})
	}
}

func testIdentity(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func testSign(t *testing.T, s Statement, key ed25519.PrivateKey) Statement {
	t.Helper()
	b, err := canonicalValue(s.Signed)
	if err != nil {
		t.Fatal(err)
	}
	s.Signatures = []Signature{{AgentID(key.Public().(ed25519.PublicKey)), base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b))}}
	return s
}
func testCharter(t *testing.T, key ed25519.PrivateKey) Statement {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	body, _ := json.Marshal(map[string]any{"agent_pubkey": NewKey(pub).PublicKey, "governance": Governance{[]Key{NewKey(pub)}, 1}, "agent_rights": []string{}})
	return testSign(t, Statement{Signed: SignedBody{"test.registry", AgentID(pub), 0, GenesisHash, "charter", "2026-09-08T00:00:00Z", body}, Signatures: []Signature{}}, key)
}
func testNext(t *testing.T, prev Statement, key ed25519.PrivateKey, note string) Statement {
	t.Helper()
	hash, _ := StatementHash(prev)
	body, _ := json.Marshal(map[string]any{"namespace": "test", "data": note})
	return testSign(t, Statement{Signed: SignedBody{prev.Signed.Registry, prev.Signed.AgentID, prev.Signed.Sequence + 1, hash, "statement", "2020-01-01T00:00:00Z", body}, Signatures: []Signature{}}, key)
}
func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path, "test.registry")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDurabilityAndConcurrentForks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	s := openTest(t, path)
	key := testIdentity(t)
	genesis := testCharter(t, key)
	first, err := s.Submit(genesis)
	if err != nil {
		t.Fatal(err)
	}
	pin := s.PublicKey()
	if _, err := s.Submit(genesis); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		candidate := testNext(t, genesis, key, fmt.Sprint(i))
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Submit(candidate); results <- err }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent forks", accepted)
	}
	snap, err := s.Snapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(snap.Heads)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTest(t, path)
	defer s.Close()
	after, err := s.Snapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(after.Heads)
	if !bytes.Equal(before, encoded) || s.PublicKey() != pin || len(after.Entries) != 2 {
		t.Fatal("restart changed durable heads, identity, or entries")
	}
	one := uint64(1)
	historical, err := s.Snapshot(&one)
	if err != nil || historical.Heads != first.Heads {
		t.Fatal("historical head changed")
	}
	if _, err := Open(path, "test.registry"); err == nil {
		t.Fatal("concurrent process opened the same database")
	}
}

func TestStartupRejectsWrongAudienceAndCorruptHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	s := openTest(t, path)
	_, err := s.Submit(testCharter(t, testIdentity(t)))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if other, err := Open(path, "other.registry"); err == nil {
		other.Close()
		t.Fatal("accepted wrong DB audience")
	}
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(entriesBucket)
		var entry LogEntry
		if err := json.Unmarshal(b.Get(indexKey(0)), &entry); err != nil {
			return err
		}
		entry.Statement.Signed.Body = json.RawMessage(`{}`)
		raw, _ := json.Marshal(entry)
		return b.Put(indexKey(0), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if corrupt, err := Open(path, "test.registry"); err == nil {
		corrupt.Close()
		t.Fatal("accepted corrupted durable history")
	}
}

func TestHTTPValidationAndSnapshotBounds(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "registry.db"))
	defer s.Close()
	handler := s.Handler()
	request := func(method, path string, body []byte, want int) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
	}
	request("GET", "/healthz", nil, 200)
	request("GET", "/v1/heads", nil, 200)
	request("GET", "/v1/consistency?from=0&to=1", nil, 400)
	request("GET", "/v1/chain/"+strings.Repeat("0", 32), nil, 200)
	request("GET", "/v1/chain/nope", nil, 400)
	request("GET", "/v1/inclusion/0", nil, 400)
	request("GET", "/v1/log?limit=1001", nil, 400)
	request("GET", "/v1/heads?size=-1", nil, 400)
	request("GET", "/v1/heads?size=9007199254740992", nil, 400)
	request("POST", "/v1/statements", []byte(`{"signed":{},"signed":{}}`), 400)
	request("POST", "/v1/statements", bytes.Repeat([]byte{' '}, MaxStatementBytes+1), 413)
	key := testIdentity(t)
	genesis := testCharter(t, key)
	b, _ := json.Marshal(genesis)
	request("POST", "/v1/statements", b, 201)
	request("POST", "/v1/statements", b, 409)
	wrong := testNext(t, genesis, key, "bad")
	wrong.Signed.Registry = "other"
	b, _ = json.Marshal(testSign(t, wrong, key))
	request("POST", "/v1/statements", b, 422)
	request(http.MethodGet, "/v1/inclusion/0?size=1", nil, 200)
}

func TestMerkleTreeShape(t *testing.T) {
	// Independent small-tree constructions exercise non-power-of-two boundaries.
	a, b, c := leafHash([]byte("a")), leafHash([]byte("b")), leafHash([]byte("c"))
	if treeRoot([]string{a, b, c}) != nodeHash(nodeHash(a, b), c) {
		t.Fatal("wrong tree shape")
	}
	path := inclusionPath([]string{a, b, c}, 2)
	if len(path) != 1 || path[0] != nodeHash(a, b) {
		t.Fatal("wrong right-boundary path")
	}
	if treeRoot(nil) != digest(nil) {
		t.Fatal("wrong empty root")
	}
}

func TestStartupRejectsLostMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	s := openTest(t, path)
	if _, err := s.Submit(testCharter(t, testIdentity(t))); err != nil {
		t.Fatal(err)
	}
	s.Close()
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(metadataBucket) }); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if recovered, err := Open(path, "test.registry"); err == nil {
		recovered.Close()
		t.Fatal("silently generated a new registrar identity for existing history")
	}
}
