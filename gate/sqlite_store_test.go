package gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSQLiteStore_PersistenceAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gate.db")

	signer := newTestSigner()
	org := &Org{
		ID: "persist-org",
		Signers: []Signer{
			{KID: signer.kid, PublicKey: signer.pub, Label: "alice"},
		},
		Rules: []ThresholdRule{
			{Service: "echo", Endpoint: "*", Verb: "POST", M: 1, N: 1},
		},
	}

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(org); err != nil {
		t.Fatal(err)
	}
	if err := store.AddCredential("persist-org", &Credential{
		ID:          "echo-cred",
		Service:     "echo",
		Value:       "k123",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer {value}",
	}); err != nil {
		t.Fatal(err)
	}

	payload := json.RawMessage(`{"hello":"world"}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{
		OrgID: "persist-org", RequestID: "r1", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: "https://example.com/echo", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload),
	}
	reqSig, _ := SignRequest(signer.priv, signable)
	if err := store.WriteGateMessage("persist-org", &GateConversationMessage{
		Type: GateMessageRequest, OrgID: "persist-org", RequestID: "r1",
		Verb: "POST", TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: "https://example.com/echo", Payload: payload,
		SignerKID: signer.kid, Signature: base64.RawURLEncoding.EncodeToString(reqSig),
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	gotOrg, err := reopened.Get("persist-org")
	if err != nil {
		t.Fatal(err)
	}
	if gotOrg.ID != org.ID || len(gotOrg.Signers) != 1 || len(gotOrg.Rules) != 1 {
		t.Fatalf("unexpected org after reopen: %+v", gotOrg)
	}

	gotCred, err := reopened.GetCredentialByService("persist-org", "echo")
	if err != nil {
		t.Fatal(err)
	}
	if gotCred.Value != "k123" {
		t.Fatalf("unexpected credential value %q", gotCred.Value)
	}

	msgs, err := reopened.ReadGateMessages("persist-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].RequestID != "r1" {
		t.Fatalf("unexpected persisted messages: %+v", msgs)
	}
}

func TestSQLiteStore_ParityWithMemoryStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "parity.db")
	sqliteStore, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()

	memoryOrg := NewOrgStore()
	memoryConv := NewMemoryConversationStore()

	memorySnapshot := runStoreParityScenario(t, memoryOrg, memoryConv)
	sqliteSnapshot := runStoreParityScenario(t, sqliteStore, sqliteStore)

	if memorySnapshot.threshold != sqliteSnapshot.threshold {
		t.Fatalf("threshold mismatch memory=%d sqlite=%d", memorySnapshot.threshold, sqliteSnapshot.threshold)
	}
	if memorySnapshot.thresholdMet != sqliteSnapshot.thresholdMet {
		t.Fatalf("thresholdMet mismatch memory=%v sqlite=%v", memorySnapshot.thresholdMet, sqliteSnapshot.thresholdMet)
	}
	if memorySnapshot.status != sqliteSnapshot.status {
		t.Fatalf("status mismatch memory=%s sqlite=%s", memorySnapshot.status, sqliteSnapshot.status)
	}
	if memorySnapshot.messages != sqliteSnapshot.messages {
		t.Fatalf("message count mismatch memory=%d sqlite=%d", memorySnapshot.messages, sqliteSnapshot.messages)
	}
}

func TestGateServer_WithSQLiteStore_RetainsExecutedState(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "server.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	var hitCount int32
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer echoSrv.Close()

	signer := newTestSigner()
	srv := httptest.NewServer(NewInsecureServerForTestsWithStores(store, store))
	defer srv.Close()

	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "sqlite-org",
		"signers": []map[string]interface{}{
			{"kid": signer.kid, "public_key": encKey(signer.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "/once", "verb": "POST", "m": 1, "n": 1},
		},
	})
	post(t, srv.URL+"/v1/orgs/sqlite-org/credentials", map[string]interface{}{
		"id": "cred", "service": "echo", "value": "token",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	payload := json.RawMessage(`{"x":1}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	targetURL := echoSrv.URL + "/once"
	signable := &GateSignable{
		OrgID: "sqlite-org", RequestID: "req-1", Verb: "POST",
		TargetEndpoint: "/once", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload),
	}
	reqSig, _ := SignRequest(signer.priv, signable)

	first := post(t, srv.URL+"/v1/orgs/sqlite-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "req-1", "verb": "POST",
		"target_endpoint": "/once", "target_service": "echo", "target_url": targetURL,
		"payload": payload, "signer_kid": signer.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(reqSig),
		"expires_at": expiresAt,
	})
	if first["status"] != "executed" {
		t.Fatalf("expected first call to execute, got %v", first["status"])
	}
	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("expected exactly one execution call, got %d", got)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	srv2 := httptest.NewServer(NewInsecureServerForTestsWithStores(reopened, reopened))
	defer srv2.Close()
	second := post(t, srv2.URL+"/v1/orgs/sqlite-org/execute/req-1", map[string]interface{}{})
	if second["status"] != "executed" {
		t.Fatalf("expected persisted executed status, got %v", second["status"])
	}
	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("expected no re-execution after restart, got %d", got)
	}
}

type storeParitySnapshot struct {
	threshold    int
	thresholdMet bool
	status       RequestStatus
	messages     int
}

func runStoreParityScenario(t *testing.T, orgStore OrganizationStore, msgStore MessageStore) storeParitySnapshot {
	t.Helper()

	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	kidA := KIDFromPublicKey(pubA)
	kidB := KIDFromPublicKey(pubB)

	orgID := "parity-org-" + kidA[:6]
	org := &Org{
		ID: orgID,
		Signers: []Signer{
			{KID: kidA, PublicKey: pubA, Label: "alice"},
			{KID: kidB, PublicKey: pubB, Label: "bob"},
		},
		Rules: []ThresholdRule{
			{Service: "svc", Endpoint: "/op", Verb: "POST", M: 2, N: 2},
		},
	}
	if err := orgStore.Create(org); err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddCredential(orgID, &Credential{
		ID:          "cred",
		Service:     "svc",
		Value:       "v",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer {value}",
	}); err != nil {
		t.Fatal(err)
	}

	payload := json.RawMessage(`{"amount":7}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{
		OrgID: orgID, RequestID: "req-1", Verb: "POST",
		TargetEndpoint: "/op", TargetService: "svc",
		TargetURL: "https://example.com/op", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload),
	}
	reqSig, _ := SignRequest(privA, signable)
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(privB, &ApprovalSignable{OrgID: orgID, RequestID: "req-1", RequestHash: reqHash})

	if err := msgStore.WriteGateMessage(orgID, &GateConversationMessage{
		Type: GateMessageRequest, OrgID: orgID, RequestID: "req-1",
		Verb: "POST", TargetEndpoint: "/op", TargetService: "svc",
		TargetURL: "https://example.com/op", Payload: payload,
		SignerKID: kidA, Signature: base64.RawURLEncoding.EncodeToString(reqSig),
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := msgStore.WriteGateMessage(orgID, &GateConversationMessage{
		Type: GateMessageApproval, OrgID: orgID, RequestID: "req-1",
		SignerKID: kidB, Signature: base64.RawURLEncoding.EncodeToString(appSig),
	}); err != nil {
		t.Fatal(err)
	}

	loadedOrg, err := orgStore.Get(orgID)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := msgStore.ReadGateMessages(orgID)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := ScanConversation(messages, "req-1", loadedOrg)
	if err != nil {
		t.Fatal(err)
	}

	return storeParitySnapshot{
		threshold:    scan.Threshold,
		thresholdMet: scan.ThresholdMet,
		status:       scan.Status,
		messages:     len(messages),
	}
}
