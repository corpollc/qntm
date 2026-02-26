package gate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type testSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	kid  string
}

func newTestSigner() testSigner {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return testSigner{pub: pub, priv: priv, kid: KIDFromPublicKey(pub)}
}

// --- Unit tests ---

func TestSignVerifyRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := &GateSignable{OrgID: "o", RequestID: "r", Verb: "POST",
		TargetEndpoint: "/e", TargetService: "s",
		TargetURL: "https://example.com/e", ExpiresAtUnix: 1735689600,
		PayloadHash: ComputePayloadHash([]byte(`{}`))}

	sig, err := SignRequest(priv, s)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(pub, s, sig); err != nil {
		t.Fatal("valid sig rejected:", err)
	}
	pub2, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyRequest(pub2, s, sig); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestSignVerifyApproval(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	s := &ApprovalSignable{OrgID: "o", RequestID: "r", RequestHash: []byte("h")}
	sig, _ := SignApproval(priv, s)
	if err := VerifyApproval(pub, s, sig); err != nil {
		t.Fatal(err)
	}
}

func TestLookupThreshold(t *testing.T) {
	o := &Org{Rules: []ThresholdRule{
		{Service: "*", Endpoint: "*", Verb: "*", M: 1},
		{Service: "echo", Endpoint: "*", Verb: "POST", M: 2},
		{Service: "echo", Endpoint: "/admin", Verb: "POST", M: 3},
	}}

	tests := []struct {
		svc, ep, verb string
		want          int
	}{
		{"echo", "/admin", "POST", 3},
		{"echo", "/data", "POST", 2},
		{"echo", "/data", "GET", 1},
		{"other", "/x", "DELETE", 1},
	}
	for _, tt := range tests {
		m, err := o.LookupThreshold(tt.svc, tt.ep, tt.verb)
		if err != nil {
			t.Errorf("%s %s %s: %v", tt.verb, tt.ep, tt.svc, err)
		} else if m != tt.want {
			t.Errorf("%s %s %s: got %d want %d", tt.verb, tt.ep, tt.svc, m, tt.want)
		}
	}
}

func TestOrgStore(t *testing.T) {
	s := NewOrgStore()
	a := newTestSigner()
	o := &Org{ID: "o1", Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "a"}},
		Rules: []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}}}
	if err := s.Create(o); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(o); err == nil {
		t.Fatal("duplicate should fail")
	}
	if _, err := s.Get("nope"); err == nil {
		t.Fatal("missing should fail")
	}
	s.AddCredential("o1", &Credential{ID: "c1", Service: "echo", Value: "k"})
	c, _ := s.GetCredentialByService("o1", "echo")
	if c.Value != "k" {
		t.Fatal("credential mismatch")
	}
}

func TestNewServer_RequiresAdminToken(t *testing.T) {
	if _, err := NewServer(""); err == nil {
		t.Fatal("expected empty admin token to fail")
	}
	if _, err := NewServer("   "); err == nil {
		t.Fatal("expected whitespace admin token to fail")
	}

	srv, err := NewServer("test-token")
	if err != nil {
		t.Fatalf("expected valid token to succeed, got: %v", err)
	}
	if srv.AdminToken != "test-token" {
		t.Fatalf("unexpected token on server: %q", srv.AdminToken)
	}
}

func TestNewInsecureServerForTests_AllowsNoToken(t *testing.T) {
	srv := NewInsecureServerForTests()
	if srv == nil {
		t.Fatal("expected server instance")
	}
	if srv.AdminToken != "" {
		t.Fatalf("expected empty admin token for insecure server, got: %q", srv.AdminToken)
	}
}

// --- ScanConversation unit tests ---

func TestScanConversation_ThresholdMet(t *testing.T) {
	a, b := newTestSigner(), newTestSigner()
	org := &Org{
		ID:      "test-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "alice"}, {KID: b.kid, PublicKey: b.pub, Label: "bob"}},
		Rules:   []ThresholdRule{{Service: "echo", Endpoint: "*", Verb: "POST", M: 2, N: 2}},
	}

	payload := json.RawMessage(`{"test":true}`)
	targetURL := "https://example.com/echo"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "test-org", RequestID: "r1", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	reqSig, _ := SignRequest(a.priv, signable)
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{OrgID: "test-org", RequestID: "r1", RequestHash: reqHash})

	messages := []GateConversationMessage{
		{
			Type: GateMessageRequest, OrgID: "test-org", RequestID: "r1",
			Verb: "POST", TargetEndpoint: "/echo", TargetService: "echo",
			TargetURL: targetURL,
			Payload:   payload, SignerKID: a.kid,
			Signature: base64.RawURLEncoding.EncodeToString(reqSig),
			ExpiresAt: expiresAt,
		},
		{
			Type: GateMessageApproval, OrgID: "test-org", RequestID: "r1",
			SignerKID: b.kid, Signature: base64.RawURLEncoding.EncodeToString(appSig),
		},
	}

	result, err := ScanConversation(messages, "r1", org)
	if err != nil {
		t.Fatal(err)
	}
	if !result.ThresholdMet {
		t.Fatal("expected threshold met")
	}
	if len(result.SignerKIDs) != 2 {
		t.Fatalf("expected 2 signers, got %d", len(result.SignerKIDs))
	}
	t.Log("✅ ScanConversation threshold met")
}

func TestScanConversation_ThresholdNotMet(t *testing.T) {
	a, b := newTestSigner(), newTestSigner()
	org := &Org{
		ID:      "test-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "alice"}, {KID: b.kid, PublicKey: b.pub, Label: "bob"}},
		Rules:   []ThresholdRule{{Service: "echo", Endpoint: "*", Verb: "POST", M: 2, N: 2}},
	}

	payload := json.RawMessage(`{}`)
	targetURL := "https://example.com/echo"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "test-org", RequestID: "r1", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	reqSig, _ := SignRequest(a.priv, signable)

	messages := []GateConversationMessage{
		{
			Type: GateMessageRequest, OrgID: "test-org", RequestID: "r1",
			Verb: "POST", TargetEndpoint: "/echo", TargetService: "echo",
			TargetURL: targetURL,
			Payload:   payload, SignerKID: a.kid,
			Signature: base64.RawURLEncoding.EncodeToString(reqSig),
			ExpiresAt: expiresAt,
		},
	}

	result, err := ScanConversation(messages, "r1", org)
	if err != nil {
		t.Fatal(err)
	}
	if result.ThresholdMet {
		t.Fatal("expected threshold NOT met")
	}
	if len(result.SignerKIDs) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(result.SignerKIDs))
	}
	t.Log("✅ ScanConversation threshold not met (1/2)")
}

func TestScanConversation_Expired(t *testing.T) {
	a := newTestSigner()
	org := &Org{
		ID:      "test-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}},
	}

	payload := json.RawMessage(`{}`)
	targetURL := "https://example.com/t"
	expiresAt := time.Now().Add(-1 * time.Second)
	signable := &GateSignable{OrgID: "test-org", RequestID: "r1", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	reqSig, _ := SignRequest(a.priv, signable)

	messages := []GateConversationMessage{
		{
			Type: GateMessageRequest, OrgID: "test-org", RequestID: "r1",
			Verb: "GET", TargetEndpoint: "/t", TargetService: "echo",
			TargetURL: targetURL,
			Payload:   payload, SignerKID: a.kid,
			Signature: base64.RawURLEncoding.EncodeToString(reqSig),
			ExpiresAt: expiresAt, // already expired
		},
	}

	result, err := ScanConversation(messages, "r1", org)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Expired {
		t.Fatal("expected expired")
	}
	if result.Status != StatusExpired {
		t.Fatalf("expected status expired, got %s", result.Status)
	}
	t.Log("✅ ScanConversation expired request")
}

func TestScanConversation_BadSignature(t *testing.T) {
	a := newTestSigner()
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	org := &Org{
		ID:      "test-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}},
	}

	payload := json.RawMessage(`{}`)
	targetURL := "https://example.com/t"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "test-org", RequestID: "r1", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	badSig, _ := SignRequest(wrongPriv, signable) // wrong key

	messages := []GateConversationMessage{
		{
			Type: GateMessageRequest, OrgID: "test-org", RequestID: "r1",
			Verb: "GET", TargetEndpoint: "/t", TargetService: "echo",
			TargetURL: targetURL,
			Payload:   payload, SignerKID: a.kid,
			Signature: base64.RawURLEncoding.EncodeToString(badSig),
			ExpiresAt: expiresAt,
		},
	}

	result, err := ScanConversation(messages, "r1", org)
	if err != nil {
		t.Fatal(err)
	}
	if result.ThresholdMet {
		t.Fatal("bad signature should not meet threshold")
	}
	if len(result.SignerKIDs) != 0 {
		t.Fatalf("expected 0 valid signers, got %d", len(result.SignerKIDs))
	}
	t.Log("✅ ScanConversation bad signature rejected")
}

func TestScanConversation_DuplicateSigner(t *testing.T) {
	a := newTestSigner()
	org := &Org{
		ID:      "test-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 2}},
	}

	payload := json.RawMessage(`{}`)
	targetURL := "https://example.com/t"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "test-org", RequestID: "r1", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	reqSig, _ := SignRequest(a.priv, signable)
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(a.priv, &ApprovalSignable{OrgID: "test-org", RequestID: "r1", RequestHash: reqHash})

	messages := []GateConversationMessage{
		{
			Type: GateMessageRequest, OrgID: "test-org", RequestID: "r1",
			Verb: "GET", TargetEndpoint: "/t", TargetService: "echo",
			TargetURL: targetURL,
			Payload:   payload, SignerKID: a.kid,
			Signature: base64.RawURLEncoding.EncodeToString(reqSig),
			ExpiresAt: expiresAt,
		},
		{
			Type: GateMessageApproval, OrgID: "test-org", RequestID: "r1",
			SignerKID: a.kid, Signature: base64.RawURLEncoding.EncodeToString(appSig),
		},
	}

	result, err := ScanConversation(messages, "r1", org)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SignerKIDs) != 1 {
		t.Fatalf("duplicate signer should count once, got %d", len(result.SignerKIDs))
	}
	if result.ThresholdMet {
		t.Fatal("duplicate signer should not meet threshold of 2")
	}
	t.Log("✅ ScanConversation duplicate signer counted once")
}

func TestScanConversation_NotFound(t *testing.T) {
	org := &Org{
		ID:    "test-org",
		Rules: []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}},
	}

	result, err := ScanConversation(nil, "nonexistent", org)
	if err != nil {
		t.Fatal(err)
	}
	if result.Found {
		t.Fatal("should not find nonexistent request")
	}
	t.Log("✅ ScanConversation request not found")
}

// --- Integration tests (HTTP) ---

func TestIntegration_2of3_Echo(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()
	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()

	a, b, c := newTestSigner(), newTestSigner(), newTestSigner()
	_ = c // carol not needed for 2-of-3

	// Create org
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "test-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "bob"},
			{"kid": c.kid, "public_key": encKey(c.pub), "label": "carol"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "/echo", "verb": "POST", "m": 2, "n": 3},
		},
	})

	// Add credential
	post(t, gateSrv.URL+"/v1/orgs/test-org/credentials", map[string]interface{}{
		"id": "echo-cred", "service": "echo", "value": "test_key_123",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	// A submits request as a conversation message
	payload := json.RawMessage(`{"test":true}`)
	targetURL := echoSrv.URL + "/echo"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "test-org", RequestID: "req-001", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := post(t, gateSrv.URL+"/v1/orgs/test-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "req-001", "verb": "POST",
		"target_endpoint": "/echo", "target_service": "echo",
		"target_url": targetURL,
		"payload":    payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})

	if s := resp["status"]; s != "pending" {
		t.Fatalf("expected pending, got %v", s)
	}

	// B approves via conversation message
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{
		OrgID: "test-org", RequestID: "req-001", RequestHash: reqHash,
	})
	resp = post(t, gateSrv.URL+"/v1/orgs/test-org/messages", map[string]interface{}{
		"type": "gate.approval", "request_id": "req-001",
		"signer_kid": b.kid, "signature": base64.RawURLEncoding.EncodeToString(appSig),
	})

	if s := resp["status"]; s != "executed" {
		t.Fatalf("expected executed, got %v", s)
	}

	execResult := resp["execution_result"].(map[string]interface{})
	if execResult["status_code"].(float64) != 200 {
		t.Fatalf("expected status 200, got %v", execResult["status_code"])
	}
	if _, hasBody := execResult["body"]; hasBody {
		t.Fatal("execution_result should not contain body (credential reflection risk)")
	}
	t.Log("✅ 2-of-3 echo integration passed (stateless)")
}

func TestIntegration_1of2_AutoExecute(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()
	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()

	a, b := newTestSigner(), newTestSigner()
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "low-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "bob"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "GET", "m": 1, "n": 2},
		},
	})
	post(t, gateSrv.URL+"/v1/orgs/low-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "key_lo",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	payload := json.RawMessage(`null`)
	targetURL := echoSrv.URL + "/balance"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "low-org", RequestID: "r1", Verb: "GET",
		TargetEndpoint: "/balance", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := post(t, gateSrv.URL+"/v1/orgs/low-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "r1", "verb": "GET",
		"target_endpoint": "/balance", "target_service": "echo",
		"target_url": targetURL,
		"payload":    payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})

	if s := resp["status"]; s != "executed" {
		t.Fatalf("expected auto-executed, got %v", s)
	}
	execResult := resp["execution_result"].(map[string]interface{})
	if _, hasBody := execResult["body"]; hasBody {
		t.Fatal("execution_result should not contain body")
	}
	t.Log("✅ 1-of-2 auto-execute passed (stateless)")
}

func TestIntegration_Expiration(t *testing.T) {
	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()

	a, b := newTestSigner(), newTestSigner()
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "exp-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "bob"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "POST", "m": 2, "n": 2},
		},
	})
	post(t, gateSrv.URL+"/v1/orgs/exp-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "k",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	// Submit with 2s expiration
	expiresAt := time.Now().Add(2 * time.Second)
	targetURL := "http://localhost:9999/echo"
	payload := json.RawMessage(`{"x":1}`)
	signable := &GateSignable{OrgID: "exp-org", RequestID: "r-exp", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := post(t, gateSrv.URL+"/v1/orgs/exp-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "r-exp", "verb": "POST",
		"target_endpoint": "/echo", "target_service": "echo",
		"target_url": targetURL,
		"payload":    payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt.Format(time.RFC3339Nano),
	})
	if resp["status"] != "pending" {
		t.Fatalf("expected pending, got %v", resp["status"])
	}

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// Try to approve — should fail (expired)
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{
		OrgID: "exp-org", RequestID: "r-exp", RequestHash: reqHash,
	})
	body, _ := json.Marshal(map[string]interface{}{
		"type": "gate.approval", "request_id": "r-exp",
		"signer_kid": b.kid, "signature": base64.RawURLEncoding.EncodeToString(appSig),
	})
	httpResp, _ := http.Post(gateSrv.URL+"/v1/orgs/exp-org/messages",
		"application/json", bytes.NewReader(body))
	if httpResp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", httpResp.StatusCode)
	}
	httpResp.Body.Close()

	// Scan should show expired
	scanResp := get(t, gateSrv.URL+"/v1/orgs/exp-org/scan/r-exp")
	if scanResp["status"] != "expired" {
		t.Fatalf("expected expired, got %v", scanResp["status"])
	}
	t.Log("✅ Expiration test passed (2s TTL, stateless)")
}

func TestIntegration_BadSignature(t *testing.T) {
	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()

	a := newTestSigner()
	_, wrongPriv, _ := ed25519.GenerateKey(nil)

	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "sig-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	payload := json.RawMessage(`{}`)
	targetURL := "http://localhost:9999/t"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "sig-org", RequestID: "r-bad", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(wrongPriv, signable) // wrong key!

	body, _ := json.Marshal(map[string]interface{}{
		"type": "gate.request", "request_id": "r-bad", "verb": "GET",
		"target_endpoint": "/t", "target_service": "echo",
		"target_url": targetURL,
		"payload":    payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})
	resp, _ := http.Post(gateSrv.URL+"/v1/orgs/sig-org/messages", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Bad signature rejected (stateless)")
}

func TestIntegration_UnknownOrg(t *testing.T) {
	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()
	resp, _ := http.Get(gateSrv.URL + "/v1/orgs/nope")
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Unknown org returns 404")
}

func TestIntegration_DuplicateRequest(t *testing.T) {
	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()

	a := newTestSigner()
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "dup-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 2, "n": 1},
		},
	})

	payload := json.RawMessage(`{}`)
	targetURL := "http://localhost:9999/t"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "dup-org", RequestID: "r-dup", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	msgBody := map[string]interface{}{
		"type": "gate.request", "request_id": "r-dup", "verb": "GET",
		"target_endpoint": "/t", "target_service": "echo",
		"target_url": targetURL,
		"payload":    payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	}
	post(t, gateSrv.URL+"/v1/orgs/dup-org/messages", msgBody) // first: OK

	body, _ := json.Marshal(msgBody)
	resp, _ := http.Post(gateSrv.URL+"/v1/orgs/dup-org/messages", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Duplicate request rejected (replay protection, stateless)")
}

func TestIntegration_ExplicitExecute(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()
	srv := NewInsecureServerForTests()
	gateSrv := httptest.NewServer(srv)
	defer gateSrv.Close()

	a, b := newTestSigner(), newTestSigner()
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "exec-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "bob"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "POST", "m": 2, "n": 2},
		},
	})
	post(t, gateSrv.URL+"/v1/orgs/exec-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "key_exec",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	// Post request and approval directly to conversation store (simulating qntm group messages)
	payload := json.RawMessage(`{"action":"test"}`)
	targetURL := echoSrv.URL + "/action"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "exec-org", RequestID: "r-exec", Verb: "POST",
		TargetEndpoint: "/action", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	reqSig, _ := SignRequest(a.priv, signable)
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{OrgID: "exec-org", RequestID: "r-exec", RequestHash: reqHash})

	srv.ConvStore.WriteGateMessage("exec-org", &GateConversationMessage{
		Type: GateMessageRequest, OrgID: "exec-org", RequestID: "r-exec",
		Verb: "POST", TargetEndpoint: "/action", TargetService: "echo",
		TargetURL: targetURL, Payload: payload,
		SignerKID: a.kid, Signature: base64.RawURLEncoding.EncodeToString(reqSig),
		ExpiresAt: expiresAt,
	})
	srv.ConvStore.WriteGateMessage("exec-org", &GateConversationMessage{
		Type: GateMessageApproval, OrgID: "exec-org", RequestID: "r-exec",
		SignerKID: b.kid, Signature: base64.RawURLEncoding.EncodeToString(appSig),
	})

	// Trigger explicit execute via HTTP
	body, _ := json.Marshal(map[string]string{})
	resp, err := http.Post(gateSrv.URL+"/v1/orgs/exec-org/execute/r-exec", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(data, &result)

	if result["status"] != "executed" {
		t.Fatalf("expected executed, got %v (body: %s)", result["status"], string(data))
	}
	execResult := result["execution_result"].(map[string]interface{})
	if execResult["status_code"].(float64) != 200 {
		t.Fatalf("expected 200, got %v", execResult["status_code"])
	}
	t.Log("✅ Explicit execute endpoint passed (stateless)")
}

func TestIntegration_AlreadyExecutedNotReexecuted(t *testing.T) {
	var hitCount int32
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer echoSrv.Close()

	gateSrv := httptest.NewServer(NewInsecureServerForTests())
	defer gateSrv.Close()

	a := newTestSigner()
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "idempotent-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "/once", "verb": "POST", "m": 1, "n": 1},
		},
	})
	post(t, gateSrv.URL+"/v1/orgs/idempotent-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "k",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	payload := json.RawMessage(`{"run":1}`)
	targetURL := echoSrv.URL + "/once"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{
		OrgID:          "idempotent-org",
		RequestID:      "once-1",
		Verb:           "POST",
		TargetEndpoint: "/once",
		TargetService:  "echo",
		TargetURL:      targetURL,
		ExpiresAtUnix:  expiresAt.Unix(),
		PayloadHash:    ComputePayloadHash(payload),
	}
	sig, _ := SignRequest(a.priv, signable)

	first := post(t, gateSrv.URL+"/v1/orgs/idempotent-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "once-1", "verb": "POST",
		"target_endpoint": "/once", "target_service": "echo", "target_url": targetURL,
		"payload": payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})
	if first["status"] != "executed" {
		t.Fatalf("expected first execution to run, got %v", first["status"])
	}

	second := post(t, gateSrv.URL+"/v1/orgs/idempotent-org/execute/once-1", map[string]string{})
	if second["status"] != "executed" {
		t.Fatalf("expected second execution status=executed, got %v", second["status"])
	}

	if got := atomic.LoadInt32(&hitCount); got != 1 {
		t.Fatalf("expected exactly one downstream call, got %d", got)
	}
}

func TestExecuteIfReady_CredentialStillUsableAcrossRequests(t *testing.T) {
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer keep_me" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer echoSrv.Close()

	signer := newTestSigner()
	org := &Org{
		ID: "cred-org",
		Signers: []Signer{
			{KID: signer.kid, PublicKey: signer.pub, Label: "alice"},
		},
		Rules: []ThresholdRule{
			{Service: "echo", Endpoint: "/auth", Verb: "POST", M: 1, N: 1},
		},
	}
	orgStore := NewOrgStore()
	if err := orgStore.Create(org); err != nil {
		t.Fatal(err)
	}
	if err := orgStore.AddCredential("cred-org", &Credential{
		ID:          "cred",
		Service:     "echo",
		Value:       "keep_me",
		HeaderName:  "Authorization",
		HeaderValue: "Bearer {value}",
	}); err != nil {
		t.Fatal(err)
	}

	conv := NewMemoryConversationStore()

	addRequest := func(requestID string) {
		payload := json.RawMessage(`{"ok":true}`)
		targetURL := echoSrv.URL + "/auth"
		expiresAt := time.Now().Add(1 * time.Hour)
		signable := &GateSignable{
			OrgID: "cred-org", RequestID: requestID, Verb: "POST",
			TargetEndpoint: "/auth", TargetService: "echo",
			TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
			PayloadHash: ComputePayloadHash(payload),
		}
		sig, _ := SignRequest(signer.priv, signable)
		if err := conv.WriteGateMessage("cred-org", &GateConversationMessage{
			Type: GateMessageRequest, OrgID: "cred-org", RequestID: requestID,
			Verb: "POST", TargetEndpoint: "/auth", TargetService: "echo",
			TargetURL: targetURL, Payload: payload, ExpiresAt: expiresAt,
			SignerKID: signer.kid, Signature: base64.RawURLEncoding.EncodeToString(sig),
		}); err != nil {
			t.Fatal(err)
		}
	}

	addRequest("r1")
	res1, err := ExecuteIfReady("r1", org, conv, orgStore)
	if err != nil {
		t.Fatalf("first execute failed: %v", err)
	}
	if res1.ExecutionResult == nil || res1.ExecutionResult.StatusCode != 200 {
		t.Fatalf("first execute status unexpected: %+v", res1.ExecutionResult)
	}

	addRequest("r2")
	res2, err := ExecuteIfReady("r2", org, conv, orgStore)
	if err != nil {
		t.Fatalf("second execute failed: %v", err)
	}
	if res2.ExecutionResult == nil || res2.ExecutionResult.StatusCode != 200 {
		t.Fatalf("second execute status unexpected: %+v", res2.ExecutionResult)
	}
}

// --- Helpers ---

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp := map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"had_auth":    r.Header.Get("Authorization") != "",
			"auth_header": r.Header.Get("Authorization"),
		}
		if json.Valid(body) && len(body) > 0 {
			resp["body"] = json.RawMessage(body)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
}

func encKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func post(t *testing.T, url string, v interface{}) map[string]interface{} {
	t.Helper()
	body, _ := json.Marshal(v)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		t.Fatalf("POST %s (%d): %s", url, resp.StatusCode, string(data))
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

func get(t *testing.T, url string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}
