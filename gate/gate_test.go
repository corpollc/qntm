package gate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

// --- Integration tests ---

func TestIntegration_2of3_Echo(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()
	gateSrv := httptest.NewServer(NewServer())
	defer gateSrv.Close()

	a, b, c := newTestSigner(), newTestSigner(), newTestSigner()

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

	// A submits
	payload := json.RawMessage(`{"test":true}`)
	signable := &GateSignable{OrgID: "test-org", RequestID: "req-001", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := post(t, gateSrv.URL+"/v1/orgs/test-org/requests", map[string]interface{}{
		"request_id": "req-001", "verb": "POST",
		"target_endpoint": "/echo", "target_service": "echo",
		"target_url": echoSrv.URL + "/echo",
		"payload": payload, "requester_kid": a.kid,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})

	if s := resp["status"]; s != "pending" {
		t.Fatalf("expected pending, got %v", s)
	}

	// B approves
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{
		OrgID: "test-org", RequestID: "req-001", RequestHash: reqHash,
	})
	resp = post(t, gateSrv.URL+"/v1/orgs/test-org/requests/req-001/approve", map[string]string{
		"signer_kid": b.kid, "signature": base64.RawURLEncoding.EncodeToString(appSig),
	})

	if s := resp["status"]; s != "executed" {
		t.Fatalf("expected executed, got %v", s)
	}

	execResult := resp["execution_result"].(map[string]interface{})
	body := execResult["body"].(map[string]interface{})
	if body["had_auth"] != true {
		t.Fatal("echo didn't receive auth")
	}
	if body["auth_header"] != "Bearer test_key_123" {
		t.Fatalf("wrong auth: %v", body["auth_header"])
	}
	t.Log("✅ 2-of-3 echo integration passed")
}

func TestIntegration_1of2_AutoExecute(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()
	gateSrv := httptest.NewServer(NewServer())
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
	signable := &GateSignable{OrgID: "low-org", RequestID: "r1", Verb: "GET",
		TargetEndpoint: "/balance", TargetService: "echo",
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := post(t, gateSrv.URL+"/v1/orgs/low-org/requests", map[string]interface{}{
		"request_id": "r1", "verb": "GET", "target_endpoint": "/balance",
		"target_service": "echo", "target_url": echoSrv.URL + "/balance",
		"payload": payload, "requester_kid": a.kid,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})

	if s := resp["status"]; s != "executed" {
		t.Fatalf("expected auto-executed, got %v", s)
	}
	t.Log("✅ 1-of-2 auto-execute passed")
}

func TestIntegration_Expiration(t *testing.T) {
	gateSrv := httptest.NewServer(NewServer())
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
	payload := json.RawMessage(`{"x":1}`)
	signable := &GateSignable{OrgID: "exp-org", RequestID: "r-exp", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := post(t, gateSrv.URL+"/v1/orgs/exp-org/requests", map[string]interface{}{
		"request_id": "r-exp", "verb": "POST", "target_endpoint": "/echo",
		"target_service": "echo", "target_url": "http://localhost:9999/echo",
		"payload": payload, "requester_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt.Format(time.RFC3339Nano),
	})
	if resp["status"] != "pending" {
		t.Fatalf("expected pending, got %v", resp["status"])
	}

	// Wait for expiration
	time.Sleep(3 * time.Second)

	// Try to approve — should fail
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{
		OrgID: "exp-org", RequestID: "r-exp", RequestHash: reqHash,
	})
	body, _ := json.Marshal(map[string]string{
		"signer_kid": b.kid, "signature": base64.RawURLEncoding.EncodeToString(appSig),
	})
	httpResp, _ := http.Post(gateSrv.URL+"/v1/orgs/exp-org/requests/r-exp/approve",
		"application/json", bytes.NewReader(body))
	if httpResp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", httpResp.StatusCode)
	}
	httpResp.Body.Close()

	// Status should show expired
	statusResp := get(t, gateSrv.URL+"/v1/orgs/exp-org/requests/r-exp")
	if statusResp["status"] != "expired" {
		t.Fatalf("expected expired, got %v", statusResp["status"])
	}
	t.Log("✅ Expiration test passed (2s TTL)")
}

func TestIntegration_BadSignature(t *testing.T) {
	gateSrv := httptest.NewServer(NewServer())
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
	signable := &GateSignable{OrgID: "sig-org", RequestID: "r-bad", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(wrongPriv, signable) // wrong key!

	body, _ := json.Marshal(map[string]interface{}{
		"request_id": "r-bad", "verb": "GET", "target_endpoint": "/t",
		"target_service": "echo", "target_url": "http://localhost:9999/t",
		"payload": payload, "requester_kid": a.kid,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	resp, _ := http.Post(gateSrv.URL+"/v1/orgs/sig-org/requests", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Bad signature rejected")
}

func TestIntegration_UnknownOrg(t *testing.T) {
	gateSrv := httptest.NewServer(NewServer())
	defer gateSrv.Close()
	resp, _ := http.Get(gateSrv.URL + "/v1/orgs/nope")
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Unknown org returns 404")
}

func TestIntegration_DuplicateRequest(t *testing.T) {
	gateSrv := httptest.NewServer(NewServer())
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
	signable := &GateSignable{OrgID: "dup-org", RequestID: "r-dup", Verb: "GET",
		TargetEndpoint: "/t", TargetService: "echo",
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	submitBody := map[string]interface{}{
		"request_id": "r-dup", "verb": "GET", "target_endpoint": "/t",
		"target_service": "echo", "target_url": "http://localhost:9999/t",
		"payload": payload, "requester_kid": a.kid,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	post(t, gateSrv.URL+"/v1/orgs/dup-org/requests", submitBody) // first: OK

	body, _ := json.Marshal(submitBody)
	resp, _ := http.Post(gateSrv.URL+"/v1/orgs/dup-org/requests", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
	t.Log("✅ Duplicate request rejected (replay protection)")
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
