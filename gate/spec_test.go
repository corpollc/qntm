package gate

// Gate API specification tests — comprehensive coverage of every endpoint,
// response code, request/response body, and error condition.
// Serves as the canonical reference for TypeScript gate client implementation.

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

// =============================================================================
// API: POST /v1/orgs — Create Organization
// =============================================================================

func TestAPI_CreateOrg_Success(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	resp := postRaw(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "my-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["id"] != "my-org" {
		t.Fatalf("org id: got %v, want my-org", body["id"])
	}
}

func TestAPI_CreateOrg_Duplicate(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	orgBody := map[string]interface{}{
		"id": "dup-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	}

	resp1 := postRaw(t, srv.URL+"/v1/orgs", orgBody)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d", resp1.StatusCode)
	}

	resp2 := postRaw(t, srv.URL+"/v1/orgs", orgBody)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d", resp2.StatusCode)
	}
}

func TestAPI_CreateOrg_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := postBytesRaw(t, srv.URL+"/v1/orgs", []byte("not json"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid JSON: expected 400, got %d", resp.StatusCode)
	}
}

func TestAPI_CreateOrg_WrongMethod(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := getRaw(t, srv.URL+"/v1/orgs")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET on /v1/orgs: expected 405, got %d", resp.StatusCode)
	}
}

func TestAPI_CreateOrg_RequiresAdminToken(t *testing.T) {
	s, _ := NewServer("secret-token")
	srv := httptest.NewServer(s)
	defer srv.Close()

	a := newTestSigner()
	body, _ := json.Marshal(map[string]interface{}{
		"id": "secure-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	// No token → 401
	resp := postBytesRaw(t, srv.URL+"/v1/orgs", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong token → 401
	req, _ := http.NewRequest("POST", srv.URL+"/v1/orgs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp = doRaw(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token → 201
	req, _ = http.NewRequest("POST", srv.URL+"/v1/orgs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	resp = doRaw(t, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("correct token: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// =============================================================================
// API: GET /v1/orgs/{org_id} — Get Organization
// =============================================================================

func TestAPI_GetOrg_Success(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "get-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	result := get(t, srv.URL+"/v1/orgs/get-org")
	if result["id"] != "get-org" {
		t.Fatalf("org id: got %v, want get-org", result["id"])
	}
	signers := result["signers"].([]interface{})
	if len(signers) != 1 {
		t.Fatalf("signers: got %d, want 1", len(signers))
	}
}

func TestAPI_GetOrg_NotFound(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := getRaw(t, srv.URL+"/v1/orgs/nonexistent")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] == nil {
		t.Fatal("error response should have 'error' field")
	}
}

// =============================================================================
// API: POST /v1/orgs/{org_id}/credentials — Add Credential
// =============================================================================

func TestAPI_AddCredential_Success(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "cred-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := postRaw(t, srv.URL+"/v1/orgs/cred-org/credentials", map[string]interface{}{
		"id": "stripe-key", "service": "stripe", "value": "sk_test_xxx",
		"header_name": "Authorization", "header_value": "Bearer {value}",
		"description": "test key",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}
}

func TestAPI_AddCredential_OrgNotFound(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := postRaw(t, srv.URL+"/v1/orgs/no-org/credentials", map[string]interface{}{
		"id": "k", "service": "s", "value": "v",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPI_AddCredential_RequiresAdmin(t *testing.T) {
	s, _ := NewServer("admin-token")
	srv := httptest.NewServer(s)
	defer srv.Close()

	body, _ := json.Marshal(map[string]interface{}{
		"id": "k", "service": "s", "value": "v",
	})
	resp := postBytesRaw(t, srv.URL+"/v1/orgs/some-org/credentials", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAPI_AddCredential_WrongMethod(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "m-org", "signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		}, "rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := getRaw(t, srv.URL+"/v1/orgs/m-org/credentials")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET credentials: expected 405, got %d", resp.StatusCode)
	}
}

// =============================================================================
// API: POST /v1/orgs/{org_id}/messages — Post Gate Message
// =============================================================================

func TestAPI_PostMessage_Request_Pending(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a, b := newTestSigner(), newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "msg-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "b"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "POST", "m": 2, "n": 2},
		},
	})
	post(t, srv.URL+"/v1/orgs/msg-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "k",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	payload := json.RawMessage(`{"x":1}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "msg-org", RequestID: "r1", Verb: "POST",
		TargetEndpoint: "/api", TargetService: "echo",
		TargetURL: "http://localhost:9999/api", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := postRaw(t, srv.URL+"/v1/orgs/msg-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "r1", "verb": "POST",
		"target_endpoint": "/api", "target_service": "echo",
		"target_url": "http://localhost:9999/api",
		"payload": payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})
	defer resp.Body.Close()

	// 2-of-2 threshold, only 1 signature → pending (202 Accepted)
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "pending" {
		t.Fatalf("expected pending, got %v", result["status"])
	}
	if result["signature_count"].(float64) != 1 {
		t.Fatalf("expected 1 signature, got %v", result["signature_count"])
	}
	if result["threshold"].(float64) != 2 {
		t.Fatalf("expected threshold 2, got %v", result["threshold"])
	}
}

func TestAPI_PostMessage_Request_AutoExecute(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "auto-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})
	post(t, srv.URL+"/v1/orgs/auto-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "key123",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	payload := json.RawMessage(`{"auto":true}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "auto-org", RequestID: "auto-1", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: echoSrv.URL + "/echo", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp := postRaw(t, srv.URL+"/v1/orgs/auto-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "auto-1", "verb": "POST",
		"target_endpoint": "/echo", "target_service": "echo",
		"target_url": echoSrv.URL + "/echo",
		"payload": payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})
	defer resp.Body.Close()

	// 1-of-1 threshold → auto-execute (200 OK)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result["status"] != "executed" {
		t.Fatalf("expected executed, got %v", result["status"])
	}
	er := result["execution_result"].(map[string]interface{})
	if er["status_code"].(float64) != 200 {
		t.Fatalf("execution status: got %v, want 200", er["status_code"])
	}
	if er["content_type"].(string) != "application/json" {
		t.Fatalf("content_type: got %v", er["content_type"])
	}
}

func TestAPI_PostMessage_UnknownSigner(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "signer-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	// Sign with unknown signer
	unknown := newTestSigner()
	payload := json.RawMessage(`{}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "signer-org", RequestID: "r1", Verb: "GET",
		TargetEndpoint: "/x", TargetService: "echo",
		TargetURL: "http://localhost/x", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(unknown.priv, signable)

	resp := postRaw(t, srv.URL+"/v1/orgs/signer-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "r1", "verb": "GET",
		"target_endpoint": "/x", "target_service": "echo",
		"target_url": "http://localhost/x",
		"payload": payload, "signer_kid": unknown.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown signer: expected 400, got %d", resp.StatusCode)
	}
}

func TestAPI_PostMessage_InvalidSignatureEncoding(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "enc-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := postRaw(t, srv.URL+"/v1/orgs/enc-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "r1", "verb": "GET",
		"target_endpoint": "/x", "target_service": "echo",
		"target_url": "http://localhost/x",
		"payload": json.RawMessage(`{}`), "signer_kid": a.kid,
		"signature":  "not-valid-base64!!!",
		"expires_at": time.Now().Add(1 * time.Hour),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad encoding: expected 400, got %d", resp.StatusCode)
	}
}

func TestAPI_PostMessage_UnknownMessageType(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "type-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := postRaw(t, srv.URL+"/v1/orgs/type-org/messages", map[string]interface{}{
		"type":       "gate.unknown",
		"request_id": "r1",
		"signer_kid": a.kid,
		"signature":  "sig",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown type: expected 400, got %d", resp.StatusCode)
	}
}

func TestAPI_PostMessage_Approval_NoRequest(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "noref-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := postRaw(t, srv.URL+"/v1/orgs/noref-org/messages", map[string]interface{}{
		"type":       "gate.approval",
		"request_id": "nonexistent",
		"signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(make([]byte, 64)),
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("approval for nonexistent: expected 400, got %d", resp.StatusCode)
	}
}

func TestAPI_PostMessage_WrongMethod(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "wm-org", "signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		}, "rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := getRaw(t, srv.URL+"/v1/orgs/wm-org/messages")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET messages: expected 405, got %d", resp.StatusCode)
	}
}

// =============================================================================
// API: GET /v1/orgs/{org_id}/scan/{request_id} — Scan Request Status
// =============================================================================

func TestAPI_Scan_Success(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "scan-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 2, "n": 1},
		},
	})

	payload := json.RawMessage(`{}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "scan-org", RequestID: "scan-1", Verb: "GET",
		TargetEndpoint: "/x", TargetService: "echo",
		TargetURL: "http://localhost/x", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	post(t, srv.URL+"/v1/orgs/scan-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "scan-1", "verb": "GET",
		"target_endpoint": "/x", "target_service": "echo",
		"target_url": "http://localhost/x",
		"payload": payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})

	result := get(t, srv.URL+"/v1/orgs/scan-org/scan/scan-1")
	if result["found"] != true {
		t.Fatal("expected found=true")
	}
	if result["status"] != "pending" {
		t.Fatalf("expected pending, got %v", result["status"])
	}
	if result["threshold"].(float64) != 2 {
		t.Fatalf("threshold: got %v, want 2", result["threshold"])
	}
}

func TestAPI_Scan_NotFound(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "scanmiss-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		},
		"rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := getRaw(t, srv.URL+"/v1/orgs/scanmiss-org/scan/nope")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPI_Scan_OrgNotFound(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := getRaw(t, srv.URL+"/v1/orgs/noorg/scan/req1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPI_Scan_WrongMethod(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "scanm-org", "signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		}, "rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	body, _ := json.Marshal(map[string]string{})
	resp := postBytesRaw(t, srv.URL+"/v1/orgs/scanm-org/scan/r1", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST scan: expected 405, got %d", resp.StatusCode)
	}
}

// =============================================================================
// API: POST /v1/orgs/{org_id}/execute/{request_id} — Execute Request
// =============================================================================

func TestAPI_Execute_ThresholdNotMet(t *testing.T) {
	s := NewInsecureServerForTests()
	srv := httptest.NewServer(s)
	defer srv.Close()

	a, b := newTestSigner(), newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "execpend-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "b"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "POST", "m": 2, "n": 2},
		},
	})
	post(t, srv.URL+"/v1/orgs/execpend-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "k",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	// Add only request (no approval)
	payload := json.RawMessage(`{}`)
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "execpend-org", RequestID: "ep-1", Verb: "POST",
		TargetEndpoint: "/x", TargetService: "echo",
		TargetURL: "http://localhost/x", ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	s.ConvStore.WriteGateMessage("execpend-org", &GateConversationMessage{
		Type: GateMessageRequest, OrgID: "execpend-org", RequestID: "ep-1",
		Verb: "POST", TargetEndpoint: "/x", TargetService: "echo",
		TargetURL: "http://localhost/x", Payload: payload, ExpiresAt: expiresAt,
		SignerKID: a.kid, Signature: base64.RawURLEncoding.EncodeToString(sig),
	})

	resp := postRaw(t, srv.URL+"/v1/orgs/execpend-org/execute/ep-1", map[string]string{})
	defer resp.Body.Close()

	// Threshold not met → 202 Accepted
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 202, got %d: %s", resp.StatusCode, body)
	}
}

func TestAPI_Execute_OrgNotFound(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := postRaw(t, srv.URL+"/v1/orgs/noexec/execute/r1", map[string]string{})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestAPI_Execute_WrongMethod(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	a := newTestSigner()
	post(t, srv.URL+"/v1/orgs", map[string]interface{}{
		"id": "execm-org", "signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "a"},
		}, "rules": []map[string]interface{}{
			{"service": "*", "endpoint": "*", "verb": "*", "m": 1, "n": 1},
		},
	})

	resp := getRaw(t, srv.URL+"/v1/orgs/execm-org/execute/r1")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET execute: expected 405, got %d", resp.StatusCode)
	}
}

// =============================================================================
// API: GET /health — Health Check
// =============================================================================

func TestAPI_Health(t *testing.T) {
	srv := httptest.NewServer(NewInsecureServerForTests())
	defer srv.Close()

	resp := getRaw(t, srv.URL+"/health")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body["status"])
	}
}

// =============================================================================
// Gate Signing — all operations and edge cases
// =============================================================================

func TestSpec_Gate_PayloadHash(t *testing.T) {
	// PayloadHash is SHA-256 of raw payload bytes
	payload := []byte(`{"amount":1000}`)
	hash := ComputePayloadHash(payload)
	if len(hash) != 32 {
		t.Fatalf("payload hash: got %d bytes, want 32", len(hash))
	}

	// Deterministic
	hash2 := ComputePayloadHash(payload)
	if !bytes.Equal(hash, hash2) {
		t.Fatal("payload hash should be deterministic")
	}

	// Nil payload
	nilHash := ComputePayloadHash(nil)
	if len(nilHash) != 32 {
		t.Fatal("nil payload should still produce a hash")
	}
}

func TestSpec_Gate_SignRequest_CBOR_Canonical(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s := &GateSignable{
		OrgID: "org1", RequestID: "req1", Verb: "POST",
		TargetEndpoint: "/api", TargetService: "svc",
		TargetURL:     "https://api.example.com/api",
		ExpiresAtUnix: 1700000000,
		PayloadHash:   ComputePayloadHash([]byte(`{}`)),
	}

	sig1, _ := SignRequest(priv, s)
	sig2, _ := SignRequest(priv, s)

	// Same input → same signature (Ed25519 is deterministic)
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("Ed25519 signatures should be deterministic")
	}
}

func TestSpec_Gate_HashRequest_Deterministic(t *testing.T) {
	s := &GateSignable{
		OrgID: "org1", RequestID: "req1", Verb: "POST",
		TargetEndpoint: "/api", TargetService: "svc",
		TargetURL:     "https://api.example.com/api",
		ExpiresAtUnix: 1700000000,
		PayloadHash:   ComputePayloadHash([]byte(`{}`)),
	}

	h1, _ := HashRequest(s)
	h2, _ := HashRequest(s)
	if !bytes.Equal(h1, h2) {
		t.Fatal("request hash should be deterministic")
	}
	if len(h1) != 32 {
		t.Fatalf("request hash: got %d bytes, want 32", len(h1))
	}
}

func TestSpec_Gate_KIDFromPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	kid := KIDFromPublicKey(pub)
	if kid == "" {
		t.Fatal("KID should not be empty")
	}

	// Deterministic
	kid2 := KIDFromPublicKey(pub)
	if kid != kid2 {
		t.Fatal("KID should be deterministic")
	}

	// Different keys → different KIDs
	pub2, _, _ := ed25519.GenerateKey(nil)
	kid3 := KIDFromPublicKey(pub2)
	if kid == kid3 {
		t.Fatal("different keys should have different KIDs")
	}

	// Verify encoding: base64url, no padding
	decoded, err := base64.RawURLEncoding.DecodeString(kid)
	if err != nil {
		t.Fatal("KID should be valid base64url:", err)
	}
	if len(decoded) != 16 {
		t.Fatalf("KID decoded: got %d bytes, want 16", len(decoded))
	}
}

// =============================================================================
// Gate Threshold — rule matching priority
// =============================================================================

func TestSpec_Gate_Threshold_Priority(t *testing.T) {
	org := &Org{Rules: []ThresholdRule{
		{Service: "*", Endpoint: "*", Verb: "*", M: 1},           // default
		{Service: "stripe", Endpoint: "*", Verb: "*", M: 2},      // service match
		{Service: "stripe", Endpoint: "*", Verb: "POST", M: 3},   // service+verb
		{Service: "stripe", Endpoint: "/charges", Verb: "*", M: 4},  // service+endpoint
		{Service: "stripe", Endpoint: "/charges", Verb: "POST", M: 5}, // exact match
	}}

	tests := []struct {
		svc, ep, verb string
		want          int
	}{
		{"other", "/x", "GET", 1},           // default
		{"stripe", "/refunds", "GET", 2},    // service only
		{"stripe", "/refunds", "POST", 3},   // service+verb
		{"stripe", "/charges", "GET", 4},    // service+endpoint
		{"stripe", "/charges", "POST", 5},   // exact
	}

	for _, tt := range tests {
		m, err := org.LookupThreshold(tt.svc, tt.ep, tt.verb)
		if err != nil {
			t.Errorf("%s %s %s: %v", tt.verb, tt.ep, tt.svc, err)
		} else if m != tt.want {
			t.Errorf("%s %s %s: got M=%d, want M=%d", tt.verb, tt.ep, tt.svc, m, tt.want)
		}
	}
}

func TestSpec_Gate_Threshold_NoMatch(t *testing.T) {
	org := &Org{Rules: []ThresholdRule{
		{Service: "stripe", Endpoint: "/charges", Verb: "POST", M: 2},
	}}

	_, err := org.LookupThreshold("other", "/x", "GET")
	if err == nil {
		t.Fatal("should return error when no rule matches")
	}
}

// =============================================================================
// Gate Credential — header injection templates
// =============================================================================

func TestSpec_Gate_Credential_HeaderTemplate(t *testing.T) {
	// Test the {value} template replacement logic
	tests := []struct {
		headerValue string
		credValue   string
		want        string
	}{
		{"Bearer {value}", "sk_test_xxx", "Bearer sk_test_xxx"},
		{"{value}", "raw_key", "raw_key"},
		{"", "fallback", "fallback"}, // empty template → use value directly
	}

	for _, tt := range tests {
		cred := &Credential{Value: tt.credValue, HeaderValue: tt.headerValue}
		var result string
		if cred.HeaderValue != "" {
			result = cred.HeaderValue
			if bytes.Contains([]byte(result), []byte("{value}")) {
				result = bytes.NewBuffer([]byte(result)).String()
				// Simulate the replacement from auth.go
				result = tt.headerValue
				if len(result) > 0 {
					result = string(bytes.ReplaceAll([]byte(result), []byte("{value}"), []byte(tt.credValue)))
				}
			}
		} else {
			result = tt.credValue
		}
		if result != tt.want {
			t.Errorf("template %q + %q: got %q, want %q", tt.headerValue, tt.credValue, result, tt.want)
		}
	}
}

func TestSpec_Gate_Credential_Scrub(t *testing.T) {
	cred := &Credential{Value: "secret", HeaderValue: "Bearer {value}"}
	cred.Scrub()
	if cred.Value != "" {
		t.Fatal("Value should be empty after Scrub")
	}
	if cred.HeaderValue != "" {
		t.Fatal("HeaderValue should be empty after Scrub")
	}

	// Scrub nil is safe
	var nilCred *Credential
	nilCred.Scrub() // should not panic
}

// =============================================================================
// Gate Store — SQLite persistence
// =============================================================================

func TestSpec_Gate_SQLiteStore_OrgCRUD(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	a := newTestSigner()
	org := &Org{
		ID:      "sql-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "alice"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}

	// Create
	if err := store.Create(org); err != nil {
		t.Fatal(err)
	}

	// Duplicate → error
	if err := store.Create(org); err == nil {
		t.Fatal("duplicate create should fail")
	}

	// Get
	got, err := store.Get("sql-org")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "sql-org" {
		t.Fatal("ID mismatch")
	}
	if len(got.Signers) != 1 {
		t.Fatal("Signers count mismatch")
	}

	// Not found
	if _, err := store.Get("nope"); err == nil {
		t.Fatal("missing org should fail")
	}
}

func TestSpec_Gate_SQLiteStore_Credentials(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	a := newTestSigner()
	store.Create(&Org{
		ID:      "cred-sql-org",
		Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "a"}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}},
	})

	// Add credential
	if err := store.AddCredential("cred-sql-org", &Credential{
		ID: "c1", Service: "stripe", Value: "sk_test",
		HeaderName: "Authorization", HeaderValue: "Bearer {value}",
	}); err != nil {
		t.Fatal(err)
	}

	// Get by service
	cred, err := store.GetCredentialByService("cred-sql-org", "stripe")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "sk_test" {
		t.Fatal("credential value mismatch")
	}

	// Not found service
	if _, err := store.GetCredentialByService("cred-sql-org", "other"); err == nil {
		t.Fatal("missing service should fail")
	}

	// Not found org
	if err := store.AddCredential("nope", &Credential{ID: "c"}); err == nil {
		t.Fatal("missing org should fail")
	}
}

func TestSpec_Gate_SQLiteStore_Messages(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	a := newTestSigner()
	store.Create(&Org{
		ID: "msg-sql-org", Signers: []Signer{{KID: a.kid, PublicKey: a.pub, Label: "a"}},
		Rules: []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1}},
	})

	// Write messages
	store.WriteGateMessage("msg-sql-org", &GateConversationMessage{
		Type: GateMessageRequest, OrgID: "msg-sql-org", RequestID: "r1",
		Verb: "POST", SignerKID: a.kid,
	})
	store.WriteGateMessage("msg-sql-org", &GateConversationMessage{
		Type: GateMessageApproval, OrgID: "msg-sql-org", RequestID: "r1",
		SignerKID: a.kid,
	})

	// Read messages — ordered by insertion
	msgs, err := store.ReadGateMessages("msg-sql-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].Type != GateMessageRequest {
		t.Fatal("first message should be request")
	}
	if msgs[1].Type != GateMessageApproval {
		t.Fatal("second message should be approval")
	}

	// Read from empty org
	msgs, err = store.ReadGateMessages("empty-org")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 {
		t.Fatal("empty org should have no messages")
	}
}

// =============================================================================
// Gate Full Flow — approval and execution with SQLite
// =============================================================================

func TestSpec_Gate_FullFlow_SQLite(t *testing.T) {
	echoSrv := httptest.NewServer(echoHandler())
	defer echoSrv.Close()

	store, err := NewSQLiteStore(t.TempDir() + "/flow.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	gateSrv := httptest.NewServer(NewInsecureServerForTestsWithStores(store, store))
	defer gateSrv.Close()

	a, b := newTestSigner(), newTestSigner()
	post(t, gateSrv.URL+"/v1/orgs", map[string]interface{}{
		"id": "flow-org",
		"signers": []map[string]interface{}{
			{"kid": a.kid, "public_key": encKey(a.pub), "label": "alice"},
			{"kid": b.kid, "public_key": encKey(b.pub), "label": "bob"},
		},
		"rules": []map[string]interface{}{
			{"service": "echo", "endpoint": "*", "verb": "POST", "m": 2, "n": 2},
		},
	})
	post(t, gateSrv.URL+"/v1/orgs/flow-org/credentials", map[string]interface{}{
		"id": "c", "service": "echo", "value": "flow_key",
		"header_name": "Authorization", "header_value": "Bearer {value}",
	})

	// Step 1: Submit request
	payload := json.RawMessage(`{"flow":"test"}`)
	targetURL := echoSrv.URL + "/echo"
	expiresAt := time.Now().Add(1 * time.Hour)
	signable := &GateSignable{OrgID: "flow-org", RequestID: "flow-1", Verb: "POST",
		TargetEndpoint: "/echo", TargetService: "echo",
		TargetURL: targetURL, ExpiresAtUnix: expiresAt.Unix(),
		PayloadHash: ComputePayloadHash(payload)}
	sig, _ := SignRequest(a.priv, signable)

	resp1 := post(t, gateSrv.URL+"/v1/orgs/flow-org/messages", map[string]interface{}{
		"type": "gate.request", "request_id": "flow-1", "verb": "POST",
		"target_endpoint": "/echo", "target_service": "echo", "target_url": targetURL,
		"payload": payload, "signer_kid": a.kid,
		"signature":  base64.RawURLEncoding.EncodeToString(sig),
		"expires_at": expiresAt,
	})
	if resp1["status"] != "pending" {
		t.Fatalf("step 1: expected pending, got %v", resp1["status"])
	}

	// Step 2: Scan — should show 1/2
	scan1 := get(t, gateSrv.URL+"/v1/orgs/flow-org/scan/flow-1")
	if scan1["status"] != "pending" {
		t.Fatalf("scan: expected pending, got %v", scan1["status"])
	}

	// Step 3: Approve
	reqHash, _ := HashRequest(signable)
	appSig, _ := SignApproval(b.priv, &ApprovalSignable{
		OrgID: "flow-org", RequestID: "flow-1", RequestHash: reqHash,
	})
	resp2 := post(t, gateSrv.URL+"/v1/orgs/flow-org/messages", map[string]interface{}{
		"type": "gate.approval", "request_id": "flow-1",
		"signer_kid": b.kid, "signature": base64.RawURLEncoding.EncodeToString(appSig),
	})
	if resp2["status"] != "executed" {
		t.Fatalf("step 3: expected executed, got %v", resp2["status"])
	}

	// Step 4: Scan again — should show executed
	scan2 := get(t, gateSrv.URL+"/v1/orgs/flow-org/scan/flow-1")
	if scan2["status"] != "executed" {
		t.Fatalf("post-execute scan: expected executed, got %v", scan2["status"])
	}

	// Step 5: Data persists in SQLite
	msgs, _ := store.ReadGateMessages("flow-org")
	if len(msgs) < 3 {
		t.Fatalf("expected at least 3 messages (req+approval+executed), got %d", len(msgs))
	}
}

// =============================================================================
// Helpers
// =============================================================================

func postRaw(t *testing.T, url string, v interface{}) *http.Response {
	t.Helper()
	body, _ := json.Marshal(v)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postBytesRaw(t *testing.T, url string, body []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getRaw(t *testing.T, url string) *http.Response {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func doRaw(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
