package esign

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDropboxSignCreateSignatureRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/signature_request/send_with_template" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got == "" {
			t.Fatal("missing authorization header")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("template_id"); got != "tmpl-123" {
			t.Fatalf("unexpected template_id: %q", got)
		}
		if got := r.Form.Get("signers[Signer][email_address]"); got != "alice@example.com" {
			t.Fatalf("unexpected signer email: %q", got)
		}
		if got := r.Form.Get("metadata[external_request_id]"); got != "req-1" {
			t.Fatalf("unexpected external request metadata: %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"signature_request":{"signature_request_id":"sigreq-1","is_complete":false}}`))
	}))
	defer ts.Close()

	provider, err := NewDropboxSignProvider(DropboxSignConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	result, err := provider.CreateSignatureRequest(context.Background(), SignatureRequest{
		ExternalRequestID: "req-1",
		TemplateID:        "tmpl-123",
		Title:             "Board Consent",
		Subject:           "Please sign",
		Message:           "Sign this when ready",
		Signers: []Signer{
			{Name: "Alice", Email: "alice@example.com", Role: "Signer"},
		},
		Metadata: map[string]string{"workflow": "wire"},
	})
	if err != nil {
		t.Fatalf("create signature request: %v", err)
	}
	if result.ProviderRequestID != "sigreq-1" {
		t.Fatalf("unexpected request id: %q", result.ProviderRequestID)
	}
	if result.Status != StatusPending {
		t.Fatalf("unexpected status: %q", result.Status)
	}
}

func TestDropboxSignGetSignatureRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/signature_request/sigreq-1" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"signature_request":{"signature_request_id":"sigreq-1","is_complete":true}}`))
	}))
	defer ts.Close()

	provider, err := NewDropboxSignProvider(DropboxSignConfig{
		APIKey:     "test-api-key",
		BaseURL:    ts.URL,
		HTTPClient: ts.Client(),
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	result, err := provider.GetSignatureRequest(context.Background(), "sigreq-1")
	if err != nil {
		t.Fatalf("get signature request: %v", err)
	}
	if result.Status != StatusSigned {
		t.Fatalf("unexpected status: %q", result.Status)
	}
}

func TestDropboxSignVerifyWebhook(t *testing.T) {
	provider, err := NewDropboxSignProvider(DropboxSignConfig{APIKey: "abc123"})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	payload := map[string]any{
		"event": map[string]any{
			"event_time": "1700000000",
			"event_type": "signature_request_all_signed",
		},
	}
	mac := hmac.New(sha256.New, []byte("abc123"))
	mac.Write([]byte("1700000000signature_request_all_signed"))
	eventHash := hex.EncodeToString(mac.Sum(nil))
	payload["event"].(map[string]any)["event_hash"] = eventHash

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	if err := provider.VerifyWebhook(body, http.Header{}); err != nil {
		t.Fatalf("verify webhook: %v", err)
	}

	payload["event"].(map[string]any)["event_hash"] = "deadbeef"
	badBody, _ := json.Marshal(payload)
	if err := provider.VerifyWebhook(badBody, http.Header{}); err == nil {
		t.Fatal("expected invalid webhook signature")
	}
}
