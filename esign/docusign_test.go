package esign

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDocuSignCreateSignatureRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v2.1/accounts/acct-1/envelopes" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
			t.Fatalf("unexpected auth header: %q", got)
		}

		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if got := body["templateId"]; got != "tpl-1" {
			t.Fatalf("unexpected templateId: %v", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"envelopeId":"env-1","status":"sent"}`))
	}))
	defer ts.Close()

	provider, err := NewDocuSignProvider(DocuSignConfig{
		AccessToken: "token-1",
		AccountID:   "acct-1",
		BaseURL:     ts.URL,
		HTTPClient:  ts.Client(),
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	result, err := provider.CreateSignatureRequest(context.Background(), SignatureRequest{
		TemplateID: "tpl-1",
		Subject:    "Please sign",
		Message:    "Board action",
		Signers: []Signer{
			{Name: "Alice", Email: "alice@example.com", Role: "Signer1"},
		},
	})
	if err != nil {
		t.Fatalf("create signature request: %v", err)
	}
	if result.ProviderRequestID != "env-1" {
		t.Fatalf("unexpected provider request id: %q", result.ProviderRequestID)
	}
	if result.Status != StatusPending {
		t.Fatalf("unexpected status: %q", result.Status)
	}
}

func TestDocuSignGetSignatureRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/v2.1/accounts/acct-1/envelopes/env-1" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"envelopeId":"env-1","status":"completed"}`))
	}))
	defer ts.Close()

	provider, err := NewDocuSignProvider(DocuSignConfig{
		AccessToken: "token-1",
		AccountID:   "acct-1",
		BaseURL:     ts.URL,
		HTTPClient:  ts.Client(),
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	result, err := provider.GetSignatureRequest(context.Background(), "env-1")
	if err != nil {
		t.Fatalf("get signature request: %v", err)
	}
	if result.Status != StatusSigned {
		t.Fatalf("unexpected status: %q", result.Status)
	}
}

func TestDocuSignVerifyWebhook(t *testing.T) {
	provider, err := NewDocuSignProvider(DocuSignConfig{
		AccessToken:       "token-1",
		AccountID:         "acct-1",
		WebhookHMACSecret: "secret-1",
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	payload := []byte(`{"event":"envelope-completed"}`)
	mac := hmac.New(sha256.New, []byte("secret-1"))
	mac.Write(payload)
	header := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	headers := http.Header{"X-DocuSign-Signature-1": []string{header}}

	if err := provider.VerifyWebhook(payload, headers); err != nil {
		t.Fatalf("verify webhook: %v", err)
	}

	headers.Set("X-DocuSign-Signature-1", "bad")
	if err := provider.VerifyWebhook(payload, headers); err == nil {
		t.Fatal("expected invalid webhook signature")
	}
}
