package esign

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultDropboxSignBaseURL = "https://api.hellosign.com/v3"

// DropboxSignConfig configures the Dropbox Sign provider.
type DropboxSignConfig struct {
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

// DropboxSignProvider implements the provider contract for Dropbox Sign.
type DropboxSignProvider struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

func NewDropboxSignProvider(cfg DropboxSignConfig) (*DropboxSignProvider, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("dropbox sign api key is required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultDropboxSignBaseURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &DropboxSignProvider{
		apiKey:     cfg.APIKey,
		baseURL:    baseURL,
		httpClient: client,
	}, nil
}

func (p *DropboxSignProvider) Name() string { return "dropbox_sign" }

func (p *DropboxSignProvider) CreateSignatureRequest(ctx context.Context, req SignatureRequest) (*SignatureRequestResult, error) {
	if strings.TrimSpace(req.TemplateID) == "" {
		return nil, fmt.Errorf("template_id is required for dropbox sign")
	}
	if len(req.Signers) == 0 {
		return nil, fmt.Errorf("at least one signer is required")
	}

	form := url.Values{}
	form.Set("template_id", req.TemplateID)
	if req.Title != "" {
		form.Set("title", req.Title)
	}
	if req.Subject != "" {
		form.Set("subject", req.Subject)
	}
	if req.Message != "" {
		form.Set("message", req.Message)
	}
	if req.TestMode {
		form.Set("test_mode", "1")
	}
	if req.ExternalRequestID != "" {
		form.Set("metadata[external_request_id]", req.ExternalRequestID)
	}
	for k, v := range req.Metadata {
		if strings.TrimSpace(k) == "" {
			continue
		}
		form.Set(fmt.Sprintf("metadata[%s]", k), v)
	}
	for _, signer := range req.Signers {
		if strings.TrimSpace(signer.Role) == "" {
			return nil, fmt.Errorf("dropbox sign template signer role is required")
		}
		form.Set(fmt.Sprintf("signers[%s][name]", signer.Role), signer.Name)
		form.Set(fmt.Sprintf("signers[%s][email_address]", signer.Role), signer.Email)
	}
	for _, cc := range req.CCs {
		if strings.TrimSpace(cc.Role) == "" {
			continue
		}
		form.Set(fmt.Sprintf("ccs[%s]", cc.Role), cc.Email)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/signature_request/send_with_template", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", basicAuthHeader(p.apiKey, ""))

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dropbox sign create failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		SignatureRequest struct {
			SignatureRequestID string `json:"signature_request_id"`
			IsComplete         bool   `json:"is_complete"`
		} `json:"signature_request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if strings.TrimSpace(out.SignatureRequest.SignatureRequestID) == "" {
		return nil, fmt.Errorf("missing signature_request_id in response")
	}

	status := StatusPending
	if out.SignatureRequest.IsComplete {
		status = StatusSigned
	}

	return &SignatureRequestResult{
		ProviderRequestID: out.SignatureRequest.SignatureRequestID,
		Status:            status,
		RawStatus:         map[bool]string{true: "all_signed", false: "pending"}[out.SignatureRequest.IsComplete],
	}, nil
}

func (p *DropboxSignProvider) GetSignatureRequest(ctx context.Context, providerRequestID string) (*SignatureRequestResult, error) {
	if strings.TrimSpace(providerRequestID) == "" {
		return nil, fmt.Errorf("provider request id is required")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/signature_request/"+url.PathEscape(providerRequestID), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", basicAuthHeader(p.apiKey, ""))

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("dropbox sign status failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		SignatureRequest struct {
			SignatureRequestID string `json:"signature_request_id"`
			IsComplete         bool   `json:"is_complete"`
			IsDeclined         bool   `json:"is_declined"`
			IsCanceled         bool   `json:"is_canceled"`
		} `json:"signature_request"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	raw := "pending"
	status := StatusPending
	switch {
	case out.SignatureRequest.IsDeclined:
		raw = "declined"
		status = StatusDeclined
	case out.SignatureRequest.IsCanceled:
		raw = "canceled"
		status = StatusCanceled
	case out.SignatureRequest.IsComplete:
		raw = "all_signed"
		status = StatusSigned
	}

	id := out.SignatureRequest.SignatureRequestID
	if strings.TrimSpace(id) == "" {
		id = providerRequestID
	}

	return &SignatureRequestResult{
		ProviderRequestID: id,
		Status:            status,
		RawStatus:         raw,
	}, nil
}

func (p *DropboxSignProvider) VerifyWebhook(payload []byte, headers http.Header) error {
	// Optional header check first (recommended by Dropbox Sign docs).
	if gotHeader := headerValue(headers, "Content-Sha256"); gotHeader != "" {
		mac := hmac.New(sha256.New, []byte(p.apiKey))
		mac.Write(payload)
		raw := mac.Sum(nil)
		expectedRawB64 := base64.StdEncoding.EncodeToString(raw)
		expectedHexB64 := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(raw)))
		if subtle.ConstantTimeCompare([]byte(gotHeader), []byte(expectedRawB64)) != 1 &&
			subtle.ConstantTimeCompare([]byte(gotHeader), []byte(expectedHexB64)) != 1 {
			return ErrWebhookInvalid
		}
	}

	var event struct {
		Event struct {
			EventTime string `json:"event_time"`
			EventType string `json:"event_type"`
			EventHash string `json:"event_hash"`
		} `json:"event"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return fmt.Errorf("decode webhook payload: %w", err)
	}
	if event.Event.EventTime == "" || event.Event.EventType == "" || event.Event.EventHash == "" {
		return ErrWebhookInvalid
	}

	mac := hmac.New(sha256.New, []byte(p.apiKey))
	mac.Write([]byte(event.Event.EventTime + event.Event.EventType))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(event.Event.EventHash)), []byte(expected)) != 1 {
		return ErrWebhookInvalid
	}
	return nil
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
