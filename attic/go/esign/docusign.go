package esign

import (
	"bytes"
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

const defaultDocuSignBaseURL = "https://demo.docusign.net/restapi"

// DocuSignConfig configures the DocuSign provider.
type DocuSignConfig struct {
	AccessToken       string
	AccountID         string
	BaseURL           string
	WebhookHMACSecret string
	HTTPClient        *http.Client
}

// DocuSignProvider implements the provider contract for DocuSign.
type DocuSignProvider struct {
	accessToken       string
	accountID         string
	baseURL           string
	webhookHMACSecret string
	httpClient        *http.Client
}

func NewDocuSignProvider(cfg DocuSignConfig) (*DocuSignProvider, error) {
	if strings.TrimSpace(cfg.AccessToken) == "" {
		return nil, fmt.Errorf("docusign access token is required")
	}
	if strings.TrimSpace(cfg.AccountID) == "" {
		return nil, fmt.Errorf("docusign account id is required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = defaultDocuSignBaseURL
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &DocuSignProvider{
		accessToken:       cfg.AccessToken,
		accountID:         cfg.AccountID,
		baseURL:           baseURL,
		webhookHMACSecret: cfg.WebhookHMACSecret,
		httpClient:        client,
	}, nil
}

func (p *DocuSignProvider) Name() string { return "docusign" }

func (p *DocuSignProvider) CreateSignatureRequest(ctx context.Context, req SignatureRequest) (*SignatureRequestResult, error) {
	if strings.TrimSpace(req.TemplateID) == "" {
		return nil, fmt.Errorf("template_id is required for docusign")
	}
	if len(req.Signers) == 0 {
		return nil, fmt.Errorf("at least one signer is required")
	}

	type templateRole struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		RoleName string `json:"roleName"`
	}
	type envelopeDefinition struct {
		Status       string         `json:"status"`
		TemplateID   string         `json:"templateId"`
		EmailSubject string         `json:"emailSubject,omitempty"`
		EmailBlurb   string         `json:"emailBlurb,omitempty"`
		TemplateRole []templateRole `json:"templateRoles"`
	}

	roles := make([]templateRole, 0, len(req.Signers))
	for _, signer := range req.Signers {
		if strings.TrimSpace(signer.Role) == "" {
			return nil, fmt.Errorf("docusign template signer role is required")
		}
		roles = append(roles, templateRole{
			Email:    signer.Email,
			Name:     signer.Name,
			RoleName: signer.Role,
		})
	}

	subject := req.Subject
	if subject == "" {
		subject = req.Title
	}
	payload := envelopeDefinition{
		Status:       "sent",
		TemplateID:   req.TemplateID,
		EmailSubject: subject,
		EmailBlurb:   req.Message,
		TemplateRole: roles,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode envelope definition: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.envelopesURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("docusign create failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		EnvelopeID string `json:"envelopeId"`
		Status     string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if strings.TrimSpace(out.EnvelopeID) == "" {
		return nil, fmt.Errorf("missing envelopeId in response")
	}

	return &SignatureRequestResult{
		ProviderRequestID: out.EnvelopeID,
		Status:            normalizeStatus(out.Status),
		RawStatus:         strings.ToLower(strings.TrimSpace(out.Status)),
	}, nil
}

func (p *DocuSignProvider) GetSignatureRequest(ctx context.Context, providerRequestID string) (*SignatureRequestResult, error) {
	if strings.TrimSpace(providerRequestID) == "" {
		return nil, fmt.Errorf("provider request id is required")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.envelopesURL()+"/"+url.PathEscape(providerRequestID), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("get request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("docusign status failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		EnvelopeID string `json:"envelopeId"`
		Status     string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	id := out.EnvelopeID
	if strings.TrimSpace(id) == "" {
		id = providerRequestID
	}
	raw := strings.ToLower(strings.TrimSpace(out.Status))

	return &SignatureRequestResult{
		ProviderRequestID: id,
		Status:            normalizeStatus(raw),
		RawStatus:         raw,
	}, nil
}

func (p *DocuSignProvider) VerifyWebhook(payload []byte, headers http.Header) error {
	if strings.TrimSpace(p.webhookHMACSecret) == "" {
		return fmt.Errorf("docusign webhook hmac secret not configured")
	}
	header := headerValue(headers, "X-DocuSign-Signature-1")
	if header == "" {
		return ErrWebhookInvalid
	}

	mac := hmac.New(sha256.New, []byte(p.webhookHMACSecret))
	mac.Write(payload)
	raw := mac.Sum(nil)
	expectedB64 := base64.StdEncoding.EncodeToString(raw)
	expectedHex := hex.EncodeToString(raw)

	if subtle.ConstantTimeCompare([]byte(header), []byte(expectedB64)) != 1 &&
		subtle.ConstantTimeCompare([]byte(strings.ToLower(header)), []byte(expectedHex)) != 1 {
		return ErrWebhookInvalid
	}
	return nil
}

func (p *DocuSignProvider) envelopesURL() string {
	return p.baseURL + "/v2.1/accounts/" + url.PathEscape(p.accountID) + "/envelopes"
}
