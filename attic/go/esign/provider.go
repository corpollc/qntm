package esign

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ErrWebhookInvalid is returned when webhook signature validation fails.
var ErrWebhookInvalid = errors.New("invalid webhook signature")

// SignatureStatus is a normalized status across providers.
type SignatureStatus string

const (
	StatusUnknown   SignatureStatus = "unknown"
	StatusDraft     SignatureStatus = "draft"
	StatusPending   SignatureStatus = "pending"
	StatusSigned    SignatureStatus = "signed"
	StatusDeclined  SignatureStatus = "declined"
	StatusCanceled  SignatureStatus = "canceled"
	StatusExpired   SignatureStatus = "expired"
	StatusCompleted SignatureStatus = "completed"
)

// Signer is a participant in a signature request.
// Role is required for template-based provider flows.
type Signer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

// SignatureRequest is a provider-agnostic request model.
// This initial implementation is optimized for template-based sends.
type SignatureRequest struct {
	ExternalRequestID string            `json:"external_request_id,omitempty"`
	TemplateID        string            `json:"template_id"`
	Title             string            `json:"title,omitempty"`
	Subject           string            `json:"subject,omitempty"`
	Message           string            `json:"message,omitempty"`
	Signers           []Signer          `json:"signers"`
	CCs               []Signer          `json:"ccs,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	TestMode          bool              `json:"test_mode,omitempty"`
}

// SignatureRequestResult is a provider response normalized for gate/broker logic.
type SignatureRequestResult struct {
	ProviderRequestID string          `json:"provider_request_id"`
	Status            SignatureStatus `json:"status"`
	RawStatus         string          `json:"raw_status,omitempty"`
}

// Provider is the contract used by broker-side integrations.
type Provider interface {
	Name() string
	CreateSignatureRequest(ctx context.Context, req SignatureRequest) (*SignatureRequestResult, error)
	GetSignatureRequest(ctx context.Context, providerRequestID string) (*SignatureRequestResult, error)
	VerifyWebhook(payload []byte, headers http.Header) error
}

func normalizeStatus(raw string) SignatureStatus {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")

	switch s {
	case "draft", "created":
		return StatusDraft
	case "pending", "sent", "in_progress", "awaiting_signature", "delivered":
		return StatusPending
	case "completed", "all_signed", "signed":
		return StatusSigned
	case "declined":
		return StatusDeclined
	case "canceled", "voided":
		return StatusCanceled
	case "expired":
		return StatusExpired
	default:
		return StatusUnknown
	}
}

func headerValue(headers http.Header, name string) string {
	if v := strings.TrimSpace(headers.Get(name)); v != "" {
		return v
	}
	for k, values := range headers {
		if !strings.EqualFold(k, name) || len(values) == 0 {
			continue
		}
		v := strings.TrimSpace(values[0])
		if v != "" {
			return v
		}
	}
	return ""
}
