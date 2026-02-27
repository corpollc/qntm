package dropbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/corpo/qntm/pkg/types"
)

// HTTPStorageProvider implements StorageProvider via the qntm Cloudflare Worker API.
type HTTPStorageProvider struct {
	BaseURL    string
	client     *http.Client
	maxRetries int
}

const readReceiptProto = "qntm-receipt-v1"

type readReceiptPayload struct {
	Proto        string `json:"proto"`
	ConvID       string `json:"conv_id"`
	MsgID        string `json:"msg_id"`
	ReaderKID    string `json:"reader_kid"`
	ReaderIKPK   string `json:"reader_ik_pk"`
	ReadTS       int64  `json:"read_ts"`
	RequiredAcks int    `json:"required_acks"`
	Signature    string `json:"sig"`
}

// NewHTTPStorageProvider creates a new HTTP-backed storage provider.
func NewHTTPStorageProvider(baseURL string) *HTTPStorageProvider {
	if baseURL == "" {
		baseURL = "https://inbox.qntm.corpo.llc"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &HTTPStorageProvider{
		BaseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		maxRetries: 3,
	}
}

func (h *HTTPStorageProvider) doWithRetry(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "qntm-cli/1.0")

	var lastErr error
	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * 500 * time.Millisecond
			time.Sleep(backoff)
		}

		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// Don't retry client errors (4xx) except 429
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return resp, nil
		}
		// Retry on 429 and 5xx
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}
	return nil, fmt.Errorf("request failed after %d retries: %w", h.maxRetries, lastErr)
}

func (h *HTTPStorageProvider) keyURL(key string) string {
	return h.BaseURL + "/v1/drop" + key
}

func buildReadReceiptSignable(
	convID types.ConversationID,
	msgID types.MessageID,
	readerKID types.KeyID,
	readTS int64,
	requiredAcks int,
) []byte {
	return []byte(fmt.Sprintf(
		"%s|%x|%x|%x|%d|%d",
		readReceiptProto,
		convID[:],
		msgID[:],
		readerKID[:],
		readTS,
		requiredAcks,
	))
}

// Store implements StorageProvider.
func (h *HTTPStorageProvider) Store(key string, data []byte) error {
	req, err := http.NewRequest(http.MethodPut, h.keyURL(key), strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := h.doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 201 || resp.StatusCode == 200 {
		if pruned := strings.TrimSpace(resp.Header.Get("X-QNTM-Pruned")); pruned != "" && pruned != "0" {
			fmt.Fprintf(os.Stderr, "note: relay pruned %s oldest message(s) from this channel\n", pruned)
		}
		return nil
	}
	if resp.StatusCode == 413 {
		return fmt.Errorf("envelope too large")
	}
	return fmt.Errorf("store failed: HTTP %d", resp.StatusCode)
}

// Retrieve implements StorageProvider.
func (h *HTTPStorageProvider) Retrieve(key string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, h.keyURL(key), nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("retrieve failed: HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// List implements StorageProvider.
func (h *HTTPStorageProvider) List(prefix string) ([]string, error) {
	u := h.BaseURL + "/v1/drop/?prefix=" + url.QueryEscape(prefix)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list failed: HTTP %d", resp.StatusCode)
	}

	var keys []string
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode key list: %w", err)
	}
	return keys, nil
}

// Delete implements StorageProvider.
func (h *HTTPStorageProvider) Delete(key string) error {
	_ = key
	return fmt.Errorf("client-side delete is disabled; relay-managed cleanup only")
}

// RecordReadReceipt reports that a receiver has successfully read a message.
// The relay may use this receipt to perform worker-side cleanup.
func (h *HTTPStorageProvider) RecordReadReceipt(
	receiverIdentity *types.Identity,
	conversation *types.Conversation,
	msgID types.MessageID,
) error {
	if receiverIdentity == nil {
		return fmt.Errorf("receiver identity is required")
	}
	if conversation == nil {
		return fmt.Errorf("conversation is required")
	}

	requiredAcks := len(conversation.Participants)
	if requiredAcks < 1 {
		requiredAcks = 1
	}

	readTS := time.Now().Unix()
	signable := buildReadReceiptSignable(
		conversation.ID,
		msgID,
		receiverIdentity.KeyID,
		readTS,
		requiredAcks,
	)
	signature := ed25519.Sign(receiverIdentity.PrivateKey, signable)

	payload := readReceiptPayload{
		Proto:        readReceiptProto,
		ConvID:       hex.EncodeToString(conversation.ID[:]),
		MsgID:        hex.EncodeToString(msgID[:]),
		ReaderKID:    hex.EncodeToString(receiverIdentity.KeyID[:]),
		ReaderIKPK:   base64.RawURLEncoding.EncodeToString(receiverIdentity.PublicKey),
		ReadTS:       readTS,
		RequiredAcks: requiredAcks,
		Signature:    base64.RawURLEncoding.EncodeToString(signature),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode read receipt: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, h.BaseURL+"/v1/receipt", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		if len(respBody) > 0 {
			return fmt.Errorf("receipt failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		return fmt.Errorf("receipt failed: HTTP %d", resp.StatusCode)
	}

	return nil
}

// Exists implements StorageProvider.
func (h *HTTPStorageProvider) Exists(key string) (bool, error) {
	req, err := http.NewRequest(http.MethodHead, h.keyURL(key), nil)
	if err != nil {
		return false, err
	}

	resp, err := h.doWithRetry(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200, nil
}
