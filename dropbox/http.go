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

type sendEnvelopeRequest struct {
	ConvID      string `json:"conv_id"`
	EnvelopeB64 string `json:"envelope_b64"`
}

type sendEnvelopeResponse struct {
	Seq int64 `json:"seq"`
}

type pollConversationRequest struct {
	ConvID  string `json:"conv_id"`
	FromSeq int64  `json:"from_seq"`
}

type pollRequest struct {
	Conversations []pollConversationRequest `json:"conversations"`
	MaxMessages   int                       `json:"max_messages,omitempty"`
}

type pollMessageResponse struct {
	Seq         int64  `json:"seq"`
	EnvelopeB64 string `json:"envelope_b64"`
}

type pollConversationResponse struct {
	ConvID   string                `json:"conv_id"`
	UpToSeq  int64                 `json:"up_to_seq"`
	Messages []pollMessageResponse `json:"messages"`
}

type pollResponse struct {
	Conversations []pollConversationResponse `json:"conversations"`
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

	var bodyBytes []byte
	if req.Body != nil {
		if req.GetBody != nil {
			bodyReader, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("failed to clone request body: %w", err)
			}
			bodyBytes, err = io.ReadAll(bodyReader)
			_ = bodyReader.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}
		} else {
			var err error
			bodyBytes, err = io.ReadAll(req.Body)
			_ = req.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to buffer request body: %w", err)
			}
		}
	}

	var lastErr error
	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * 500 * time.Millisecond
			time.Sleep(backoff)
		}

		attemptReq := req.Clone(req.Context())
		if bodyBytes != nil {
			attemptReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			attemptReq.ContentLength = int64(len(bodyBytes))
			attemptReq.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(bodyBytes)), nil
			}
		}

		resp, err := h.client.Do(attemptReq)
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

func (h *HTTPStorageProvider) sequencedSendURL() string {
	return h.BaseURL + "/v1/send"
}

func (h *HTTPStorageProvider) sequencedPollURL() string {
	return h.BaseURL + "/v1/poll"
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
	req, err := http.NewRequest(http.MethodPut, h.keyURL(key), bytes.NewReader(data))
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
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if len(respBody) > 0 {
		return fmt.Errorf("store failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
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

// StoreEnvelope stores an envelope through the worker sequenced API.
func (h *HTTPStorageProvider) StoreEnvelope(convID types.ConversationID, data []byte) (int64, error) {
	reqBody, err := json.Marshal(sendEnvelopeRequest{
		ConvID:      hex.EncodeToString(convID[:]),
		EnvelopeB64: base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to encode send request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, h.sequencedSendURL(), bytes.NewReader(reqBody))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.doWithRetry(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(respBody) > 0 {
			return 0, fmt.Errorf("sequenced send failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		return 0, fmt.Errorf("sequenced send failed: HTTP %d", resp.StatusCode)
	}

	var result sendEnvelopeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode sequenced send response: %w", err)
	}
	if result.Seq <= 0 {
		return 0, fmt.Errorf("invalid sequenced send response: missing seq")
	}
	return result.Seq, nil
}

// PollEnvelopes fetches sequenced envelopes from fromSeq+1 without List().
func (h *HTTPStorageProvider) PollEnvelopes(
	convID types.ConversationID,
	fromSeq int64,
	limit int,
) ([]SequencedEnvelope, int64, error) {
	requestBody := pollRequest{
		Conversations: []pollConversationRequest{
			{
				ConvID:  hex.EncodeToString(convID[:]),
				FromSeq: fromSeq,
			},
		},
	}
	if limit > 0 {
		requestBody.MaxMessages = limit
	}

	reqBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fromSeq, fmt.Errorf("failed to encode poll request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, h.sequencedPollURL(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, fromSeq, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.doWithRetry(req)
	if err != nil {
		return nil, fromSeq, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		if len(respBody) > 0 {
			return nil, fromSeq, fmt.Errorf("poll failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}
		return nil, fromSeq, fmt.Errorf("poll failed: HTTP %d", resp.StatusCode)
	}

	var result pollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fromSeq, fmt.Errorf("failed to decode poll response: %w", err)
	}
	if len(result.Conversations) == 0 {
		return []SequencedEnvelope{}, fromSeq, nil
	}

	item := result.Conversations[0]
	envelopes := make([]SequencedEnvelope, 0, len(item.Messages))
	for _, msg := range item.Messages {
		data, err := base64.StdEncoding.DecodeString(msg.EnvelopeB64)
		if err != nil {
			continue
		}
		envelopes = append(envelopes, SequencedEnvelope{
			Seq:  msg.Seq,
			Data: data,
		})
	}

	return envelopes, item.UpToSeq, nil
}

// HeadSequence returns the latest known sequence for a conversation.
func (h *HTTPStorageProvider) HeadSequence(convID types.ConversationID) (int64, error) {
	_, upToSeq, err := h.PollEnvelopes(convID, 0, 0)
	if err != nil {
		return 0, err
	}
	return upToSeq, nil
}
