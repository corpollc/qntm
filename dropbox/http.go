package dropbox

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPStorageProvider implements StorageProvider via the qntm Cloudflare Worker API.
type HTTPStorageProvider struct {
	BaseURL    string
	client     *http.Client
	maxRetries int
}

// NewHTTPStorageProvider creates a new HTTP-backed storage provider.
func NewHTTPStorageProvider(baseURL string) *HTTPStorageProvider {
	if baseURL == "" {
		baseURL = "https://qntm.s6.xyz"
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
	req, err := http.NewRequest(http.MethodDelete, h.keyURL(key), nil)
	if err != nil {
		return err
	}

	resp, err := h.doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("delete failed: HTTP %d", resp.StatusCode)
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
