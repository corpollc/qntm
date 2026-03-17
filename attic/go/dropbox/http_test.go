package dropbox

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/invite"
	"github.com/corpo/qntm/pkg/types"
)

func newTestServer() (*httptest.Server, *sync.Map) {
	store := &sync.Map{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/receipt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		body, _ := io.ReadAll(r.Body)
		store.Store("/__receipt__", body)
		w.WriteHeader(200)
	})
	mux.HandleFunc("/v1/drop/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path[len("/v1/drop"):]

		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			if len(body) > 65536 {
				http.Error(w, `{"error":"envelope too large"}`, 413)
				return
			}
			store.Store(key, body)
			w.WriteHeader(201)

		case http.MethodGet:
			// Check for list operation
			if key == "/" || key == "" {
				prefix := r.URL.Query().Get("prefix")
				var keys []string
				store.Range(func(k, v interface{}) bool {
					ks := k.(string)
					if len(ks) >= len(prefix) && ks[:len(prefix)] == prefix {
						keys = append(keys, ks)
					}
					return true
				})
				if keys == nil {
					keys = []string{}
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(keys)
				return
			}
			val, ok := store.Load(key)
			if !ok {
				http.Error(w, `{"error":"not found"}`, 404)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(val.([]byte))

		case http.MethodHead:
			_, ok := store.Load(key)
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(200)

		case http.MethodDelete:
			store.Delete(key)
			w.WriteHeader(200)

		default:
			w.WriteHeader(405)
		}
	})

	return httptest.NewServer(mux), store
}

func TestHTTPStorageProvider_StoreRetrieve(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	if err := p.Store("/test/key1", []byte("hello")); err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	data, err := p.Retrieve("/test/key1")
	if err != nil {
		t.Fatalf("Retrieve failed: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("got %q, want %q", data, "hello")
	}
}

func TestHTTPStorageProvider_NotFound(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	_, err := p.Retrieve("/nonexistent")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestHTTPStorageProvider_Exists(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	exists, err := p.Exists("/test/ex")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("should not exist yet")
	}

	p.Store("/test/ex", []byte("data"))

	exists, err = p.Exists("/test/ex")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("should exist after store")
	}
}

func TestHTTPStorageProvider_List(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	p.Store("/conv1/msg/a", []byte("1"))
	p.Store("/conv1/msg/b", []byte("2"))
	p.Store("/conv2/msg/c", []byte("3"))

	keys, err := p.List("/conv1/")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestHTTPStorageProvider_Delete(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	p.Store("/del/key", []byte("bye"))
	if err := p.Delete("/del/key"); err == nil {
		t.Fatalf("expected delete to be disabled")
	}
}

func TestHTTPStorageProvider_TooLarge(t *testing.T) {
	srv, _ := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	bigData := make([]byte, 65537)
	err := p.Store("/big", bigData)
	if err == nil {
		t.Fatal("expected error for oversized envelope")
	}
}

func TestHTTPStorageProvider_RetryPreservesRequestBody(t *testing.T) {
	attempts := 0
	bodies := make([]string, 0, 2)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/drop/retry/body" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		body, _ := io.ReadAll(r.Body)
		attempts++
		bodies = append(bodies, string(body))

		// Force exactly one retry path before success.
		if attempts == 1 {
			http.Error(w, "transient failure", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)
	p.maxRetries = 1

	payload := []byte("payload-123")
	if err := p.Store("/retry/body", payload); err != nil {
		t.Fatalf("Store failed after retry: %v", err)
	}

	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if len(bodies) != 2 {
		t.Fatalf("expected 2 captured request bodies, got %d", len(bodies))
	}
	if bodies[0] != string(payload) || bodies[1] != string(payload) {
		t.Fatalf("request body changed across retries: %#v", bodies)
	}
}

func TestHTTPStorageProvider_RecordReadReceipt(t *testing.T) {
	srv, store := newTestServer()
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)

	identityMgr := identity.NewManager()
	inviteMgr := invite.NewManager()

	senderIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate sender identity: %v", err)
	}
	receiverIdentity, err := identityMgr.GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate receiver identity: %v", err)
	}

	invitePayload, err := inviteMgr.CreateInvite(senderIdentity, types.ConversationTypeDirect)
	if err != nil {
		t.Fatalf("failed to create invite: %v", err)
	}
	keys, err := inviteMgr.DeriveConversationKeys(invitePayload)
	if err != nil {
		t.Fatalf("failed to derive keys: %v", err)
	}
	conversation, err := inviteMgr.CreateConversation(invitePayload, keys)
	if err != nil {
		t.Fatalf("failed to create conversation: %v", err)
	}
	inviteMgr.AddParticipant(conversation, receiverIdentity.PublicKey)

	msgID, err := identityMgr.GenerateMessageID()
	if err != nil {
		t.Fatalf("failed to generate message id: %v", err)
	}

	if err := p.RecordReadReceipt(receiverIdentity, conversation, msgID); err != nil {
		t.Fatalf("RecordReadReceipt failed: %v", err)
	}

	if _, ok := store.Load("/__receipt__"); !ok {
		t.Fatalf("expected receipt payload to be posted")
	}
}

func TestHTTPStorageProvider_SequencedStoreAndPoll(t *testing.T) {
	type sequencedConversation struct {
		head int64
		data map[int64][]byte
	}

	mu := sync.Mutex{}
	conversations := map[string]*sequencedConversation{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/send":
			var payload sendEnvelopeRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad payload", 400)
				return
			}
			data, err := base64.StdEncoding.DecodeString(payload.EnvelopeB64)
			if err != nil {
				http.Error(w, "bad b64", 400)
				return
			}

			mu.Lock()
			entry := conversations[payload.ConvID]
			if entry == nil {
				entry = &sequencedConversation{data: map[int64][]byte{}}
				conversations[payload.ConvID] = entry
			}
			entry.head++
			seq := entry.head
			entry.data[seq] = append([]byte(nil), data...)
			mu.Unlock()

			_ = json.NewEncoder(w).Encode(sendEnvelopeResponse{Seq: seq})
			return

		case r.Method == http.MethodPost && r.URL.Path == "/v1/poll":
			var payload pollRequest
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad payload", 400)
				return
			}
			if len(payload.Conversations) != 1 {
				http.Error(w, "expected one conversation", 400)
				return
			}

			reqConv := payload.Conversations[0]
			mu.Lock()
			entry := conversations[reqConv.ConvID]
			head := int64(0)
			if entry != nil {
				head = entry.head
			}
			upTo := head
			if payload.MaxMessages > 0 && reqConv.FromSeq+int64(payload.MaxMessages) < upTo {
				upTo = reqConv.FromSeq + int64(payload.MaxMessages)
			}
			msgs := make([]pollMessageResponse, 0)
			if entry != nil {
				for seq := reqConv.FromSeq + 1; seq <= upTo; seq++ {
					if data, ok := entry.data[seq]; ok {
						msgs = append(msgs, pollMessageResponse{
							Seq:         seq,
							EnvelopeB64: base64.StdEncoding.EncodeToString(data),
						})
					}
				}
			}
			mu.Unlock()

			_ = json.NewEncoder(w).Encode(pollResponse{
				Conversations: []pollConversationResponse{
					{
						ConvID:   reqConv.ConvID,
						UpToSeq:  upTo,
						Messages: msgs,
					},
				},
			})
			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	p := NewHTTPStorageProvider(srv.URL)
	convID := types.ConversationID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	seq1, err := p.StoreEnvelope(convID, []byte("first"))
	if err != nil {
		t.Fatalf("StoreEnvelope 1 failed: %v", err)
	}
	seq2, err := p.StoreEnvelope(convID, []byte("second"))
	if err != nil {
		t.Fatalf("StoreEnvelope 2 failed: %v", err)
	}
	if seq1 != 1 || seq2 != 2 {
		t.Fatalf("unexpected sequence numbers: %d %d", seq1, seq2)
	}

	envelopes, upTo, err := p.PollEnvelopes(convID, 0, 10)
	if err != nil {
		t.Fatalf("PollEnvelopes failed: %v", err)
	}
	if upTo != 2 {
		t.Fatalf("expected upTo 2, got %d", upTo)
	}
	if len(envelopes) != 2 {
		t.Fatalf("expected 2 envelopes, got %d", len(envelopes))
	}
	if string(envelopes[0].Data) != "first" || string(envelopes[1].Data) != "second" {
		t.Fatalf("unexpected envelope contents")
	}

	head, err := p.HeadSequence(convID)
	if err != nil {
		t.Fatalf("HeadSequence failed: %v", err)
	}
	if head != 2 {
		t.Fatalf("expected head 2, got %d", head)
	}
}

// Verify interface compliance at compile time
var _ StorageProvider = (*HTTPStorageProvider)(nil)
var _ StorageProvider = (*MemoryStorageProvider)(nil)

// FileStorageProvider is in cli package, tested separately
