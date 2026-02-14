package dropbox

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func newTestServer() (*httptest.Server, *sync.Map) {
	store := &sync.Map{}

	mux := http.NewServeMux()
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
	if err := p.Delete("/del/key"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	exists, _ := p.Exists("/del/key")
	if exists {
		t.Error("key should be deleted")
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

// Verify interface compliance at compile time
var _ StorageProvider = (*HTTPStorageProvider)(nil)
var _ StorageProvider = (*MemoryStorageProvider)(nil)
// FileStorageProvider is in cli package, tested separately
