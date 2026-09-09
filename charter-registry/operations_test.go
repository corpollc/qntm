package charter

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCapacityIsAtomicAndPreservesHistory(t *testing.T) {
	s, err := OpenWithLimits(filepath.Join(t.TempDir(), "registry.db"), "test.registry", Limits{2, 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	statements := make([]Statement, 8)
	for i := range statements {
		statements[i] = testCharter(t, testIdentity(t))
	}
	var wg sync.WaitGroup
	results := make(chan error, len(statements))
	for _, statement := range statements {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Submit(statement); results <- err }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrCapacity) {
			t.Fatal(err)
		}
	}
	if accepted != 2 {
		t.Fatalf("accepted %d with capacity 2", accepted)
	}
	stats, err := s.Stats()
	if err != nil || stats.Entries != 2 || stats.LogBytes == 0 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
	raw, _ := canonicalValue(testCharter(t, testIdentity(t)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/statements", bytes.NewReader(raw)))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "registry_capacity_reached") {
		t.Fatal(w.Code, w.Body.String())
	}
	if snap, err := s.Snapshot(nil); err != nil || len(snap.Entries) != 2 {
		t.Fatal("lost history at capacity", err)
	}
}

func TestByteCapacityAndPrivateBackupRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.db")
	s, err := OpenWithLimits(path, "test.registry", Limits{10, 1})
	if err != nil {
		t.Fatal(err)
	}
	key := testIdentity(t)
	genesis := testCharter(t, key)
	if _, err := s.Submit(genesis); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	s.Close()
	s = openTest(t, path)
	defer s.Close()
	if _, err := s.Submit(genesis); err != nil {
		t.Fatal(err)
	}
	ops := NewOperations(s, 1)
	for _, path := range []string{"/metrics", "/backup"} {
		w := httptest.NewRecorder()
		ops.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("public admin route %s: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	ops.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/backup", nil))
	copyPath := filepath.Join(t.TempDir(), "restore.db")
	if err := os.WriteFile(copyPath, w.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	restored := openTest(t, copyPath)
	defer restored.Close()
	if restored.PublicKey() != s.PublicKey() {
		t.Fatal("backup changed registrar")
	}
	before, _ := s.Snapshot(nil)
	after, _ := restored.Snapshot(nil)
	if before.Heads != after.Heads {
		t.Fatal("backup changed signed checkpoints")
	}
	if _, err := restored.Submit(testNext(t, genesis, key, "restored")); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateMetricsAndBusyResponse(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "registry.db"))
	defer s.Close()
	o := NewOperations(s, 1)
	api := o.Handler()
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	o.slots <- struct{}{}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("GET", "/v1/heads", nil))
	<-o.slots
	if w.Code != 503 || w.Header().Get("Retry-After") != "2" {
		t.Fatal(w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	o.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, expected := range []string{`qntm_charter_requests_total{status="200"} 1`, `qntm_charter_requests_total{status="503"} 1`, "qntm_charter_request_duration_seconds_count 2", "qntm_charter_entries 0"} {
		if !strings.Contains(w.Body.String(), expected) {
			t.Fatal("missing metric", expected, w.Body.String())
		}
	}
}
