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
	dir := t.TempDir()
	path := filepath.Join(dir, "source.db")
	s, err := OpenWithLimits(path, "test.registry", Limits{10, 1})
	if err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(dir, "snapshot.db")
	if s.SnapshotPath() != snapPath {
		t.Fatalf("unexpected snapshot path: %q", s.SnapshotPath())
	}
	info, err := os.Stat(snapPath)
	if err != nil || info.Mode().Perm() != 0600 || info.Size() < 8192 {
		t.Fatalf("startup snapshot missing or insecure: %v %v", info, err)
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
	for _, route := range []string{"/metrics", "/backup"} {
		w := httptest.NewRecorder()
		ops.Handler().ServeHTTP(w, httptest.NewRequest("GET", route, nil))
		if w.Code != 404 {
			t.Fatalf("public admin route %s: %d", route, w.Code)
		}
	}
	// Admin listener must NEVER expose /backup or the signing seed over TCP.
	w := httptest.NewRecorder()
	ops.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/backup", nil))
	if w.Code != 404 {
		t.Fatalf("admin /backup must be removed, got %d", w.Code)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Fatalf("leaked temporary snapshot file %s", e.Name())
		}
	}
	snapBytes, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(snapPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions: %v %v", info, err)
	}
	if len(snapBytes) < 0x14 || (!bytes.Equal(snapBytes[0x10:0x14], []byte{0xed, 0xda, 0x0c, 0xed}) && !bytes.Equal(snapBytes[0x10:0x14], []byte{0xed, 0x0c, 0xda, 0xed})) {
		t.Fatal("snapshot.db missing valid bbolt magic header")
	}
	copyPath := filepath.Join(t.TempDir(), "restore.db")
	if err := os.WriteFile(copyPath, snapBytes, 0600); err != nil {
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
	// /healthz must remain 200 even when all API concurrency slots are occupied.
	w = httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("expected /healthz 200 under full slots, got %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest("GET", "/v1/heads", nil))
	<-o.slots
	if w.Code != 503 || w.Header().Get("Retry-After") != "2" {
		t.Fatal(w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	o.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, expected := range []string{`qntm_charter_requests_total{status="200"} 2`, `qntm_charter_requests_total{status="503"} 1`, "qntm_charter_request_duration_seconds_count 3", "qntm_charter_entries 0"} {
		if !strings.Contains(w.Body.String(), expected) {
			t.Fatal("missing metric", expected, w.Body.String())
		}
	}
}

func TestSnapshotCacheAndInvalidation(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "registry.db"))
	defer s.Close()
	emptyA, err := s.Snapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	zero := uint64(0)
	emptyB, err := s.Snapshot(&zero)
	if err != nil {
		t.Fatal(err)
	}
	if emptyA != emptyB {
		t.Fatal("expected latest snapshot to be served from cache")
	}
	key := testIdentity(t)
	genesis := testCharter(t, key)
	r1, err := s.Submit(genesis)
	if err != nil {
		t.Fatal(err)
	}
	snap1A, err := s.Snapshot(nil)
	if err != nil {
		t.Fatal(err)
	}
	one := uint64(1)
	snap1B, err := s.Snapshot(&one)
	if err != nil {
		t.Fatal(err)
	}
	if snap1A != snap1B || len(snap1A.Entries) != 1 || snap1A.Heads != r1.Heads {
		t.Fatal("cache did not update cleanly after Submit")
	}
	next := testNext(t, genesis, key, "second")
	r2, err := s.Submit(next)
	if err != nil {
		t.Fatal(err)
	}
	snap2, err := s.Snapshot(nil)
	if err != nil || len(snap2.Entries) != 2 || snap2.Heads != r2.Heads {
		t.Fatalf("expected 2 entries in cached snapshot, got %v %v", snap2, err)
	}
	hist1, err := s.Snapshot(&one)
	if err != nil || hist1.Heads != r1.Heads {
		t.Fatal("historical snapshot checkpoint changed")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/consistency?from=2&to=2", nil))
	if w.Code != 200 {
		t.Fatalf("same-size consistency failed: %d %s", w.Code, w.Body.String())
	}
}
