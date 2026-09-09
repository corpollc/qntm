package charter

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type StorageStats struct {
	Entries       uint64
	LogBytes      uint64
	DatabaseBytes int64
}

func storageStats(tx *bolt.Tx) StorageStats {
	stats := StorageStats{DatabaseBytes: tx.Size()}
	c := tx.Bucket(entriesBucket).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		stats.Entries++
		stats.LogBytes += uint64(len(v))
	}
	return stats
}

func (s *Store) Stats() (StorageStats, error) {
	var stats StorageStats
	err := s.db.View(func(tx *bolt.Tx) error { stats = storageStats(tx); return nil })
	return stats, err
}

// Backup streams a transactionally consistent database, INCLUDING THE SIGNING
// KEY. Callers must keep the destination private and encrypt off-host copies.
func (s *Store) Backup(w io.Writer) error {
	return s.db.View(func(tx *bolt.Tx) error { _, err := tx.WriteTo(w); return err })
}

var latencyBounds = [...]float64{0.005, 0.025, 0.1, 0.5, 1, 5, 30}

// Operations observes public HTTP traffic without logging paths, identifiers,
// request bodies or client addresses. Capacity rejection also counts as a 503.
type Operations struct {
	store     *Store
	started   time.Time
	mu        sync.Mutex
	statuses  [600]uint64
	latencies [len(latencyBounds)]uint64
	count     uint64
	seconds   float64
	slots     chan struct{}
}

func NewOperations(s *Store, concurrent int) *Operations {
	if concurrent < 1 {
		panic("positive concurrency required")
	}
	return &Operations{store: s, started: time.Now(), slots: make(chan struct{}, concurrent)}
}

type measuredResponse struct {
	http.ResponseWriter
	status int
}

func (w *measuredResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *measuredResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (o *Operations) Handler() http.Handler {
	api := o.store.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		mw := &measuredResponse{ResponseWriter: w}
		defer func() {
			elapsed := time.Since(start).Seconds()
			status := mw.status
			if status < 100 || status >= 600 {
				status = 500
			}
			o.mu.Lock()
			defer o.mu.Unlock()
			o.statuses[status]++
			o.count++
			o.seconds += elapsed
			for i, bound := range latencyBounds {
				if elapsed <= bound {
					o.latencies[i]++
				}
			}
		}()
		select {
		case o.slots <- struct{}{}:
			defer func() { <-o.slots }()
			api.ServeHTTP(mw, r)
		default:
			mw.Header().Set("Retry-After", "2")
			reject(mw, http.StatusServiceUnavailable, "registry_busy", fmt.Errorf("registry busy; retry later"))
		}
	})
}

// AdminHandler MUST be served on a private loopback listener. It exposes a
// signing-key-bearing backup and must never share the public reverse proxy.
func (o *Operations) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", o.metrics)
	mux.HandleFunc("GET /backup", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		if err := o.store.Backup(w); err != nil {
			panic(http.ErrAbortHandler)
		}
	})
	return mux
}

func (o *Operations) metrics(w http.ResponseWriter, r *http.Request) {
	stats, err := o.store.Stats()
	if err != nil {
		http.Error(w, "storage unavailable", 503)
		return
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Fprintln(w, "# TYPE qntm_charter_requests_total counter")
	for status, count := range o.statuses {
		if count != 0 {
			fmt.Fprintf(w, "qntm_charter_requests_total{status=\"%d\"} %d\n", status, count)
		}
	}
	fmt.Fprintln(w, "# TYPE qntm_charter_request_duration_seconds histogram")
	for i, bound := range latencyBounds {
		fmt.Fprintf(w, "qntm_charter_request_duration_seconds_bucket{le=\"%g\"} %d\n", bound, o.latencies[i])
	}
	fmt.Fprintf(w, "qntm_charter_request_duration_seconds_bucket{le=\"+Inf\"} %d\nqntm_charter_request_duration_seconds_sum %g\nqntm_charter_request_duration_seconds_count %d\n", o.count, o.seconds, o.count)
	for name, value := range map[string]uint64{"entries": stats.Entries, "log_bytes": stats.LogBytes, "database_bytes": uint64(stats.DatabaseBytes), "capacity_entries": o.store.limits.MaxEntries, "capacity_log_bytes": o.store.limits.MaxLogBytes, "heap_bytes": mem.Alloc, "goroutines": uint64(runtime.NumGoroutine())} {
		fmt.Fprintf(w, "# TYPE qntm_charter_%s gauge\nqntm_charter_%s %d\n", name, name, value)
	}
	fmt.Fprintf(w, "# TYPE qntm_charter_uptime_seconds gauge\nqntm_charter_uptime_seconds %g\n", time.Since(o.started).Seconds())
}
