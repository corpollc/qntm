package charter

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

const MaxStatementBytes = 1 << 20

// Handler exposes the reference HTTP transport. Signatures authorize writes;
// there is no operator admission token. Browser CORS is disabled by default.
func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /v1/info", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"registry": s.Registry, "draft_version": DraftVersion, "registrar": s.PublicKey(), "max_statement_bytes": MaxStatementBytes, "witnessed": false})
	})
	mux.HandleFunc("POST /v1/statements", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxStatementBytes)
		b, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				reject(w, 413, "statement_too_large", err)
			} else {
				reject(w, 400, "invalid_body", err)
			}
			return
		}
		statement, err := ParseStatement(b)
		if err != nil {
			reject(w, 400, "invalid_statement", err)
			return
		}
		receipt, err := s.Submit(statement)
		if err != nil {
			var invalid *ValidationError
			switch {
			case errors.Is(err, ErrConflict):
				reject(w, 409, "sequence_conflict", err)
			case errors.As(err, &invalid):
				reject(w, 422, "authority_rejected", err)
			default:
				reject(w, 500, "storage_error", errors.New("registry storage unavailable"))
			}
			return
		}
		respond(w, 201, receipt)
	})
	snapshot := func(w http.ResponseWriter, r *http.Request) *Snapshot {
		size, err := optionalSize(r, "size")
		if err != nil {
			reject(w, 400, "invalid_size", err)
			return nil
		}
		snap, err := s.Snapshot(size)
		if err != nil {
			if errors.Is(err, ErrSnapshot) {
				reject(w, 400, "invalid_size", err)
			} else {
				reject(w, 500, "storage_error", errors.New("registry storage unavailable"))
			}
			return nil
		}
		return snap
	}
	mux.HandleFunc("GET /v1/heads", func(w http.ResponseWriter, r *http.Request) {
		if snap := snapshot(w, r); snap != nil {
			respond(w, 200, snap.Heads)
		}
	})
	mux.HandleFunc("GET /v1/chain/{agent}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("agent")
		if !validHex(id, 16) {
			reject(w, 400, "invalid_agent", errors.New("expected 16-byte lowercase hex agent ID"))
			return
		}
		if snap := snapshot(w, r); snap != nil {
			respond(w, 200, snap.Chain(id))
		}
	})
	mux.HandleFunc("GET /v1/inclusion/{index}", func(w http.ResponseWriter, r *http.Request) {
		index, err := parseSize(r.PathValue("index"))
		if err != nil {
			reject(w, 400, "invalid_index", err)
			return
		}
		if snap := snapshot(w, r); snap != nil {
			if index >= uint64(len(snap.Entries)) {
				reject(w, 400, "invalid_index", ErrSnapshot)
				return
			}
			respond(w, 200, map[string]any{"inclusion": snap.Inclusion(int(index)), "heads": snap.Heads})
		}
	})
	mux.HandleFunc("GET /v1/consistency", func(w http.ResponseWriter, r *http.Request) {
		from, err := parseSize(r.URL.Query().Get("from"))
		if err != nil {
			reject(w, 400, "invalid_from", err)
			return
		}
		to, err := optionalSize(r, "to")
		if err != nil {
			reject(w, 400, "invalid_to", err)
			return
		}
		newer, err := s.Snapshot(to)
		if err != nil || from > uint64(len(newer.Entries)) {
			reject(w, 400, "invalid_size", ErrSnapshot)
			return
		}
		older, err := s.snapshot(newer.Entries[:from])
		if err != nil {
			reject(w, 500, "storage_error", err)
			return
		}
		respond(w, 200, map[string]any{"from": older.Heads, "to": newer.Heads, "proof": newer.Consistency(int(from))})
	})
	mux.HandleFunc("GET /v1/log", func(w http.ResponseWriter, r *http.Request) {
		from := uint64(0)
		var err error
		if r.URL.Query().Has("from") {
			from, err = parseSize(r.URL.Query().Get("from"))
		}
		if err != nil {
			reject(w, 400, "invalid_from", err)
			return
		}
		limit := uint64(100)
		if r.URL.Query().Has("limit") {
			limit, err = parseSize(r.URL.Query().Get("limit"))
		}
		if err != nil || limit < 1 || limit > 1000 {
			reject(w, 400, "invalid_limit", errors.New("limit must be 1..1000"))
			return
		}
		if snap := snapshot(w, r); snap != nil {
			n := uint64(len(snap.Entries))
			if from > n {
				reject(w, 400, "invalid_from", ErrSnapshot)
				return
			}
			end := min(from+limit, n)
			respond(w, 200, map[string]any{"entries": snap.Entries[from:end], "from": from, "next": end, "heads": snap.Heads})
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}
func parseSize(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > MaxSafeInteger || strconv.FormatUint(n, 10) != value {
		return 0, errors.New("expected canonical non-negative safe integer")
	}
	return n, nil
}
func optionalSize(r *http.Request, name string) (*uint64, error) {
	if !r.URL.Query().Has(name) {
		return nil, nil
	}
	n, err := parseSize(r.URL.Query().Get(name))
	return &n, err
}
func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func reject(w http.ResponseWriter, status int, code string, err error) {
	respond(w, status, map[string]string{"error": code, "message": err.Error()})
}
