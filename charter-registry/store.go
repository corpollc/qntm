package charter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var ErrConflict = errors.New("sequence already exists, is missing, or forks current head")
var ErrSnapshot = errors.New("snapshot size or index is out of range")
var ErrCapacity = errors.New("registry capacity reached; contact the operator")

type Limits struct {
	MaxEntries  uint64 `json:"max_entries"`
	MaxLogBytes uint64 `json:"max_log_bytes"`
}

func DefaultLimits() Limits { return Limits{MaxEntries: 2000, MaxLogBytes: 16 << 20} }

type ValidationError struct{ Cause error }

func (e *ValidationError) Error() string { return e.Cause.Error() }

var metadataBucket = []byte("metadata")
var entriesBucket = []byte("entries")

type LogEntry struct {
	Statement  Statement `json:"statement"`
	ReceivedAt string    `json:"received_at"`
}
type HeadBody struct {
	Kind      string `json:"kind"`
	Registry  string `json:"registry"`
	TreeSize  uint64 `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp string `json:"timestamp"`
}
type EpochBody struct {
	Kind      string `json:"kind"`
	Registry  string `json:"registry"`
	Epoch     uint64 `json:"epoch"`
	MapSize   uint64 `json:"map_size"`
	MapRoot   string `json:"map_root"`
	LogSize   uint64 `json:"log_size"`
	LogRoot   string `json:"log_root"`
	Timestamp string `json:"timestamp"`
}
type SignedHead[T any] struct {
	Signed T      `json:"signed"`
	KID    string `json:"kid"`
	Sig    string `json:"sig"`
}
type Heads struct {
	Log   SignedHead[HeadBody]  `json:"log"`
	Epoch SignedHead[EpochBody] `json:"epoch"`
}
type MapLeaf struct {
	AgentID       string `json:"agent_id"`
	Sequence      uint64 `json:"seq"`
	StatementHash string `json:"statement_hash"`
}
type MapWitness struct {
	Leaf     MapLeaf  `json:"leaf"`
	Index    int      `json:"index"`
	Siblings []string `json:"siblings"`
}
type RangeProof struct {
	AgentID string      `json:"agent_id"`
	Present bool        `json:"present"`
	Left    *MapWitness `json:"left"`
	Right   *MapWitness `json:"right"`
}
type Inclusion struct {
	Entry    LogEntry `json:"entry"`
	Index    int      `json:"index"`
	Siblings []string `json:"siblings"`
}
type ChainResult struct {
	Chain []Statement `json:"chain"`
	Proof RangeProof  `json:"proof"`
	Heads Heads       `json:"heads"`
}
type Receipt struct {
	Index         int       `json:"index"`
	StatementHash string    `json:"statement_hash"`
	Inclusion     Inclusion `json:"inclusion"`
	Heads         Heads     `json:"heads"`
}

// Store uses one durable transaction per accepted statement. No successful receipt
// is returned before bbolt commits and fsyncs it. The DB also holds the registrar key.
type Store struct {
	db        *bolt.DB
	Registry  string
	key       ed25519.PrivateKey
	createdAt string
	limits    Limits
}

func Open(path, registry string) (*Store, error) {
	return OpenWithLimits(path, registry, DefaultLimits())
}

// OpenWithLimits bounds accepted history. Existing entries remain readable if an
// operator lowers the limits; only further appends are rejected.
func OpenWithLimits(path, registry string, limits Limits) (*Store, error) {
	if limits.MaxEntries == 0 || limits.MaxLogBytes == 0 {
		return nil, errors.New("registry capacity limits must be positive")
	}
	if registry == "" {
		return nil, errors.New("registry identifier is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, Registry: registry, limits: limits}
	err = db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(metadataBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(entriesBucket)
		if err != nil {
			return err
		}
		if meta.Get([]byte("registry")) == nil {
			first, _ := tx.Bucket(entriesBucket).Cursor().First()
			metaFirst, _ := meta.Cursor().First()
			if first != nil || metaFirst != nil {
				return errors.New("database metadata is missing or incomplete")
			}
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			for k, value := range map[string][]byte{"registry": []byte(registry), "seed": key.Seed(), "created_at": []byte(time.Now().UTC().Format(time.RFC3339Nano)), "version": []byte(DraftVersion)} {
				if err := meta.Put([]byte(k), value); err != nil {
					return err
				}
			}
		}
		if string(meta.Get([]byte("registry"))) != registry || string(meta.Get([]byte("version"))) != DraftVersion {
			return errors.New("database registry or draft version mismatch")
		}
		seed := meta.Get([]byte("seed"))
		if len(seed) != ed25519.SeedSize {
			return errors.New("invalid registrar key in database")
		}
		s.key = ed25519.NewKeyFromSeed(seed)
		s.createdAt = string(meta.Get([]byte("created_at")))
		if !validTime(s.createdAt) {
			return errors.New("invalid database creation timestamp")
		}
		entries, err := readEntries(tx, nil)
		if err != nil {
			return err
		}
		states := map[string]*State{}
		for i, entry := range entries {
			if !validTime(entry.ReceivedAt) {
				return fmt.Errorf("invalid arrival timestamp at log index %d", i)
			}
			id := entry.Statement.Signed.AgentID
			next, err := Advance(states[id], entry.Statement, registry)
			if err != nil {
				return fmt.Errorf("invalid stored statement %d: %w", i, err)
			}
			states[id] = next
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error   { return s.db.Close() }
func (s *Store) PublicKey() Key { return NewKey(s.key.Public().(ed25519.PublicKey)) }
func indexKey(index uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, index)
	return b
}
func readEntries(tx *bolt.Tx, size *uint64) ([]LogEntry, error) {
	entries := []LogEntry{}
	c := tx.Bucket(entriesBucket).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		if size != nil && uint64(len(entries)) == *size {
			break
		}
		if !bytes.Equal(k, indexKey(uint64(len(entries)))) {
			return nil, errors.New("log index gap")
		}
		var e LogEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	if size != nil && uint64(len(entries)) != *size {
		return nil, ErrSnapshot
	}
	return entries, nil
}

func (s *Store) Submit(input Statement) (Receipt, error) {
	var receipt Receipt
	// Freeze caller-owned slices before the transaction; validation below uses this copy.
	raw, err := canonicalValue(input)
	if err != nil {
		return receipt, &ValidationError{err}
	}
	statement, err := ParseStatement(raw)
	if err != nil {
		return receipt, &ValidationError{err}
	}
	var entries []LogEntry
	err = s.db.Update(func(tx *bolt.Tx) error {
		var err error
		entries, err = readEntries(tx, nil)
		if err != nil {
			return err
		}
		var state *State
		for _, entry := range entries {
			if entry.Statement.Signed.AgentID == statement.Signed.AgentID {
				state, err = Advance(state, entry.Statement, s.Registry)
				if err != nil {
					return err
				}
			}
		}
		b := statement.Signed
		if (state == nil && b.Sequence != 0) || (state != nil && (b.Sequence != state.Sequence+1 || b.PreviousHash != state.HeadHash)) {
			return ErrConflict
		}
		if _, err := Advance(state, statement, s.Registry); err != nil {
			return &ValidationError{err}
		}
		if uint64(len(entries)) >= MaxSafeInteger {
			return errors.New("registry log is full")
		}
		entry := LogEntry{statement, time.Now().UTC().Format(time.RFC3339Nano)}
		encoded, err := canonicalValue(entry)
		if err != nil {
			return err
		}
		stats := storageStats(tx)
		if stats.Entries >= s.limits.MaxEntries || uint64(len(encoded)) > s.limits.MaxLogBytes || stats.LogBytes > s.limits.MaxLogBytes-uint64(len(encoded)) {
			return ErrCapacity
		}
		if err := tx.Bucket(entriesBucket).Put(indexKey(uint64(len(entries))), encoded); err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return receipt, err
	}
	snapshot, err := s.snapshot(entries)
	if err != nil {
		return receipt, err
	}
	index := len(entries) - 1
	hash, err := StatementHash(statement)
	if err != nil {
		return receipt, err
	}
	return Receipt{index, hash, snapshot.Inclusion(index), snapshot.Heads}, nil
}

type Snapshot struct {
	Entries              []LogEntry
	Leaves               []MapLeaf
	logHashes, mapHashes []string
	Heads                Heads
}

func signedHead[T any](body T, key ed25519.PrivateKey) (SignedHead[T], error) {
	b, err := canonicalValue(body)
	if err != nil {
		return SignedHead[T]{}, err
	}
	return SignedHead[T]{body, AgentID(key.Public().(ed25519.PublicKey)), base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, b))}, nil
}
func (s *Store) Snapshot(size *uint64) (*Snapshot, error) {
	var entries []LogEntry
	err := s.db.View(func(tx *bolt.Tx) error { var err error; entries, err = readEntries(tx, size); return err })
	if err != nil {
		return nil, err
	}
	return s.snapshot(entries)
}
func (s *Store) snapshot(entries []LogEntry) (*Snapshot, error) {
	snap := &Snapshot{Entries: entries, Leaves: []MapLeaf{}, logHashes: []string{}, mapHashes: []string{}}
	for _, e := range entries {
		b, err := canonicalValue(e)
		if err != nil {
			return nil, err
		}
		snap.logHashes = append(snap.logHashes, leafHash(b))
		hash, err := StatementHash(e.Statement)
		if err != nil {
			return nil, err
		}
		snap.Leaves = append(snap.Leaves, MapLeaf{e.Statement.Signed.AgentID, e.Statement.Signed.Sequence, hash})
	}
	sort.Slice(snap.Leaves, func(i, j int) bool {
		a, b := snap.Leaves[i], snap.Leaves[j]
		if a.AgentID == b.AgentID {
			return a.Sequence < b.Sequence
		}
		return a.AgentID < b.AgentID
	})
	for _, leaf := range snap.Leaves {
		b, err := canonicalValue(leaf)
		if err != nil {
			return nil, err
		}
		snap.mapHashes = append(snap.mapHashes, leafHash(b))
	}
	n := uint64(len(entries))
	timestamp := s.createdAt
	if n > 0 {
		timestamp = entries[n-1].ReceivedAt
	}
	var err error
	snap.Heads.Log, err = signedHead(HeadBody{"charter.log", s.Registry, n, treeRoot(snap.logHashes), timestamp}, s.key)
	if err != nil {
		return nil, err
	}
	snap.Heads.Epoch, err = signedHead(EpochBody{"charter.epoch", s.Registry, n, n, treeRoot(snap.mapHashes), n, snap.Heads.Log.Signed.RootHash, timestamp}, s.key)
	return snap, err
}
func (s *Snapshot) witness(index int) *MapWitness {
	if index < 0 || index >= len(s.Leaves) {
		return nil
	}
	return &MapWitness{s.Leaves[index], index, inclusionPath(s.mapHashes, index)}
}
func (s *Snapshot) Chain(agentID string) ChainResult {
	chain := []Statement{}
	for _, e := range s.Entries {
		if e.Statement.Signed.AgentID == agentID {
			chain = append(chain, e.Statement)
		}
	}
	// The last leaf <= this agent, and its immediate successor. This proves
	// either the chain's upper bound or an empty range, including tree boundaries.
	right := sort.Search(len(s.Leaves), func(i int) bool { return s.Leaves[i].AgentID > agentID })
	return ChainResult{chain, RangeProof{agentID, len(chain) > 0, s.witness(right - 1), s.witness(right)}, s.Heads}
}
func (s *Snapshot) Inclusion(index int) Inclusion {
	return Inclusion{s.Entries[index], index, inclusionPath(s.logHashes, index)}
}
func (s *Snapshot) Consistency(oldSize int) []string {
	return consistencyPath(s.logHashes, oldSize, true)
}
