package gate

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const gateSchemaVersion = "1"

// SQLiteStore persists qntm-gate org state and conversation messages in SQLite.
// A single store instance satisfies both OrganizationStore and MessageStore.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database file and applies schema bootstrap.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	store := &SQLiteStore{db: db}
	if err := store.bootstrap(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) bootstrap() error {
	if _, err := s.db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return fmt.Errorf("enable wal mode: %w", err)
	}
	if _, err := s.db.Exec("PRAGMA foreign_keys=ON;"); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS gate_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS gate_orgs (
			id TEXT PRIMARY KEY,
			signers_json BLOB NOT NULL,
			rules_json BLOB NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS gate_credentials (
			org_id TEXT NOT NULL,
			id TEXT NOT NULL,
			service TEXT NOT NULL,
			value TEXT NOT NULL,
			header_name TEXT,
			header_value TEXT,
			description TEXT,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(org_id, id),
			FOREIGN KEY(org_id) REFERENCES gate_orgs(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS gate_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			org_id TEXT NOT NULL,
			message_json BLOB NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(org_id) REFERENCES gate_orgs(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_gate_messages_org_id_id
			ON gate_messages(org_id, id ASC);`,
		`INSERT INTO gate_meta(key, value)
		 VALUES ('schema_version', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value;`,
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin bootstrap tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	for i, stmt := range stmts {
		if i == len(stmts)-1 {
			if _, err = tx.Exec(stmt, gateSchemaVersion); err != nil {
				return fmt.Errorf("apply bootstrap statement %d: %w", i, err)
			}
			continue
		}
		if _, err = tx.Exec(stmt); err != nil {
			return fmt.Errorf("apply bootstrap statement %d: %w", i, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit bootstrap tx: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Create creates a new org.
func (s *SQLiteStore) Create(org *Org) error {
	if org == nil {
		return fmt.Errorf("org is required")
	}
	signersJSON, err := json.Marshal(org.Signers)
	if err != nil {
		return fmt.Errorf("marshal signers: %w", err)
	}
	rulesJSON, err := json.Marshal(org.Rules)
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin create org tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.Exec(
		`INSERT INTO gate_orgs(id, signers_json, rules_json) VALUES (?, ?, ?)`,
		org.ID, signersJSON, rulesJSON,
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return fmt.Errorf("org %q already exists", org.ID)
		}
		return fmt.Errorf("insert org: %w", err)
	}

	for _, cred := range org.Credentials {
		if err = upsertCredential(tx, org.ID, cred); err != nil {
			return err
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit create org tx: %w", err)
	}
	return nil
}

// Get returns an org by ID.
func (s *SQLiteStore) Get(orgID string) (*Org, error) {
	row := s.db.QueryRow(`SELECT signers_json, rules_json FROM gate_orgs WHERE id = ?`, orgID)

	var signersJSON []byte
	var rulesJSON []byte
	if err := row.Scan(&signersJSON, &rulesJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("org %q not found", orgID)
		}
		return nil, fmt.Errorf("query org %q: %w", orgID, err)
	}

	var signers []Signer
	if err := json.Unmarshal(signersJSON, &signers); err != nil {
		return nil, fmt.Errorf("decode signers for %q: %w", orgID, err)
	}
	var rules []ThresholdRule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		return nil, fmt.Errorf("decode rules for %q: %w", orgID, err)
	}

	creds := make(map[string]*Credential)
	rows, err := s.db.Query(`
		SELECT id, service, value, header_name, header_value, description
		FROM gate_credentials
		WHERE org_id = ?
		ORDER BY id ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query credentials for %q: %w", orgID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cred Credential
		if err := rows.Scan(&cred.ID, &cred.Service, &cred.Value, &cred.HeaderName, &cred.HeaderValue, &cred.Description); err != nil {
			return nil, fmt.Errorf("scan credential for %q: %w", orgID, err)
		}
		creds[cred.ID] = cloneCredential(&cred)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials for %q: %w", orgID, err)
	}

	return &Org{
		ID:          orgID,
		Signers:     signers,
		Rules:       rules,
		Credentials: creds,
	}, nil
}

// AddCredential adds or updates a credential in an org.
func (s *SQLiteStore) AddCredential(orgID string, cred *Credential) error {
	if cred == nil {
		return fmt.Errorf("credential is required")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin add credential tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var exists int
	if err = tx.QueryRow(`SELECT COUNT(1) FROM gate_orgs WHERE id = ?`, orgID).Scan(&exists); err != nil {
		return fmt.Errorf("count org %q: %w", orgID, err)
	}
	if exists == 0 {
		return fmt.Errorf("org %q not found", orgID)
	}

	if err = upsertCredential(tx, orgID, cred); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit add credential tx: %w", err)
	}
	return nil
}

// GetCredentialByService returns one credential matching a service name.
func (s *SQLiteStore) GetCredentialByService(orgID, service string) (*Credential, error) {
	var exists int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM gate_orgs WHERE id = ?`, orgID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("lookup org %q: %w", orgID, err)
	}
	if exists == 0 {
		return nil, fmt.Errorf("org %q not found", orgID)
	}

	row := s.db.QueryRow(`
		SELECT id, service, value, header_name, header_value, description
		FROM gate_credentials
		WHERE org_id = ? AND service = ?
		ORDER BY id ASC
		LIMIT 1`, orgID, service)

	var cred Credential
	if err := row.Scan(&cred.ID, &cred.Service, &cred.Value, &cred.HeaderName, &cred.HeaderValue, &cred.Description); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("no credential for service %q in org %q", service, orgID)
		}
		return nil, fmt.Errorf("query credential for %q/%q: %w", orgID, service, err)
	}
	return cloneCredential(&cred), nil
}

// ReadGateMessages returns all gate messages for an org in insertion order.
func (s *SQLiteStore) ReadGateMessages(orgID string) ([]GateConversationMessage, error) {
	rows, err := s.db.Query(`
		SELECT message_json
		FROM gate_messages
		WHERE org_id = ?
		ORDER BY id ASC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query messages for %q: %w", orgID, err)
	}
	defer rows.Close()

	out := make([]GateConversationMessage, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("scan message for %q: %w", orgID, err)
		}
		var msg GateConversationMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return nil, fmt.Errorf("decode message for %q: %w", orgID, err)
		}
		out = append(out, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages for %q: %w", orgID, err)
	}
	return out, nil
}

// WriteGateMessage stores a gate message for an org.
func (s *SQLiteStore) WriteGateMessage(orgID string, msg *GateConversationMessage) error {
	if msg == nil {
		return fmt.Errorf("message is required")
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO gate_messages(org_id, message_json) VALUES (?, ?)`,
		orgID, raw,
	)
	if err != nil {
		return fmt.Errorf("insert message: %w", err)
	}
	return nil
}

func upsertCredential(tx *sql.Tx, orgID string, cred *Credential) error {
	if cred == nil {
		return fmt.Errorf("credential is required")
	}
	_, err := tx.Exec(`
		INSERT INTO gate_credentials(org_id, id, service, value, header_name, header_value, description)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(org_id, id) DO UPDATE SET
			service=excluded.service,
			value=excluded.value,
			header_name=excluded.header_name,
			header_value=excluded.header_value,
			description=excluded.description`,
		orgID, cred.ID, cred.Service, cred.Value, cred.HeaderName, cred.HeaderValue, cred.Description,
	)
	if err != nil {
		return fmt.Errorf("upsert credential %q in org %q: %w", cred.ID, orgID, err)
	}
	return nil
}

func cloneCredential(c *Credential) *Credential {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed")
}
