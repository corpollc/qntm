// Package charter implements the experimental Charter Registry v0.2 authority rules.
package charter

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

const DraftVersion = "0.2"
const MaxSafeInteger = uint64(1<<53 - 1)

var GenesisHash = strings.Repeat("0", 64)
var timestampPattern = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$`)

type Key struct {
	KID       string `json:"kid"`
	PublicKey string `json:"pubkey"`
}
type Governance struct {
	Keys      []Key `json:"keys"`
	Threshold int   `json:"threshold"`
}
type Signature struct {
	KID string `json:"kid"`
	Sig string `json:"sig"`
}
type SignedBody struct {
	Registry     string          `json:"registry"`
	AgentID      string          `json:"agent_id"`
	Sequence     uint64          `json:"seq"`
	PreviousHash string          `json:"prev_hash"`
	Type         string          `json:"type"`
	IssuedAt     string          `json:"issued_at"`
	Body         json.RawMessage `json:"body"`
}
type Statement struct {
	Signed     SignedBody  `json:"signed"`
	Signatures []Signature `json:"signatures"`
}
type State struct {
	Registry, AgentID, AgentPublicKey, HeadHash string
	Sequence                                    uint64
	Governance                                  *Governance
	AgentRights                                 map[string]bool
	NextCommitment                              string
	OperationalKeys                             map[string]bool
	Decommissioned                              bool
}

func digest(raw []byte) string                   { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func AgentID(publicKey ed25519.PublicKey) string { return digest(publicKey)[:32] }
func NewKey(publicKey ed25519.PublicKey) Key {
	return Key{AgentID(publicKey), base64.RawURLEncoding.EncodeToString(publicKey)}
}
func validHex(value string, size int) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == size && hex.EncodeToString(b) == value
}
func wire(value string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != size || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, errors.New("invalid canonical base64url")
	}
	return b, nil
}
func validTime(value string) bool {
	_, err := time.Parse(time.RFC3339Nano, value)
	return timestampPattern.MatchString(value) && err == nil
}
func obj(value any) (map[string]any, error) {
	o, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("expected object")
	}
	return o, nil
}
func str(value any) string { s, _ := value.(string); return s }
func fields(o map[string]any, names ...string) bool {
	if len(o) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := o[name]; !ok {
			return false
		}
	}
	return true
}
func integer(value any) (uint64, bool) {
	n, ok := value.(float64)
	return uint64(n), ok && n >= 0 && n <= float64(MaxSafeInteger) && math.Trunc(n) == n
}
func parseGovernance(value any) (*Governance, error) {
	o, err := obj(value)
	if err != nil {
		return nil, err
	}
	if !fields(o, "keys", "threshold") {
		return nil, errors.New("invalid governance fields")
	}
	keys, ok := o["keys"].([]any)
	threshold, valid := integer(o["threshold"])
	if !ok || !valid || threshold < 1 || threshold > uint64(len(keys)) {
		return nil, errors.New("invalid governance threshold")
	}
	g := &Governance{Keys: []Key{}, Threshold: int(threshold)}
	seen := map[string]bool{}
	for _, value := range keys {
		k, err := obj(value)
		if err != nil {
			return nil, err
		}
		publicKey, err := wire(str(k["pubkey"]), 32)
		id := str(k["kid"])
		if err != nil || !validPublicKey(publicKey) || !fields(k, "kid", "pubkey") || AgentID(publicKey) != id || seen[id] {
			return nil, errors.New("invalid or duplicate governance key")
		}
		seen[id] = true
		g.Keys = append(g.Keys, Key{id, str(k["pubkey"])})
	}
	return g, nil
}

func GovernanceCommitment(g Governance) (string, error) {
	copy := Governance{Keys: append([]Key(nil), g.Keys...), Threshold: g.Threshold}
	sort.Slice(copy.Keys, func(i, j int) bool { return copy.Keys[i].KID < copy.Keys[j].KID })
	b, err := canonicalValue(copy)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}
func StatementHash(s Statement) (string, error) {
	b, err := canonicalValue(s.Signed)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

// ParseStatement checks the full JSON shape before decoding into Go structs, so
// absent/null sequence fields cannot silently become sequence zero.
func ParseStatement(raw []byte) (Statement, error) {
	var s Statement
	canonical, err := CanonicalJSON(raw)
	if err != nil {
		return s, err
	}
	var value any
	if err := json.Unmarshal(canonical, &value); err != nil {
		return s, err
	}
	o, err := obj(value)
	if err != nil {
		return s, err
	}
	b, err := obj(o["signed"])
	if err != nil {
		return s, err
	}
	_, seqOK := integer(b["seq"])
	if !fields(o, "signed", "signatures") || !fields(b, "registry", "agent_id", "seq", "prev_hash", "type", "issued_at", "body") || !seqOK || str(b["registry"]) == "" || !validHex(str(b["agent_id"]), 16) || !validHex(str(b["prev_hash"]), 32) || !validTime(str(b["issued_at"])) {
		return s, errors.New("invalid statement fields")
	}
	switch str(b["type"]) {
	case "charter", "constitution.amend", "governance.rotate", "opkey.delegate", "opkey.revoke", "agent.successor", "agent.decommission", "liveness.update", "statement":
	default:
		return s, errors.New("unknown core statement type")
	}
	signatures, ok := o["signatures"].([]any)
	if !ok {
		return s, errors.New("expected signatures array")
	}
	seen := map[string]bool{}
	for _, value := range signatures {
		sig, err := obj(value)
		if err != nil {
			return s, err
		}
		id := str(sig["kid"])
		_, err = wire(str(sig["sig"]), 64)
		if !fields(sig, "kid", "sig") || !validHex(id, 16) || seen[id] || err != nil {
			return s, errors.New("invalid or duplicate signature")
		}
		seen[id] = true
	}
	err = json.Unmarshal(canonical, &s)
	return s, err
}

// Advance returns fresh authority state. It never mutates the previous state.
func Advance(previous *State, input Statement, registry string) (*State, error) {
	raw, err := canonicalValue(input)
	if err != nil {
		return nil, err
	}
	s, err := ParseStatement(raw)
	if err != nil {
		return nil, err
	}
	b := s.Signed
	if registry == "" || b.Registry != registry {
		return nil, errors.New("registry audience mismatch")
	}
	var body any
	if err := json.Unmarshal(b.Body, &body); err != nil {
		return nil, err
	}
	state := &State{Registry: registry, AgentID: b.AgentID, AgentRights: map[string]bool{}, OperationalKeys: map[string]bool{}}
	if previous == nil {
		if b.Sequence != 0 || b.PreviousHash != GenesisHash || b.Type != "charter" {
			return nil, errors.New("first statement must be a genesis charter")
		}
		o, err := obj(body)
		if err != nil {
			return nil, err
		}
		pk, err := wire(str(o["agent_pubkey"]), 32)
		if err != nil || !validPublicKey(pk) || AgentID(pk) != b.AgentID {
			return nil, errors.New("agent public key does not match ID")
		}
		state.AgentPublicKey = str(o["agent_pubkey"])
		gov, present := o["governance"]
		if !present {
			return nil, errors.New("missing governance")
		}
		if gov != nil {
			state.Governance, err = parseGovernance(gov)
			if err != nil {
				return nil, err
			}
		}
		rights, ok := o["agent_rights"].([]any)
		if !ok {
			return nil, errors.New("expected agent_rights array")
		}
		for _, right := range rights {
			r := str(right)
			if (r != "statement" && r != "liveness.update") || state.AgentRights[r] {
				return nil, errors.New("invalid or duplicate informational agent right")
			}
			state.AgentRights[r] = true
		}
		if commitment, ok := o["next_governance_commitment"]; ok {
			if !validHex(str(commitment), 32) {
				return nil, errors.New("invalid commitment")
			}
			state.NextCommitment = str(commitment)
		}
		if extensions, ok := o["extensions"]; ok {
			e, err := obj(extensions)
			if err != nil {
				return nil, err
			}
			for namespace := range e {
				if namespace == "" {
					return nil, errors.New("empty extension namespace")
				}
			}
		}
	} else {
		if b.AgentID != previous.AgentID || registry != previous.Registry || b.Sequence != previous.Sequence+1 || b.PreviousHash != previous.HeadHash || b.Type == "charter" {
			return nil, errors.New("sequence, audience, or previous hash mismatch")
		}
		if previous.Decommissioned {
			return nil, errors.New("decommissioned record is terminal")
		}
		if previous.Governance == nil {
			return nil, errors.New("record is frozen at birth")
		}
		*state = *previous
		state.OperationalKeys = map[string]bool{}
		for k, v := range previous.OperationalKeys {
			state.OperationalKeys[k] = v
		}
	}
	publicKeys := map[string]string{b.AgentID: state.AgentPublicKey}
	if state.Governance != nil {
		for _, key := range state.Governance.Keys {
			publicKeys[key.KID] = key.PublicKey
		}
	}
	canonical, err := canonicalValue(b)
	if err != nil {
		return nil, err
	}
	signers := map[string]bool{}
	for _, signature := range s.Signatures {
		pk, err := wire(publicKeys[signature.KID], 32)
		if err != nil {
			return nil, errors.New("signature outside current authority")
		}
		sig, _ := wire(signature.Sig, 64)
		if !ed25519.Verify(pk, canonical, sig) {
			return nil, errors.New("invalid statement signature")
		}
		signers[signature.KID] = true
	}
	count := 0
	if state.Governance != nil {
		for _, k := range state.Governance.Keys {
			if signers[k.KID] {
				count++
			}
		}
	}
	governed := state.Governance != nil && count >= state.Governance.Threshold
	if previous == nil {
		if !signers[b.AgentID] || (state.Governance != nil && !governed) {
			return nil, errors.New("charter requires agent signature and governance acceptance")
		}
	} else {
		if !governed && !(state.AgentRights[b.Type] && signers[b.AgentID]) {
			return nil, errors.New("statement lacks current governing authority")
		}
		switch b.Type {
		case "statement":
			o, err := obj(body)
			if err != nil {
				return nil, err
			}
			if str(o["namespace"]) == "" {
				return nil, errors.New("empty statement namespace")
			}
			if _, ok := o["data"]; !ok {
				return nil, errors.New("missing statement data")
			}
			if schema, ok := o["schema"]; ok && str(schema) == "" {
				return nil, errors.New("empty schema identifier")
			}
		case "governance.rotate":
			o, err := obj(body)
			if err != nil {
				return nil, err
			}
			next, err := parseGovernance(o["governance"])
			if err != nil {
				return nil, err
			}
			commitment, err := GovernanceCommitment(*next)
			if err != nil {
				return nil, err
			}
			if state.NextCommitment != "" && state.NextCommitment != commitment {
				return nil, errors.New("rotation violates governance commitment")
			}
			state.Governance = next
			state.NextCommitment = ""
			if c, ok := o["next_governance_commitment"]; ok {
				if !validHex(str(c), 32) {
					return nil, errors.New("invalid next commitment")
				}
				state.NextCommitment = str(c)
			}
		case "opkey.delegate", "opkey.revoke":
			o, err := obj(body)
			if err != nil {
				return nil, err
			}
			id := str(o["kid"])
			if !validHex(id, 16) {
				return nil, errors.New("invalid operational key ID")
			}
			if b.Type == "opkey.revoke" {
				if !state.OperationalKeys[id] {
					return nil, errors.New("operational key not delegated")
				}
				delete(state.OperationalKeys, id)
			} else {
				if str(o["scope"]) == "" {
					return nil, errors.New("missing operational scope")
				}
				if expiry, ok := o["expires_at"]; ok && !validTime(str(expiry)) {
					return nil, errors.New("invalid operational expiry")
				}
				state.OperationalKeys[id] = true
			}
		case "agent.successor":
			o, err := obj(body)
			if err != nil {
				return nil, err
			}
			if !validHex(str(o["agent_id"]), 16) || str(o["agent_id"]) == b.AgentID {
				return nil, errors.New("invalid successor")
			}
		case "agent.decommission":
			state.Decommissioned = true
		}
	}
	state.Sequence = b.Sequence
	state.HeadHash, err = StatementHash(s)
	return state, err
}

func Replay(chain []Statement, registry, agentID string) (*State, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty chain")
	}
	var state *State
	for i, s := range chain {
		if s.Signed.AgentID != agentID {
			return nil, errors.New("agent audience mismatch")
		}
		next, err := Advance(state, s, registry)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		state = next
	}
	return state, nil
}
