// Package shortref implements trie-based short references for hex IDs.
// Any hex ID (kid, conv_id) can be referred to by its shortest unique prefix
// with a minimum of 3 characters.
package shortref

import (
	"fmt"
	"strings"
	"sync"
)

const MinPrefixLen = 3

// Trie is a hex-character trie for computing shortest unique prefixes.
type Trie struct {
	mu   sync.RWMutex
	root *node
	ids  map[string]struct{} // full hex ids in the trie
}

type node struct {
	children [16]*node
	count    int // how many full IDs pass through this node
	terminal bool
}

func hexCharToIdx(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

// New creates an empty trie.
func New() *Trie {
	return &Trie{root: &node{}, ids: make(map[string]struct{})}
}

// Insert adds a hex ID to the trie.
func (t *Trie) Insert(hexID string) {
	hexID = strings.ToLower(hexID)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.ids[hexID]; exists {
		return
	}
	t.ids[hexID] = struct{}{}
	n := t.root
	for i := 0; i < len(hexID); i++ {
		idx := hexCharToIdx(hexID[i])
		if idx < 0 {
			return
		}
		if n.children[idx] == nil {
			n.children[idx] = &node{}
		}
		n = n.children[idx]
		n.count++
	}
	n.terminal = true
}

// Remove removes a hex ID from the trie.
func (t *Trie) Remove(hexID string) {
	hexID = strings.ToLower(hexID)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.ids[hexID]; !exists {
		return
	}
	delete(t.ids, hexID)
	n := t.root
	for i := 0; i < len(hexID); i++ {
		idx := hexCharToIdx(hexID[i])
		if idx < 0 {
			return
		}
		child := n.children[idx]
		if child == nil {
			return
		}
		child.count--
		if child.count == 0 {
			n.children[idx] = nil
			return
		}
		n = child
	}
}

// ShortRef returns the shortest unique prefix for the given hex ID.
// Returns the full ID if not in the trie.
func (t *Trie) ShortRef(hexID string) string {
	hexID = strings.ToLower(hexID)
	t.mu.RLock()
	defer t.mu.RUnlock()
	if _, exists := t.ids[hexID]; !exists {
		return hexID
	}
	n := t.root
	for i := 0; i < len(hexID); i++ {
		idx := hexCharToIdx(hexID[i])
		if idx < 0 {
			return hexID
		}
		n = n.children[idx]
		if n == nil {
			return hexID
		}
		prefixLen := i + 1
		if n.count == 1 && prefixLen >= MinPrefixLen {
			return hexID[:prefixLen]
		}
	}
	return hexID
}

// Resolve resolves a short prefix to full hex IDs. Returns all matches.
func (t *Trie) Resolve(prefix string) []string {
	prefix = strings.ToLower(prefix)
	t.mu.RLock()
	defer t.mu.RUnlock()
	var matches []string
	for id := range t.ids {
		if strings.HasPrefix(id, prefix) {
			matches = append(matches, id)
		}
	}
	return matches
}

// ResolveExact resolves a prefix to exactly one ID, or returns an error.
func (t *Trie) ResolveExact(prefix string) (string, error) {
	matches := t.Resolve(prefix)
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no match for prefix %q", prefix)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous prefix %q matches %d IDs: %s", prefix, len(matches), strings.Join(matches, ", "))
	}
}

// All returns all IDs in the trie.
func (t *Trie) All() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]string, 0, len(t.ids))
	for id := range t.ids {
		result = append(result, id)
	}
	return result
}

// Len returns the number of IDs in the trie.
func (t *Trie) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.ids)
}
