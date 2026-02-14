package cli

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/corpo/qntm/handle"
	"github.com/corpo/qntm/naming"
	"github.com/corpo/qntm/pkg/types"
	"github.com/corpo/qntm/shortref"
)

func TestFormatKID_LocalName(t *testing.T) {
	dir := t.TempDir()
	names, _ := naming.NewStore(dir)
	names.SetIdentityName("aabbccdd11223344aabbccdd11223344", "Alice")

	trie := shortref.New()
	trie.Insert("aabbccdd11223344aabbccdd11223344")

	dc := &DisplayContext{Names: names, Trie: trie}

	var kid types.KeyID
	b, _ := hex.DecodeString("aabbccdd11223344aabbccdd11223344")
	copy(kid[:], b)

	got := dc.FormatKID(kid, "")
	if got != "Alice (aab)" {
		t.Errorf("expected 'Alice (aab)', got %q", got)
	}
}

func TestFormatKID_RevealedHandle(t *testing.T) {
	dir := t.TempDir()
	names, _ := naming.NewStore(dir)
	handles, _ := handle.NewStore(dir)
	handles.StoreReveal("cccc000000000000cccc000000000000", "aabbccdd11223344aabbccdd11223344", "alice_handle")

	trie := shortref.New()
	trie.Insert("aabbccdd11223344aabbccdd11223344")

	dc := &DisplayContext{Names: names, Trie: trie, Handles: handles}

	var kid types.KeyID
	b, _ := hex.DecodeString("aabbccdd11223344aabbccdd11223344")
	copy(kid[:], b)

	got := dc.FormatKID(kid, "cccc000000000000cccc000000000000")
	if got != "@alice_handle (aab)" {
		t.Errorf("expected '@alice_handle (aab)', got %q", got)
	}
}

func TestFormatKID_ShortRef(t *testing.T) {
	dir := t.TempDir()
	names, _ := naming.NewStore(dir)

	trie := shortref.New()
	trie.Insert("aabbccdd11223344aabbccdd11223344")
	trie.Insert("ff00000000000000ff00000000000000")

	dc := &DisplayContext{Names: names, Trie: trie}

	var kid types.KeyID
	b, _ := hex.DecodeString("aabbccdd11223344aabbccdd11223344")
	copy(kid[:], b)

	got := dc.FormatKID(kid, "")
	// Should be short ref "aab" (unique prefix)
	if got != "aab" {
		t.Errorf("expected 'aab', got %q", got)
	}
}

func TestFormatConvID_LocalName(t *testing.T) {
	dir := t.TempDir()
	names, _ := naming.NewStore(dir)
	names.SetConversationName("11223344556677881122334455667788", "Engineering")

	trie := shortref.New()
	trie.Insert("11223344556677881122334455667788")

	dc := &DisplayContext{Names: names, Trie: trie}

	var convID types.ConversationID
	b, _ := hex.DecodeString("11223344556677881122334455667788")
	copy(convID[:], b)

	got := dc.FormatConvID(convID)
	if got != "Engineering (112)" {
		t.Errorf("expected 'Engineering (112)', got %q", got)
	}
}

func TestFormatConvID_ShortRef(t *testing.T) {
	dir := t.TempDir()
	names, _ := naming.NewStore(dir)

	trie := shortref.New()
	trie.Insert("11223344556677881122334455667788")

	dc := &DisplayContext{Names: names, Trie: trie}

	var convID types.ConversationID
	b, _ := hex.DecodeString("11223344556677881122334455667788")
	copy(convID[:], b)

	got := dc.FormatConvID(convID)
	if got != "112" {
		t.Errorf("expected '112', got %q", got)
	}
}

func TestFormatKID_NameTakesPriorityOverHandle(t *testing.T) {
	dir := t.TempDir()
	names, _ := naming.NewStore(dir)
	names.SetIdentityName("aabbccdd11223344aabbccdd11223344", "Alice")
	handles, _ := handle.NewStore(dir)
	handles.StoreReveal("cccc000000000000cccc000000000000", "aabbccdd11223344aabbccdd11223344", "alice_handle")

	trie := shortref.New()
	trie.Insert("aabbccdd11223344aabbccdd11223344")

	dc := &DisplayContext{Names: names, Trie: trie, Handles: handles}

	var kid types.KeyID
	b, _ := hex.DecodeString("aabbccdd11223344aabbccdd11223344")
	copy(kid[:], b)

	got := dc.FormatKID(kid, "cccc000000000000cccc000000000000")
	if got != "Alice (aab)" {
		t.Errorf("local name should take priority, got %q", got)
	}
}

func TestResolveConvID_ByName(t *testing.T) {
	dir := t.TempDir()
	configDir = dir // set package-level var for resolveConvID

	// Create a naming store with a conv name
	names, _ := naming.NewStore(dir)
	names.SetConversationName("aabbccdd11223344aabbccdd11223344", "TestConv")

	got, err := resolveConvID("TestConv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "aabbccdd11223344aabbccdd11223344" {
		t.Errorf("expected resolved hex, got %q", got)
	}
}

func TestResolveKID_ByName(t *testing.T) {
	dir := t.TempDir()
	configDir = dir

	names, _ := naming.NewStore(dir)
	names.SetIdentityName("aabbccdd11223344aabbccdd11223344", "Alice")

	got, err := resolveKID("Alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "aabbccdd11223344aabbccdd11223344" {
		t.Errorf("expected resolved hex, got %q", got)
	}
}

func TestResolveConvID_FullHex(t *testing.T) {
	dir := t.TempDir()
	configDir = dir
	os.MkdirAll(dir, 0700)

	got, err := resolveConvID("aabbccdd11223344aabbccdd11223344")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "aabbccdd11223344aabbccdd11223344" {
		t.Errorf("expected passthrough hex, got %q", got)
	}
}
