package cli

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"

	"github.com/corpo/qntm/pkg/types"
)

func testConversation(t *testing.T) *types.Conversation {
	t.Helper()

	var convID types.ConversationID
	if _, err := rand.Read(convID[:]); err != nil {
		t.Fatalf("failed to generate conv id: %v", err)
	}

	root := make([]byte, 32)
	if _, err := rand.Read(root); err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	return &types.Conversation{
		ID: convID,
		Keys: types.ConversationKeys{
			Root: root,
		},
	}
}

func TestChatArchiveAppendAndLoad(t *testing.T) {
	origConfigDir := configDir
	configDir = t.TempDir()
	defer func() {
		configDir = origConfigDir
	}()

	conv := testConversation(t)
	entry := chatArchiveEntry{
		MessageID:    "aabbcc",
		Direction:    "incoming",
		SenderKIDHex: "00112233445566778899aabbccddeeff",
		BodyType:     "text",
		Body:         "hello",
		BodyEncoding: "utf8",
		CreatedTS:    1700000000,
	}

	if err := appendChatArchiveEntry(conv, entry); err != nil {
		t.Fatalf("append failed: %v", err)
	}

	loaded, err := loadChatArchive(conv)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if len(loaded) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(loaded))
	}
	if loaded[0].Body != "hello" {
		t.Fatalf("expected body 'hello', got %q", loaded[0].Body)
	}

	raw, err := os.ReadFile(chatArchivePath(conv.ID))
	if err != nil {
		t.Fatalf("failed reading archive file: %v", err)
	}
	if bytes.Contains(raw, []byte("hello")) {
		t.Fatalf("archive file unexpectedly contains plaintext body")
	}
}

func TestChatArchiveDedupByMessageIDAndDirection(t *testing.T) {
	origConfigDir := configDir
	configDir = t.TempDir()
	defer func() {
		configDir = origConfigDir
	}()

	conv := testConversation(t)
	entry := chatArchiveEntry{
		MessageID: "deadbeef",
		Direction: "outgoing",
		BodyType:  "text",
		Body:      "once",
		CreatedTS: 1700000010,
	}

	if err := appendChatArchiveEntry(conv, entry); err != nil {
		t.Fatalf("first append failed: %v", err)
	}
	if err := appendChatArchiveEntry(conv, entry); err != nil {
		t.Fatalf("second append failed: %v", err)
	}

	loaded, err := loadChatArchive(conv)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected deduped length 1, got %d", len(loaded))
	}
}
