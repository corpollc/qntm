package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/corpo/qntm/gate"
)

func TestFormatGateMessage_Request(t *testing.T) {
	msg := gate.GateConversationMessage{
		Type:           gate.GateMessageRequest,
		OrgID:          "acme",
		RequestID:      "req-123",
		Verb:           "GET",
		TargetEndpoint: "/api.php",
		TargetService:  "trivia",
		SignerKID:      "abc123",
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	body, _ := json.Marshal(msg)
	result := FormatGateMessage("gate.request", body)

	if !strings.Contains(result, "GATE REQUEST") {
		t.Fatalf("expected GATE REQUEST, got: %s", result)
	}
	if !strings.Contains(result, "req-123") {
		t.Fatalf("expected request ID, got: %s", result)
	}
	if !strings.Contains(result, "trivia") {
		t.Fatalf("expected service name, got: %s", result)
	}
}

func TestFormatGateMessage_Approval(t *testing.T) {
	msg := gate.GateConversationMessage{
		Type:      gate.GateMessageApproval,
		RequestID: "req-456",
		SignerKID: "signer-xyz",
	}
	body, _ := json.Marshal(msg)
	result := FormatGateMessage("gate.approval", body)

	if !strings.Contains(result, "GATE APPROVAL") {
		t.Fatalf("expected GATE APPROVAL, got: %s", result)
	}
	if !strings.Contains(result, "signer-xyz") {
		t.Fatalf("expected signer KID, got: %s", result)
	}
}

func TestFormatGateMessage_Executed(t *testing.T) {
	msg := gate.GateConversationMessage{
		Type:                gate.GateMessageExecuted,
		RequestID:           "req-789",
		ExecutionStatusCode: 200,
	}
	body, _ := json.Marshal(msg)
	result := FormatGateMessage("gate.executed", body)

	if !strings.Contains(result, "GATE EXECUTED") {
		t.Fatalf("expected GATE EXECUTED, got: %s", result)
	}
	if !strings.Contains(result, "HTTP 200") {
		t.Fatalf("expected HTTP status, got: %s", result)
	}
}

func TestFormatGateMessage_InvalidJSON(t *testing.T) {
	result := FormatGateMessage("gate.request", []byte("not json"))
	if result != "not json" {
		t.Fatalf("expected raw body for invalid JSON, got: %s", result)
	}
}

func TestChatEntryBodyBytes_UTF8(t *testing.T) {
	entry := chatArchiveEntry{
		Body:         `{"hello":"world"}`,
		BodyEncoding: "utf8",
	}
	got := chatEntryBodyBytes(entry)
	if string(got) != `{"hello":"world"}` {
		t.Fatalf("expected JSON body, got: %s", string(got))
	}
}

func TestChatEntryBodyBytes_Base64(t *testing.T) {
	// base64 RawStdEncoding of "test data"
	entry := chatArchiveEntry{
		Body:         "dGVzdCBkYXRh",
		BodyEncoding: "base64",
	}
	got := chatEntryBodyBytes(entry)
	if string(got) != "test data" {
		t.Fatalf("expected 'test data', got: %s", string(got))
	}
}
