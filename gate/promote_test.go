package gate

import (
	"encoding/json"
	"testing"

	"github.com/corpo/qntm/pkg/types"
)

func TestPromotePayloadMarshalRoundTrip(t *testing.T) {
	payload := PromotePayload{
		ConvID:     "test-org",
		GatewayKID: "gw-kid-test",
		Rules: []ThresholdRule{
			{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 3},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded PromotePayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ConvID != "test-org" {
		t.Fatalf("expected conv_id=test-org, got %s", decoded.ConvID)
	}
	if decoded.GatewayKID != "gw-kid-test" {
		t.Fatalf("expected gateway_kid=gw-kid-test, got %s", decoded.GatewayKID)
	}
	if len(decoded.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(decoded.Rules))
	}
	if decoded.Rules[0].M != 2 {
		t.Fatalf("expected M=2, got %d", decoded.Rules[0].M)
	}
	if decoded.Rules[0].N != 3 {
		t.Fatalf("expected N=3, got %d", decoded.Rules[0].N)
	}
}

func TestConfigPayloadMarshalRoundTrip(t *testing.T) {
	payload := ConfigPayload{
		Rules: []ThresholdRule{
			{Service: "stripe", Endpoint: "/charges", Verb: "POST", M: 3, N: 5},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ConfigPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(decoded.Rules))
	}
	if decoded.Rules[0].Service != "stripe" {
		t.Fatalf("expected service=stripe, got %s", decoded.Rules[0].Service)
	}
	if decoded.Rules[0].M != 3 {
		t.Fatalf("expected M=3, got %d", decoded.Rules[0].M)
	}
}

func TestPromotePayloadRequiresConvID(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// Promote without conv_id should fail
	payload := PromotePayload{
		ConvID:     "",
		GatewayKID: "gw-kid-test",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	body, _ := json.Marshal(payload)

	err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body},
	})
	if err == nil {
		t.Fatal("expected error for promote without conv_id")
	}
}

func TestPromoteWithGatewayKID(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	payload := PromotePayload{
		ConvID:     "multi-org",
		GatewayKID: "gw-kid-test",
		Rules: []ThresholdRule{
			{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 3},
		},
	}
	body, _ := json.Marshal(payload)

	err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body},
	})
	if err != nil {
		t.Fatalf("handlePromote failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if state == nil {
		t.Fatal("conversation state not created")
	}
	if state.ConvID != "multi-org" {
		t.Fatalf("unexpected conv_id: %s", state.ConvID)
	}
	if state.GatewayKID != "gw-kid-test" {
		t.Fatalf("unexpected gateway_kid: %s", state.GatewayKID)
	}
	// Participants are derived from conversation membership, not from promote payload
	if len(state.Participants) != 0 {
		t.Fatalf("expected 0 participants (populated from membership), got %d", len(state.Participants))
	}
}

func TestPromoteOverwritesExistingState(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// First promote
	payload1 := PromotePayload{
		ConvID:     "org-v1",
		GatewayKID: "gw-kid-v1",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	body1, _ := json.Marshal(payload1)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body1},
	})

	// Second promote replaces state
	payload2 := PromotePayload{
		ConvID:     "org-v2",
		GatewayKID: "gw-kid-v2",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 2}},
	}
	body2, _ := json.Marshal(payload2)
	err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body2},
	})
	if err != nil {
		t.Fatalf("second promote failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if state.ConvID != "org-v2" {
		t.Fatalf("expected org-v2, got %s", state.ConvID)
	}
	if state.GatewayKID != "gw-kid-v2" {
		t.Fatalf("expected gw-kid-v2, got %s", state.GatewayKID)
	}
	if state.Rules[0].M != 2 {
		t.Fatalf("expected M=2, got %d", state.Rules[0].M)
	}
}

func TestConfigUpdatesRulesOnPromotedConversation(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// Promote first
	promotePayload := PromotePayload{
		ConvID:     "cfg-org",
		GatewayKID: "gw-kid-test",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	promoteBody, _ := json.Marshal(promotePayload)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: promoteBody},
	})

	// Config with multiple rules
	configPayload := ConfigPayload{
		Rules: []ThresholdRule{
			{Service: "github", Endpoint: "/repos", Verb: "DELETE", M: 3, N: 5},
			{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 5},
		},
	}
	configBody, _ := json.Marshal(configPayload)

	err := gw.handleConfig(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageConfig), Body: configBody},
	})
	if err != nil {
		t.Fatalf("handleConfig failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if len(state.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(state.Rules))
	}
	if state.Rules[0].Service != "github" {
		t.Fatalf("expected first rule service=github, got %s", state.Rules[0].Service)
	}
	if state.Rules[0].M != 3 {
		t.Fatalf("expected first rule M=3, got %d", state.Rules[0].M)
	}
}

func TestGateMessageTypeConstants(t *testing.T) {
	if string(GateMessagePromote) != "gate.promote" {
		t.Fatalf("unexpected GateMessagePromote: %s", GateMessagePromote)
	}
	if string(GateMessageConfig) != "gate.config" {
		t.Fatalf("unexpected GateMessageConfig: %s", GateMessageConfig)
	}
	if string(GateMessageSecret) != "gate.secret" {
		t.Fatalf("unexpected GateMessageSecret: %s", GateMessageSecret)
	}
}

func TestPromoteGatewayKIDStored(t *testing.T) {
	payload := PromotePayload{
		ConvID:     "auto-kid-org",
		GatewayKID: "gw-kid-test",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}

	id := newTestIdentity()
	gw := NewGateway(id)
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	body, _ := json.Marshal(payload)
	err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body},
	})
	if err != nil {
		t.Fatalf("handlePromote failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if state.GatewayKID != "gw-kid-test" {
		t.Fatalf("expected gateway_kid=gw-kid-test, got %s", state.GatewayKID)
	}
}
