package gate

import (
	"encoding/json"
	"testing"

	"github.com/corpo/qntm/pkg/types"
)

func TestPromotePayloadMarshalRoundTrip(t *testing.T) {
	signer := newTestSigner()
	payload := PromotePayload{
		OrgID: "test-org",
		Signers: []Signer{
			{KID: signer.kid, PublicKey: signer.pub, Label: "alice"},
		},
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

	if decoded.OrgID != "test-org" {
		t.Fatalf("expected org_id=test-org, got %s", decoded.OrgID)
	}
	if len(decoded.Signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(decoded.Signers))
	}
	if decoded.Signers[0].KID != signer.kid {
		t.Fatalf("expected kid=%s, got %s", signer.kid, decoded.Signers[0].KID)
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

func TestPromotePayloadRequiresOrgID(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// Promote without org_id should fail
	payload := PromotePayload{
		OrgID:   "",
		Signers: []Signer{},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	body, _ := json.Marshal(payload)

	err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body},
	})
	if err == nil {
		t.Fatal("expected error for promote without org_id")
	}
}

func TestPromoteWithMultipleSigners(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer1 := newTestSigner()
	signer2 := newTestSigner()
	signer3 := newTestSigner()

	payload := PromotePayload{
		OrgID: "multi-org",
		Signers: []Signer{
			{KID: signer1.kid, PublicKey: signer1.pub, Label: "alice"},
			{KID: signer2.kid, PublicKey: signer2.pub, Label: "bob"},
			{KID: signer3.kid, PublicKey: signer3.pub, Label: "charlie"},
		},
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
	if state.OrgID != "multi-org" {
		t.Fatalf("unexpected org_id: %s", state.OrgID)
	}
	if len(state.Participants) != 3 {
		t.Fatalf("expected 3 participants, got %d", len(state.Participants))
	}
	if _, ok := state.Participants[signer1.kid]; !ok {
		t.Fatal("signer1 not found in participants")
	}
	if _, ok := state.Participants[signer2.kid]; !ok {
		t.Fatal("signer2 not found in participants")
	}
	if _, ok := state.Participants[signer3.kid]; !ok {
		t.Fatal("signer3 not found in participants")
	}
}

func TestPromoteOverwritesExistingState(t *testing.T) {
	id := newTestIdentity()
	gw := NewGateway(id)

	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// First promote
	signer1 := newTestSigner()
	payload1 := PromotePayload{
		OrgID:   "org-v1",
		Signers: []Signer{{KID: signer1.kid, PublicKey: signer1.pub}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	body1, _ := json.Marshal(payload1)
	_ = gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body1},
	})

	// Second promote replaces state
	signer2 := newTestSigner()
	payload2 := PromotePayload{
		OrgID:   "org-v2",
		Signers: []Signer{{KID: signer2.kid, PublicKey: signer2.pub}},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 2, N: 2}},
	}
	body2, _ := json.Marshal(payload2)
	err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body2},
	})
	if err != nil {
		t.Fatalf("second promote failed: %v", err)
	}

	state := gw.GetConversationState(convID)
	if state.OrgID != "org-v2" {
		t.Fatalf("expected org-v2, got %s", state.OrgID)
	}
	if len(state.Participants) != 1 {
		t.Fatalf("expected 1 participant, got %d", len(state.Participants))
	}
	if _, ok := state.Participants[signer2.kid]; !ok {
		t.Fatal("signer2 not found after re-promote")
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
		OrgID:   "cfg-org",
		Signers: []Signer{},
		Rules:   []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
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

func TestSignerKIDAutoPopulatedFromPublicKey(t *testing.T) {
	signer := newTestSigner()
	payload := PromotePayload{
		OrgID: "auto-kid-org",
		Signers: []Signer{
			{PublicKey: signer.pub}, // KID intentionally left empty
		},
		Rules: []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
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
	// The handlePromote computes KID from public key when KID is empty
	expectedKID := KIDFromPublicKey(signer.pub)
	if _, ok := state.Participants[expectedKID]; !ok {
		t.Fatalf("expected participant with auto-computed KID %s, got keys: %v",
			expectedKID, func() []string {
				keys := make([]string, 0)
				for k := range state.Participants {
					keys = append(keys, k)
				}
				return keys
			}())
	}
}
