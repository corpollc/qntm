package gate

import (
	"encoding/json"
	"testing"

	"github.com/corpo/qntm/pkg/types"
)

// helper: promote a conversation with the given signers
func promoteConv(t *testing.T, gw *Gateway, conv *types.Conversation, orgID string, signers []Signer) {
	t.Helper()
	payload := PromotePayload{
		ConvID:     orgID,
		GatewayKID: "gw-kid-test",
		Rules:      []ThresholdRule{{Service: "*", Endpoint: "*", Verb: "*", M: 1, N: 1}},
	}
	body, _ := json.Marshal(payload)
	if err := gw.handlePromote(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessagePromote), Body: body},
	}); err != nil {
		t.Fatalf("promoteConv: %v", err)
	}
	// Add signers as participants (participants are now derived from conversation membership)
	state := gw.GetConversationState(conv.ID)
	for _, s := range signers {
		state.Participants[s.KID] = s.PublicKey
	}
}

func TestMembershipProposal_RequiresPromotedConversation(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	proposal := MembershipProposalPayload{
		ProposalID:  "p1",
		Action:      "add",
		MemberKID:   "new-member-kid",
		MemberPubkey: encKey(signer.pub),
		ProposerKID: signer.kid,
	}
	body, _ := json.Marshal(proposal)
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{
			BodyType: string(GateMessageMembershipProposal),
			Body:     body,
		},
	}, nil)
	if err == nil {
		t.Fatal("expected error for membership proposal in non-promoted conversation")
	}
}

func TestMembershipProposal_StoresProposal(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer1 := newTestSigner()
	signer2 := newTestSigner()
	promoteConv(t, gw, conv, "test-org", []Signer{
		{KID: signer1.kid, PublicKey: signer1.pub, Label: "alice"},
		{KID: signer2.kid, PublicKey: signer2.pub, Label: "bob"},
	})

	newMember := newTestSigner()
	proposal := MembershipProposalPayload{
		ProposalID:   "p1",
		Action:       "add",
		MemberKID:    newMember.kid,
		MemberPubkey: encKey(newMember.pub),
		ProposerKID:  signer1.kid,
	}
	body, _ := json.Marshal(proposal)
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{
			BodyType: string(GateMessageMembershipProposal),
			Body:     body,
		},
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	state := gw.GetConversationState(convID)
	if state.PendingMembershipProposals == nil {
		t.Fatal("PendingMembershipProposals is nil")
	}
	p, ok := state.PendingMembershipProposals["p1"]
	if !ok {
		t.Fatal("proposal p1 not found")
	}
	if p.Action != "add" {
		t.Fatalf("expected action=add, got %s", p.Action)
	}
	if p.MemberKID != newMember.kid {
		t.Fatalf("expected member_kid=%s, got %s", newMember.kid, p.MemberKID)
	}
	// The proposer's approval should already be recorded
	if len(p.Approvals) != 1 {
		t.Fatalf("expected 1 approval (proposer auto-approves), got %d", len(p.Approvals))
	}
	if _, ok := p.Approvals[signer1.kid]; !ok {
		t.Fatal("proposer's approval not recorded")
	}
}

func TestMembershipApproval_RequiresAllSigners(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer1 := newTestSigner()
	signer2 := newTestSigner()
	signer3 := newTestSigner()
	promoteConv(t, gw, conv, "test-org", []Signer{
		{KID: signer1.kid, PublicKey: signer1.pub, Label: "alice"},
		{KID: signer2.kid, PublicKey: signer2.pub, Label: "bob"},
		{KID: signer3.kid, PublicKey: signer3.pub, Label: "charlie"},
	})

	newMember := newTestSigner()
	// Propose
	proposal := MembershipProposalPayload{
		ProposalID:   "p1",
		Action:       "add",
		MemberKID:    newMember.kid,
		MemberPubkey: encKey(newMember.pub),
		ProposerKID:  signer1.kid,
	}
	body, _ := json.Marshal(proposal)
	_ = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipProposal), Body: body},
	}, nil)

	// Approve from signer2 only
	approval := MembershipApprovalPayload{
		ProposalID:  "p1",
		ApproverKID: signer2.kid,
	}
	body, _ = json.Marshal(approval)
	_ = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipApproval), Body: body},
	}, nil)

	// Should still be pending — need signer3 too
	state := gw.GetConversationState(convID)
	p := state.PendingMembershipProposals["p1"]
	if p == nil {
		t.Fatal("proposal should still be pending")
	}
	if len(p.Approvals) != 2 {
		t.Fatalf("expected 2 approvals, got %d", len(p.Approvals))
	}

	// The new member should NOT be in participants yet
	if _, ok := state.Participants[newMember.kid]; ok {
		t.Fatal("new member should NOT be in participants yet")
	}
}

func TestMembershipApproval_ExecutesWhenUnanimous(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer1 := newTestSigner()
	signer2 := newTestSigner()
	promoteConv(t, gw, conv, "test-org", []Signer{
		{KID: signer1.kid, PublicKey: signer1.pub, Label: "alice"},
		{KID: signer2.kid, PublicKey: signer2.pub, Label: "bob"},
	})

	newMember := newTestSigner()

	// Propose (signer1 auto-approves)
	proposal := MembershipProposalPayload{
		ProposalID:   "p1",
		Action:       "add",
		MemberKID:    newMember.kid,
		MemberPubkey: encKey(newMember.pub),
		ProposerKID:  signer1.kid,
	}
	body, _ := json.Marshal(proposal)
	_ = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipProposal), Body: body},
	}, nil)

	// Approve from signer2 — now unanimous
	approval := MembershipApprovalPayload{
		ProposalID:  "p1",
		ApproverKID: signer2.kid,
	}
	body, _ = json.Marshal(approval)
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipApproval), Body: body},
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The new member should now be in participants
	state := gw.GetConversationState(convID)
	if _, ok := state.Participants[newMember.kid]; !ok {
		t.Fatal("new member should be in participants after unanimous approval")
	}

	// Proposal should be removed
	if _, ok := state.PendingMembershipProposals["p1"]; ok {
		t.Fatal("proposal should be removed after execution")
	}
}

func TestMembershipApproval_ExecutesRemoveWhenUnanimous(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer1 := newTestSigner()
	signer2 := newTestSigner()
	signer3 := newTestSigner()
	promoteConv(t, gw, conv, "test-org", []Signer{
		{KID: signer1.kid, PublicKey: signer1.pub, Label: "alice"},
		{KID: signer2.kid, PublicKey: signer2.pub, Label: "bob"},
		{KID: signer3.kid, PublicKey: signer3.pub, Label: "charlie"},
	})

	// Verify signer3 is a participant
	state := gw.GetConversationState(convID)
	if _, ok := state.Participants[signer3.kid]; !ok {
		t.Fatal("signer3 should be a participant")
	}

	// Propose removing signer3
	proposal := MembershipProposalPayload{
		ProposalID:  "p-remove",
		Action:      "remove",
		MemberKID:   signer3.kid,
		ProposerKID: signer1.kid,
	}
	body, _ := json.Marshal(proposal)
	_ = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipProposal), Body: body},
	}, nil)

	// signer2 approves
	approval := MembershipApprovalPayload{ProposalID: "p-remove", ApproverKID: signer2.kid}
	body, _ = json.Marshal(approval)
	_ = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipApproval), Body: body},
	}, nil)

	// signer3 approves — now unanimous
	approval = MembershipApprovalPayload{ProposalID: "p-remove", ApproverKID: signer3.kid}
	body, _ = json.Marshal(approval)
	_ = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{BodyType: string(GateMessageMembershipApproval), Body: body},
	}, nil)

	state = gw.GetConversationState(convID)
	if _, ok := state.Participants[signer3.kid]; ok {
		t.Fatal("signer3 should be removed after unanimous approval")
	}
	if len(state.Participants) != 2 {
		t.Fatalf("expected 2 participants, got %d", len(state.Participants))
	}
}

func TestDirectGroupAdd_RejectedInPromotedConversation(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	promoteConv(t, gw, conv, "test-org", []Signer{
		{KID: signer.kid, PublicKey: signer.pub, Label: "alice"},
	})

	// Try to send a group_add message directly
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{
			BodyType: "group_add",
			Body:     []byte(`{"members":[{"kid":"new"}]}`),
		},
	}, nil)
	if err == nil {
		t.Fatal("expected error for direct group_add in promoted conversation")
	}
}

func TestDirectGroupRemove_RejectedInPromotedConversation(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	signer := newTestSigner()
	promoteConv(t, gw, conv, "test-org", []Signer{
		{KID: signer.kid, PublicKey: signer.pub, Label: "alice"},
	})

	// Try to send a group_remove message directly
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{
			BodyType: "group_remove",
			Body:     []byte(`{"members":["some-kid"]}`),
		},
	}, nil)
	if err == nil {
		t.Fatal("expected error for direct group_remove in promoted conversation")
	}
}

func TestMembershipChange_AllowedInNonPromotedConversation(t *testing.T) {
	gw := NewGateway(newTestIdentity())
	convID := newTestConversationID()
	conv := &types.Conversation{ID: convID}
	gw.RegisterConversation(conv)

	// NOT promoted — group_add and group_remove should be silently ignored
	// (the gateway doesn't process them, but it shouldn't error either)
	err := gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{
			BodyType: "group_add",
			Body:     []byte(`{"members":[{"kid":"new"}]}`),
		},
	}, nil)
	if err != nil {
		t.Fatalf("group_add in non-promoted conversation should not error, got: %v", err)
	}

	err = gw.processMessage(conv, &types.Message{
		Inner: &types.InnerPayload{
			BodyType: "group_remove",
			Body:     []byte(`{"members":["some-kid"]}`),
		},
	}, nil)
	if err != nil {
		t.Fatalf("group_remove in non-promoted conversation should not error, got: %v", err)
	}
}
