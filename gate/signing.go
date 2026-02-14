// Package gate implements the qntm-gate multisig API gateway.
//
// qntm-gate lets DAOs and agent-governed LLCs interact with real-world APIs
// (banks, HR platforms, etc.) through threshold authorization. Multiple signers
// must approve requests before API credentials are injected and requests forwarded.
package gate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"github.com/corpo/qntm/pkg/cbor"
)

// GateSignable is the CBOR structure signed for gate authorization requests.
// Per the spec: signature covers CBOR({org_id, request_id, verb, target_endpoint, target_service, H(payload)}).
type GateSignable struct {
	OrgID          string `cbor:"org_id"`
	RequestID      string `cbor:"request_id"`
	Verb           string `cbor:"verb"`
	TargetEndpoint string `cbor:"target_endpoint"`
	TargetService  string `cbor:"target_service"`
	PayloadHash    []byte `cbor:"payload_hash"`
}

// ApprovalSignable is the CBOR structure signed for approvals.
type ApprovalSignable struct {
	OrgID       string `cbor:"org_id"`
	RequestID   string `cbor:"request_id"`
	RequestHash []byte `cbor:"request_hash"`
}

// ComputePayloadHash returns SHA-256 of the payload bytes.
func ComputePayloadHash(payload []byte) []byte {
	h := sha256.Sum256(payload)
	return h[:]
}

// SignRequest signs a gate request.
func SignRequest(privKey ed25519.PrivateKey, s *GateSignable) ([]byte, error) {
	tbs, err := cbor.MarshalCanonical(s)
	if err != nil {
		return nil, fmt.Errorf("marshal signable: %w", err)
	}
	return ed25519.Sign(privKey, tbs), nil
}

// VerifyRequest verifies a gate request signature.
func VerifyRequest(pubKey ed25519.PublicKey, s *GateSignable, sig []byte) error {
	tbs, err := cbor.MarshalCanonical(s)
	if err != nil {
		return fmt.Errorf("marshal signable: %w", err)
	}
	if !ed25519.Verify(pubKey, tbs, sig) {
		return fmt.Errorf("invalid request signature")
	}
	return nil
}

// SignApproval signs an approval.
func SignApproval(privKey ed25519.PrivateKey, s *ApprovalSignable) ([]byte, error) {
	tbs, err := cbor.MarshalCanonical(s)
	if err != nil {
		return nil, fmt.Errorf("marshal approval: %w", err)
	}
	return ed25519.Sign(privKey, tbs), nil
}

// VerifyApproval verifies an approval signature.
func VerifyApproval(pubKey ed25519.PublicKey, s *ApprovalSignable, sig []byte) error {
	tbs, err := cbor.MarshalCanonical(s)
	if err != nil {
		return fmt.Errorf("marshal approval: %w", err)
	}
	if !ed25519.Verify(pubKey, tbs, sig) {
		return fmt.Errorf("invalid approval signature")
	}
	return nil
}

// HashRequest computes SHA-256 of the CBOR-encoded GateSignable.
func HashRequest(s *GateSignable) ([]byte, error) {
	tbs, err := cbor.MarshalCanonical(s)
	if err != nil {
		return nil, fmt.Errorf("marshal signable: %w", err)
	}
	h := sha256.Sum256(tbs)
	return h[:], nil
}
