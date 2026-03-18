import { describe, it, expect } from 'vitest';
import {
  generateIdentity,
  keyIDFromPublicKey,
  base64UrlEncode,
  marshalCanonical,
} from '../src/index.js';
import {
  GovMessagePropose,
  GovMessageApprove,
  GovMessageApplied,
  signProposal,
  verifyProposal,
  hashProposal,
  signGovApproval,
  verifyGovApproval,
  createProposalBody,
} from '../src/governance/index.js';
import type { GovProposalSignable, GovApprovalSignable } from '../src/governance/index.js';

function makeIdentity() {
  return generateIdentity();
}

describe('Governance message types', () => {
  it('exports correct type constants', () => {
    expect(GovMessagePropose).toBe('gov.propose');
    expect(GovMessageApprove).toBe('gov.approve');
    expect(GovMessageApplied).toBe('gov.applied');
  });
});

describe('Governance proposal signing', () => {
  it('signs and verifies a floor-change proposal', () => {
    const proposer = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));

    const signable: GovProposalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-456',
      proposal_type: 'floor_change',
      proposed_floor: 3,
      proposed_rules: undefined,
      eligible_signer_kids: [kid],
      required_approvals: 1,
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
    };

    const sig = signProposal(proposer.privateKey, signable);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64); // Ed25519 signature

    expect(verifyProposal(proposer.publicKey, signable, sig)).toBe(true);

    // Wrong key fails
    const other = makeIdentity();
    expect(verifyProposal(other.publicKey, signable, sig)).toBe(false);
  });

  it('signs and verifies a rules-change proposal', () => {
    const proposer = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));

    const signable: GovProposalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-789',
      proposal_type: 'rules_change',
      proposed_floor: undefined,
      proposed_rules: [
        { service: 'api', endpoint: '/v1/deploy', verb: 'POST', m: 2 },
      ],
      eligible_signer_kids: [kid],
      required_approvals: 1,
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
    };

    const sig = signProposal(proposer.privateKey, signable);
    expect(verifyProposal(proposer.publicKey, signable, sig)).toBe(true);
  });

  it('produces deterministic proposal hashes', () => {
    const signable: GovProposalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-456',
      proposal_type: 'floor_change',
      proposed_floor: 3,
      proposed_rules: undefined,
      eligible_signer_kids: ['kid1'],
      required_approvals: 1,
      expires_at_unix: 1710000000,
    };

    const h1 = hashProposal(signable);
    const h2 = hashProposal(signable);
    expect(h1).toEqual(h2);
  });
});

describe('Governance approval signing', () => {
  it('signs and verifies a governance approval', () => {
    const approver = makeIdentity();

    const proposalSignable: GovProposalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-456',
      proposal_type: 'floor_change',
      proposed_floor: 3,
      proposed_rules: undefined,
      eligible_signer_kids: ['kid1'],
      required_approvals: 1,
      expires_at_unix: 1710000000,
    };
    const proposalHash = hashProposal(proposalSignable);

    const approvalSignable: GovApprovalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-456',
      proposal_hash: proposalHash,
    };

    const sig = signGovApproval(approver.privateKey, approvalSignable);
    expect(verifyGovApproval(approver.publicKey, approvalSignable, sig)).toBe(true);

    const other = makeIdentity();
    expect(verifyGovApproval(other.publicKey, approvalSignable, sig)).toBe(false);
  });
});

describe('Membership governance proposals', () => {
  it('signs and verifies a member_add proposal', () => {
    const proposer = makeIdentity();
    const newMember = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));
    const newMemberKid = base64UrlEncode(keyIDFromPublicKey(newMember.publicKey));

    const signable: GovProposalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-add-1',
      proposal_type: 'member_add',
      proposed_floor: undefined,
      proposed_rules: undefined,
      proposed_members: [{ kid: newMemberKid, public_key: base64UrlEncode(newMember.publicKey) }],
      eligible_signer_kids: [kid],
      required_approvals: 1,
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
    };

    const sig = signProposal(proposer.privateKey, signable);
    expect(verifyProposal(proposer.publicKey, signable, sig)).toBe(true);
  });

  it('signs and verifies a member_remove proposal', () => {
    const proposer = makeIdentity();
    const removedMember = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));
    const removedKid = base64UrlEncode(keyIDFromPublicKey(removedMember.publicKey));

    const signable: GovProposalSignable = {
      conv_id: 'conv-123',
      proposal_id: 'prop-rm-1',
      proposal_type: 'member_remove',
      proposed_floor: undefined,
      proposed_rules: undefined,
      removed_member_kids: [removedKid],
      eligible_signer_kids: [kid],
      required_approvals: 1,
      expires_at_unix: Math.floor(Date.now() / 1000) + 3600,
    };

    const sig = signProposal(proposer.privateKey, signable);
    expect(verifyProposal(proposer.publicKey, signable, sig)).toBe(true);
  });
});

describe('createProposalBody', () => {
  it('creates a floor-change proposal with frozen roster', () => {
    const proposer = makeIdentity();
    const member2 = makeIdentity();
    const kid1 = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));
    const kid2 = base64UrlEncode(keyIDFromPublicKey(member2.publicKey));

    const body = createProposalBody(proposer, {
      convId: 'conv-123',
      proposalType: 'floor_change',
      proposedFloor: 3,
      eligibleSignerKids: [kid1, kid2],
      requiredApprovals: 2,
      expiresInSeconds: 3600,
    });

    expect(body.type).toBe('gov.propose');
    expect(body.proposal_id).toBeTruthy();
    expect(body.proposal_type).toBe('floor_change');
    expect(body.proposed_floor).toBe(3);
    expect(body.eligible_signer_kids).toEqual([kid1, kid2]);
    expect(body.required_approvals).toBe(2);
    expect(body.signer_kid).toBe(kid1);
    expect(body.signature).toBeTruthy();
  });

  it('creates a rules-change proposal', () => {
    const proposer = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));

    const rules = [
      { service: 'api', endpoint: '/v1/deploy', verb: 'POST', m: 3 },
    ];

    const body = createProposalBody(proposer, {
      convId: 'conv-123',
      proposalType: 'rules_change',
      proposedRules: rules,
      eligibleSignerKids: [kid],
      requiredApprovals: 1,
      expiresInSeconds: 3600,
    });

    expect(body.type).toBe('gov.propose');
    expect(body.proposal_type).toBe('rules_change');
    expect(body.proposed_rules).toEqual(rules);
  });

  it('creates a member_add proposal', () => {
    const proposer = makeIdentity();
    const newMember = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));
    const newMemberKid = base64UrlEncode(keyIDFromPublicKey(newMember.publicKey));

    const body = createProposalBody(proposer, {
      convId: 'conv-123',
      proposalType: 'member_add',
      proposedMembers: [{ kid: newMemberKid, publicKey: base64UrlEncode(newMember.publicKey) }],
      eligibleSignerKids: [kid],
      requiredApprovals: 1,
      expiresInSeconds: 3600,
    });

    expect(body.type).toBe('gov.propose');
    expect(body.proposal_type).toBe('member_add');
    expect(body.proposed_members).toHaveLength(1);
    expect(body.proposed_members![0].kid).toBe(newMemberKid);
  });

  it('creates a member_remove proposal', () => {
    const proposer = makeIdentity();
    const kid = base64UrlEncode(keyIDFromPublicKey(proposer.publicKey));

    const body = createProposalBody(proposer, {
      convId: 'conv-123',
      proposalType: 'member_remove',
      removedMemberKids: ['kid-to-remove'],
      eligibleSignerKids: [kid],
      requiredApprovals: 1,
      expiresInSeconds: 3600,
    });

    expect(body.type).toBe('gov.propose');
    expect(body.proposal_type).toBe('member_remove');
    expect(body.removed_member_kids).toEqual(['kid-to-remove']);
  });
});
