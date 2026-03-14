# Gateway Agent Brief

This note summarizes the current gateway approval-model decisions for coding agents. It is a handoff aid, not the canonical protocol spec.

## Core Decisions

- `gate.promote` enables the gateway for a conversation and sets the minimum approval floor for ordinary gateway requests.
- `gate.promote` does not freeze the signer roster for future requests.
- Each `gate.request` must freeze its own approval context:
  - `eligible_signer_kids`
  - `required_approvals`
- The frozen approval context is part of the signed request material. Approvers must be signing the exact roster and threshold that the gateway will enforce.
- The gateway must verify that the request snapshot matches canonical conversation membership and applicable policy at request-creation time.
- The gateway must reject any request whose `required_approvals` is below the promoted floor.
- If `signer_kid` remains in request or approval JSON, treat it as redundant. The only trusted signer identity is the authenticated qntm envelope sender, and any redundant JSON identity must match it.
- Only votes from senders in the request's frozen `eligible_signer_kids` roster count.
- Membership-governed actions, especially add/remove participant flows, require unanimity among current human participants even if the promoted floor is lower.
- Any membership change after promotion invalidates all pending unexecuted requests. They must be reissued under a fresh signer snapshot.

## Implementation Implications

- Update shared gate schema/types so `gate.request` carries the frozen signer roster and per-request threshold.
- Update request hashing/signing so the frozen approval context is covered by the request signature.
- Update gateway scan logic to evaluate approvals against the frozen per-request roster, not live membership.
- Update approval/disapproval handling so signer identity comes from the authenticated envelope sender, not trusted JSON fields.
- Update membership-change handling so pending requests are invalidated on add/remove.
- Keep `gate.promote` focused on conversation-wide policy floor and gateway enablement, not on freezing signers for later requests.

## Relevant Beads

- `qntm-z26.7` request-scoped approval context and threshold floor semantics
- `qntm-z26.5` conversation promotion semantics and gateway participant validation
- `qntm-e83` approval state derivation
- `qntm-z26.2` post-promotion membership governance
- `qntm-3gde` bind approvals to authenticated sender identity
- `qntm-qko0` enforce promotion and membership-derived signer invariants in the worker
