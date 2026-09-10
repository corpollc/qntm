/** Inspect private saved intent without interpreting it as accepted membership. */
import { base64UrlDecode, base64UrlEncode, deserializeEnvelope, serializeEnvelope, restoreGroupSession, parseGroupGenesisBody,
  keyIDFromPublicKey, QSP1Suite, openSecret, marshalCanonical, unmarshalCanonical } from '@corpollc/qntm'
import type { Identity } from '@corpollc/qntm'
import type { GroupSessionState } from '@corpollc/qntm'
import type { StoredGroupOperation, StoredGroupAdditionOrigin, StoredGroupRemovalOrigin, StoredGroupRemovalTarget, StoredGroupOperationEvidence } from './store'
type Addition = Extract<StoredGroupOperation, { kind: 'addition' }>
type Repair = Extract<StoredGroupOperation, { kind: 'addition_rekey' }>
const hex = (value: Uint8Array) => Array.from(value, b => b.toString(16).padStart(2, '0')).join('')
const suite = new QSP1Suite()
const fromHex = (value: string) => Uint8Array.from(value.match(/../g)!, byte => parseInt(byte, 16))

/** Pin the exact member record and admission incarnation a removal targets.
 * Reads the saved checkpoint only; it grants nothing and installs no keys. */
export function groupRemovalTarget(session: GroupSessionState, keyId: string): StoredGroupRemovalTarget {
  const member = parseGroupGenesisBody(base64UrlDecode(session.snapshot)).founding_members.find(row => hex(row.key_id) === keyId)
  if (!member) throw new Error('Removal target is not a current member')
  const admission = session.admissions[keyId]
  return { keyId, publicKey: hex(member.public_key), record: base64UrlEncode(marshalCanonical(member)), admission: admission ? structuredClone(admission) : null }
}
/** Refuse to publish an old removal against a later admission of its target.
 * Journals saved before target pinning still detect a readmission sourced at
 * the current epoch: a removal is prepared only while no addition is pending,
 * so any admission sourced at this epoch is newer than that intent. */
export function assertGroupRemovalTargetCurrent(session: GroupSessionState, target: StoredGroupRemovalTarget | undefined, removed: string[]) {
  if (!target) {
    for (const keyId of removed) {
      if (session.admissions[keyId]?.sourceEpoch === session.epoch) throw new Error('Saved removal predates a later admission of its target; its operation is preserved')
    }
    return
  }
  requireValue(removed.length === 1 && removed[0] === target.keyId, 'Saved removal differs from its pinned target; its operation is preserved')
  requireValue(sameGroupOperationValue(groupRemovalTarget(session, target.keyId), target), 'Saved removal no longer targets its original admission; its operation is preserved')
}
/** Validate a pinned target against its own record without any current state. */
export function validateGroupRemovalTarget(value: StoredGroupRemovalTarget) {
  requireValue(/^[a-f0-9]{32}$/.test(value.keyId) && /^[a-f0-9]{64}$/.test(value.publicKey), 'Invalid removal target key')
  const record = unmarshalCanonical<{ key_id: Uint8Array; public_key: Uint8Array }>(base64UrlDecode(value.record))
  requireValue(record && typeof record === 'object' && sameGroupOperationValue(marshalCanonical(record), base64UrlDecode(value.record))
    && base64UrlEncode(base64UrlDecode(value.record)) === value.record
    && record.key_id instanceof Uint8Array && hex(record.key_id) === value.keyId
    && record.public_key instanceof Uint8Array && hex(record.public_key) === value.publicKey
    && hex(keyIDFromPublicKey(fromHex(value.publicKey))) === value.keyId, 'Invalid removal target record')
  if (value.admission !== null) {
    const admission = value.admission
    requireValue(admission && typeof admission === 'object' && Object.keys(admission).sort().join(',') === 'addDigest,addId,completion,sourceEpoch'
      && /^[a-f0-9]{32}$/.test(admission.addId) && /^[a-f0-9]{64}$/.test(admission.addDigest)
      && Number.isSafeInteger(admission.sourceEpoch) && admission.sourceEpoch >= 0
      && !!admission.completion && typeof admission.completion === 'object'
      && Object.keys(admission.completion).sort().join(',') === 'rekeyDigest,rekeyId'
      && /^[a-f0-9]{32}$/.test(admission.completion.rekeyId) && /^[a-f0-9]{64}$/.test(admission.completion.rekeyDigest), 'Invalid removal target admission')
  }
}
export function sameGroupOperationValue(left: unknown, right: unknown) {
  const a = marshalCanonical(left), b = marshalCanonical(right)
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
function requireValue(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message) }
export const MAX_GROUP_OPERATION_REVISIONS = 256
export const MAX_GROUP_OPERATION_EVIDENCE_BYTES = 4 * 1024 * 1024
export function assertGroupOperationEvidenceBudget(origin: StoredGroupAdditionOrigin | StoredGroupRemovalOrigin | undefined, superseded: StoredGroupOperationEvidence[]) {
  requireValue(Array.isArray(superseded) && superseded.length <= MAX_GROUP_OPERATION_REVISIONS, 'Saved recovery evidence reached its revision limit; operation preserved')
  requireValue(marshalCanonical({ ...(origin ? { origin } : {}), superseded }).length <= MAX_GROUP_OPERATION_EVIDENCE_BYTES,
    'Saved recovery evidence reached its byte limit; operation preserved')
}
export function appendGroupOperationEvidence(op: Extract<StoredGroupOperation, { kind: 'addition_rekey' | 'renewal' | 'refresh' | 'removal_rekey' | 'rekey' }>) {
  const evidence: StoredGroupOperationEvidence[] = [...structuredClone(op.superseded ?? []),
    { kind: op.kind, controls: [...op.controls], welcomes: [...op.welcomes], delivered: op.delivered, delivery: 'unknown' }]
  assertGroupOperationEvidenceBudget(op.origin, evidence)
  return evidence
}
function originalAddition(op: Addition | Repair): Addition {
  return op.kind === 'addition' ? op : { kind: 'addition', controls: op.origin.controls, welcomes: op.origin.welcomes,
    expected: op.expected, delivered: op.origin.delivered, recipient: op.origin.recipient, recoveryChallenge: op.origin.recoveryChallenge }
}

export function groupAdditionIntent(identity: Identity, saved: Addition | Repair) {
  const op = originalAddition(saved)
  requireValue(op.controls.length === 2 && op.welcomes.length === 1, 'Invalid saved addition shape')
  const expected = restoreGroupSession(identity, op.expected), wire = base64UrlDecode(op.controls[0])
  const addition = deserializeEnvelope(wire), rekeyWire = base64UrlDecode(op.controls[1]), rekey = deserializeEnvelope(rekeyWire)
  requireValue(sameGroupOperationValue(serializeEnvelope(addition), wire) && sameGroupOperationValue(serializeEnvelope(rekey), rekeyWire)
    && hex(addition.conv_id) === expected.conversationId && hex(rekey.conv_id) === expected.conversationId,
  'Invalid saved addition context')
  const proof = { addId: hex(addition.msg_id), addDigest: hex(suite.hash(wire)) }
  if (saved.kind === 'addition_rekey') requireValue(saved.recipient === saved.origin.recipient && sameGroupOperationValue(saved.origin.admission, proof), 'Saved rotation differs from its original admission')
  const matches = Object.entries(expected.admissions).filter(([, admission]) => admission.addId === proof.addId && admission.addDigest === proof.addDigest)
  requireValue(matches.length === 1 && matches[0][1].completion && matches[0][1].sourceEpoch === addition.conv_epoch,
    'Saved addition lacks exact recipient provenance; preserve it for recovery')
  const kid = matches[0][0], recipient = parseGroupGenesisBody(base64UrlDecode(expected.snapshot)).founding_members.find(member => hex(member.key_id) === kid)?.public_key
  requireValue(recipient && hex(keyIDFromPublicKey(recipient)) === kid && (op.recipient === undefined || op.recipient === hex(recipient)),
    'Saved addition recipient differs from its admission proof')
  return { kid, recipient, proof, addition, rekey, rekeyWire }
}

/** Older journals kept the optional challenge only inside the recipient box. */
export function groupAdditionChallenge(identity: Identity, saved: Addition | Repair, intent = groupAdditionIntent(identity, saved)): string | null {
  const op = originalAddition(saved)
  const envelope = deserializeEnvelope(base64UrlDecode(op.welcomes[0]))
  const plain = openSecret(identity.privateKey, intent.recipient, envelope.ciphertext)
  const signed = unmarshalCanonical<{ payload: Record<string, unknown>; signature: Uint8Array }>(plain)
  const payload = signed?.payload, { ciphertext: _ciphertext, ...header } = envelope
  requireValue(payload && sameGroupOperationValue(plain, marshalCanonical(signed))
    && payload.proto === 'qntm/group-welcome/v1' && sameGroupOperationValue(payload.inviter_ik_pk, identity.publicKey)
    && sameGroupOperationValue(payload.recipient_ik_pk, intent.recipient)
    && sameGroupOperationValue(envelope.conv_id, intent.addition.conv_id)
    && sameGroupOperationValue(payload.envelope, header)
    && sameGroupOperationValue(payload.addition_id, intent.addition.msg_id)
    && sameGroupOperationValue(payload.rekey_id, intent.rekey.msg_id)
    && (payload.addition_hash === undefined || sameGroupOperationValue(payload.addition_hash, suite.hash(base64UrlDecode(op.controls[0]))))
    && (payload.rekey_hash === undefined || sameGroupOperationValue(payload.rekey_hash, suite.hash(intent.rekeyWire)))
    && signed.signature instanceof Uint8Array && suite.verify(identity.publicKey, marshalCanonical(payload), signed.signature),
  'Invalid saved welcome challenge binding')
  const challenge = payload.recovery_challenge
  requireValue(challenge === undefined || challenge instanceof Uint8Array && challenge.length === 32, 'Invalid saved recovery challenge')
  const value = challenge === undefined ? null : hex(challenge as Uint8Array)
  requireValue(op.recoveryChallenge === undefined || op.recoveryChallenge === value, 'Saved recovery challenge differs from its signed welcome')
  return value
}

/** Verify a saved renewal before preserving its challenge in a replacement. */
export function groupRenewalChallenge(identity: Identity, op: Extract<StoredGroupOperation, { kind: 'renewal' }>): string | null {
  requireValue(op.welcomes.length === 1 && /^[a-f0-9]{64}$/.test(op.recipient), 'Invalid saved renewal shape')
  const recipient = Uint8Array.from(op.recipient.match(/../g)!, byte => parseInt(byte, 16))
  const envelope = deserializeEnvelope(base64UrlDecode(op.welcomes[0])), { ciphertext: _ciphertext, ...header } = envelope
  const plain = openSecret(identity.privateKey, recipient, envelope.ciphertext)
  const signed = unmarshalCanonical<{ payload: Record<string, unknown>; signature: Uint8Array }>(plain), payload = signed?.payload
  const wireAdmission = (payload?.admissions as Record<string, unknown> | undefined)?.[hex(keyIDFromPublicKey(recipient))]
  const bytes = (value: string) => Uint8Array.from(value.match(/../g)!, byte => parseInt(byte, 16))
  requireValue(payload && op.admission.completion && payload.proto === 'qntm/group-renewal/v1'
    && sameGroupOperationValue(plain, marshalCanonical(signed)) && sameGroupOperationValue(payload.envelope, header)
    && hex(envelope.conv_id) === op.expected.conversationId
    && sameGroupOperationValue(payload.inviter_ik_pk, identity.publicKey) && sameGroupOperationValue(payload.recipient_ik_pk, recipient)
    && sameGroupOperationValue(wireAdmission, { add_id: bytes(op.admission.addId), add_hash: bytes(op.admission.addDigest), source_epoch: op.admission.sourceEpoch,
      rekey_id: bytes(op.admission.completion.rekeyId), rekey_hash: bytes(op.admission.completion.rekeyDigest) })
    && signed.signature instanceof Uint8Array && suite.verify(identity.publicKey, marshalCanonical(payload), signed.signature),
  'Invalid saved renewal challenge binding')
  const challenge = payload.recovery_challenge
  requireValue(challenge === undefined || challenge instanceof Uint8Array && challenge.length === 32, 'Invalid saved renewal recovery challenge')
  const value = challenge === undefined ? null : hex(challenge as Uint8Array)
  requireValue(!op.origin || value === op.origin.recoveryChallenge, 'Saved renewal differs from its original recovery challenge')
  return value
}

/** Recover the reviewed recipient from one authenticated sender-side refresh box.
 * Older browser journals omitted explicit metadata; never infer it from changes
 * in membership, and never reinterpret this generic purpose as admission.
 */
export function groupRefreshIntent(identity: Identity, op: Extract<StoredGroupOperation, { kind: 'refresh' }>) {
  requireValue(op.controls.length === 0 && op.welcomes.length === 1, 'Saved refresh must have one uniquely authenticated recipient; operation preserved')
  const expected = restoreGroupSession(identity, op.expected), snapshot = parseGroupGenesisBody(base64UrlDecode(expected.snapshot))
  const wire = base64UrlDecode(op.welcomes[0]), envelope = deserializeEnvelope(wire), { ciphertext: _ciphertext, ...header } = envelope
  const fromHex = (value: string) => Uint8Array.from(value.match(/../g)!, byte => parseInt(byte, 16))
  requireValue(wire.length <= 65536 && sameGroupOperationValue(serializeEnvelope(envelope), wire)
    && Object.keys(envelope).sort().join(',') === 'ciphertext,conv_epoch,conv_id,created_ts,expiry_ts,kind,msg_id,suite,v'
    && header.msg_id instanceof Uint8Array && header.msg_id.length === 16
    && Number.isSafeInteger(header.created_ts) && header.created_ts > 0 && Number.isSafeInteger(header.expiry_ts)
    && header.expiry_ts > header.created_ts && header.expiry_ts - header.created_ts <= 604800
    && envelope.ciphertext instanceof Uint8Array && envelope.ciphertext.length >= 40
    && header.v === 1 && header.suite === 'QSP-1' && (header as { kind?: string }).kind === 'group_welcome'
    && hex(header.conv_id) === expected.conversationId && header.conv_epoch === expected.epoch,
  'Invalid saved refresh header')
  const admissions = Object.fromEntries(Object.entries(expected.admissions).map(([kid, admission]) => {
    requireValue(admission.completion, 'Invalid saved refresh admission completion')
    return [kid, { add_id: fromHex(admission.addId), add_hash: fromHex(admission.addDigest), source_epoch: admission.sourceEpoch,
      rekey_id: fromHex(admission.completion.rekeyId), rekey_hash: fromHex(admission.completion.rekeyDigest) }]
  }))
  requireValue(op.recipient === undefined || /^[a-f0-9]{64}$/.test(op.recipient), 'Invalid saved refresh recipient')
  const matches: { recipient: Uint8Array; challenge: string | null }[] = []
  for (const member of snapshot.founding_members) {
    if (op.recipient !== undefined && hex(member.public_key) !== op.recipient) continue
    try {
      const plain = openSecret(identity.privateKey, member.public_key, envelope.ciphertext)
      const signed = unmarshalCanonical<{ payload: Record<string, unknown>; signature: Uint8Array }>(plain), payload = signed?.payload
      const fields = ['proto', 'envelope', 'inviter_ik_pk', 'recipient_ik_pk', 'group_key', 'group_state',
        ...(payload?.replay_from_seq !== undefined ? ['replay_from_seq'] : []),
        ...(payload?.admissions !== undefined ? ['admissions'] : []), ...(payload?.recovery_challenge !== undefined ? ['recovery_challenge'] : [])]
      requireValue(payload && Object.keys(signed).sort().join(',') === 'payload,signature'
        && Object.keys(payload).sort().join(',') === fields.sort().join(',')
        && sameGroupOperationValue(plain, marshalCanonical(signed)) && payload.proto === 'qntm/group-refresh/v1'
        && sameGroupOperationValue(payload.envelope, header) && sameGroupOperationValue(payload.inviter_ik_pk, identity.publicKey)
        && sameGroupOperationValue(payload.recipient_ik_pk, member.public_key)
        && sameGroupOperationValue(payload.group_key, fromHex(expected.root)) && sameGroupOperationValue(payload.group_state, snapshot)
        && (payload.admissions === undefined || sameGroupOperationValue(payload.admissions, admissions))
        && (payload.replay_from_seq === undefined || Number.isSafeInteger(payload.replay_from_seq) && (payload.replay_from_seq as number) >= 0)
        && signed.signature instanceof Uint8Array && suite.verify(identity.publicKey, marshalCanonical(payload), signed.signature),
      'Invalid signed refresh context')
      const challenge = payload.recovery_challenge
      requireValue(challenge === undefined || challenge instanceof Uint8Array && challenge.length === 32, 'Invalid signed refresh challenge')
      const value = challenge === undefined ? null : hex(challenge as Uint8Array)
      requireValue(op.recoveryChallenge === undefined || op.recoveryChallenge === value, 'Saved refresh challenge mismatch')
      matches.push({ recipient: member.public_key, challenge: value })
    } catch { /* Only a fully authenticated box establishes the reviewed recipient. */ }
  }
  requireValue(matches.length === 1, 'Saved refresh lacks a unique authenticated recipient or challenge; operation preserved')
  return matches[0]
}
