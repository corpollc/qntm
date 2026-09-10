/** Inspect private saved intent without interpreting it as accepted membership. */
import { base64UrlDecode, deserializeEnvelope, serializeEnvelope, restoreGroupSession, parseGroupGenesisBody,
  keyIDFromPublicKey, QSP1Suite, openSecret, marshalCanonical, unmarshalCanonical } from '@corpollc/qntm'
import type { Identity } from '@corpollc/qntm'
import type { StoredGroupOperation } from './store'
type Addition = Extract<StoredGroupOperation, { kind: 'addition' }>
const hex = (value: Uint8Array) => Array.from(value, b => b.toString(16).padStart(2, '0')).join('')
const suite = new QSP1Suite()
export const sameGroupOperationValue = (left: unknown, right: unknown) => hex(marshalCanonical(left)) === hex(marshalCanonical(right))
function requireValue(condition: unknown, message: string): asserts condition { if (!condition) throw new Error(message) }

export function groupAdditionIntent(identity: Identity, op: Addition) {
  requireValue(op.controls.length === 2 && op.welcomes.length === 1, 'Invalid saved addition shape')
  const expected = restoreGroupSession(identity, op.expected), wire = base64UrlDecode(op.controls[0])
  const addition = deserializeEnvelope(wire), rekeyWire = base64UrlDecode(op.controls[1]), rekey = deserializeEnvelope(rekeyWire)
  requireValue(sameGroupOperationValue(serializeEnvelope(addition), wire) && sameGroupOperationValue(serializeEnvelope(rekey), rekeyWire)
    && hex(addition.conv_id) === expected.conversationId && hex(rekey.conv_id) === expected.conversationId,
  'Invalid saved addition context')
  const proof = { addId: hex(addition.msg_id), addDigest: hex(suite.hash(wire)) }
  const matches = Object.entries(expected.admissions).filter(([, admission]) => admission.addId === proof.addId && admission.addDigest === proof.addDigest)
  requireValue(matches.length === 1 && matches[0][1].completion && matches[0][1].sourceEpoch === addition.conv_epoch,
    'Saved addition lacks exact recipient provenance; preserve it for recovery')
  const kid = matches[0][0], recipient = parseGroupGenesisBody(base64UrlDecode(expected.snapshot)).founding_members.find(member => hex(member.key_id) === kid)?.public_key
  requireValue(recipient && hex(keyIDFromPublicKey(recipient)) === kid && (op.recipient === undefined || op.recipient === hex(recipient)),
    'Saved addition recipient differs from its admission proof')
  return { kid, recipient, proof, addition, rekey, rekeyWire }
}

/** Older journals kept the optional challenge only inside the recipient box. */
export function groupAdditionChallenge(identity: Identity, op: Addition, intent = groupAdditionIntent(identity, op)): string | null {
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
