/** Canonical QSP v1.1 rekey selection; validation precedes key unwrapping. */
import { deserializeEnvelope, decryptMessage, type DecryptMessageOptions } from '../message/index.js';
import { GroupState, parseGroupRekeyBody, applyRekey } from '../group/index.js';
import { QSP1Suite } from '../crypto/qsp1.js';
import { base64UrlEncode, uint8ArrayEquals } from '../identity/index.js';
import type { Identity, Conversation, OuterEnvelope } from '../types.js';
const suite=new QSP1Suite();
/** A caller may supply the exact public key of an independently accepted
 * gateway. It authorizes control signing only, never roster/admin membership. */
export type RekeyResolutionOptions=DecryptMessageOptions & {authorizedControlSigner?:Uint8Array};
export type RekeyResolution={envelope:OuterEnvelope;conversation:Conversation|null;excluded:boolean};
export function compareMessageIDs(a:Uint8Array,b:Uint8Array):number {
  if(a.length!==16||b.length!==16)throw new Error('Invalid rekey message ID');
  for(let i=0;i<16;i++)if(a[i]!==b[i])return a[i]-b[i];return 0;
}
/** Roster is the authenticated state at the source transition, never a claimed candidate roster. */
export function resolveRekeyCandidates(identity:Identity,source:Conversation,roster:GroupState,wires:Uint8Array[],options:RekeyResolutionOptions={}):RekeyResolution|null {
  if(source.type!=='group'||!Number.isSafeInteger(source.currentEpoch)||source.currentEpoch<0)throw new Error('Invalid rekey source context');
  if(wires.length>512)throw new Error('Rekey candidate limit exceeded');
  const recipients=roster.listMembers().map(base64UrlEncode).sort();
  if(!recipients.length||recipients.length>128)throw new Error('Invalid rekey roster');
  let winner:{envelope:OuterEnvelope;wrapped:Record<string,Uint8Array>}|undefined;
  for(const wire of wires){
    try {
      if(!wire.length||wire.length>65536)continue;
      const envelope=deserializeEnvelope(wire);
      if(envelope.conv_epoch!==source.currentEpoch||!uint8ArrayEquals(envelope.conv_id,source.id))continue;
      const message=decryptMessage(envelope,source,options);
      if(!message.verified||message.inner.body_type!=='group_rekey'||(!roster.isMember(message.inner.sender_kid)&&(!options.authorizedControlSigner||!uint8ArrayEquals(message.inner.sender_ik_pk,options.authorizedControlSigner))))continue;
      const body=parseGroupRekeyBody(message.inner.body) as ReturnType<typeof parseGroupRekeyBody>&{group_epoch?:number};
      if(body.new_conv_epoch!==source.currentEpoch+1||(body.group_epoch!==undefined&&body.group_epoch!==source.currentEpoch)
        ||!body.wrapped_keys||JSON.stringify(Object.keys(body.wrapped_keys).sort())!==JSON.stringify(recipients)
        ||Object.values(body.wrapped_keys).some(value=>!(value instanceof Uint8Array)))continue;
      if(!winner||compareMessageIDs(envelope.msg_id,winner.envelope.msg_id)<0)winner={envelope,wrapped:body.wrapped_keys};
    }catch{/* Invalid candidate cannot influence the selected message ID. */}
  }
  if(!winner)return null;
  const wrapped=winner.wrapped[base64UrlEncode(identity.keyID)];
  if(!wrapped)return{envelope:winner.envelope,conversation:null,excluded:true};
  // Never select a different winner just because this recipient cannot unwrap it.
  // A malformed canonical wrapping requires authenticated recovery.
  const root=suite.unwrapKeyForRecipient(wrapped,identity.privateKey,identity.keyID,source.id);
  if(root.length!==32)throw new Error('Canonical rekey has an invalid group key');
  const conversation:Conversation={...source,keys:{...source.keys},participants:roster.listMembers()};
  applyRekey(conversation,root,source.currentEpoch+1);
  return{envelope:winner.envelope,conversation,excluded:false};
}
