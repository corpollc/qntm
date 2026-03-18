import { randomUUID } from 'node:crypto';
import {
  DropboxClient,
  QSP1Suite,
  addParticipant,
  base64UrlDecode,
  base64UrlEncode,
  computePayloadHash,
  createConversation,
  createMessage,
  decryptMessage,
  defaultTTL,
  deriveConversationKeys,
  deserializeEnvelope,
  generateIdentity,
  hashProposal,
  hashRequest,
  inviteFromURL,
  keyIDFromPublicKey,
  parseGroupAddBody,
  parseGroupGenesisBody,
  parseGroupRekeyBody,
  parseGroupRemoveBody,
  processGroupMessage,
  serializeEnvelope,
  signApproval,
  signGovApproval,
  GroupState,
} from '@corpollc/qntm';
import type { Conversation, Identity } from '@corpollc/qntm';

export interface JsonResult {
  ok: boolean;
  kind: string;
  data?: Record<string, unknown>;
  error?: string;
}

interface HistoryEntry {
  message_id: string;
  body_type: string;
  unsafe_body: string;
  sender_kid: string;
  direction: 'incoming' | 'outgoing';
  created_at: string;
}

interface ConversationState {
  id: string;
  name: string;
  conv: Conversation;
  cursor: number;
  history: HistoryEntry[];
  participantKids: string[];
  participantPublicKeys: string[];
  groupState: GroupState;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = parseInt(hex.slice(index, index + 2), 16);
  }
  return bytes;
}

function groupBodyToJson(bodyType: string, bodyBytes: Uint8Array): string | null {
  try {
    let parsed: unknown;
    switch (bodyType) {
      case 'group_genesis':
        parsed = parseGroupGenesisBody(bodyBytes);
        break;
      case 'group_add':
        parsed = parseGroupAddBody(bodyBytes);
        break;
      case 'group_remove':
        parsed = parseGroupRemoveBody(bodyBytes);
        break;
      case 'group_rekey':
        parsed = parseGroupRekeyBody(bodyBytes);
        break;
      default:
        return null;
    }
    return JSON.stringify(parsed, (_key, value) => {
      if (value instanceof Uint8Array || value instanceof ArrayBuffer) {
        return base64UrlEncode(value instanceof Uint8Array ? value : new Uint8Array(value));
      }
      return value;
    });
  } catch {
    return null;
  }
}

function parseConversationOption(args: string[]): string {
  for (let index = 0; index < args.length; index += 1) {
    if ((args[index] === '-c' || args[index] === '--conversation') && args[index + 1]) {
      return args[index + 1];
    }
  }
  throw new Error(`Missing required conversation option in ${args.join(' ')}`);
}

function parseJoinArgs(args: string[]): { token: string; label: string } {
  const dashDashIndex = args.indexOf('--');
  if (dashDashIndex < 0 || !args[dashDashIndex + 1]) {
    throw new Error(`group join requires an invite token: ${args.join(' ')}`);
  }
  let label = '';
  for (let index = 0; index < dashDashIndex; index += 1) {
    if (args[index] === '--name' && args[index + 1]) {
      label = args[index + 1];
      break;
    }
  }
  return { label, token: args[dashDashIndex + 1] };
}

export class TslibAgent {
  readonly name: string;
  private readonly dropbox: DropboxClient;
  private readonly suite = new QSP1Suite();
  private identity: Identity | null = null;
  private readonly conversations = new Map<string, ConversationState>();

  constructor(name: string, relayUrl: string) {
    this.name = name;
    this.dropbox = new DropboxClient(relayUrl);
  }

  async run(args: string[], _extraEnv: Record<string, string> = {}): Promise<JsonResult> {
    if (args.length === 0) {
      throw new Error('Missing command');
    }
    switch (args[0]) {
      case 'identity':
        if (args[1] !== 'generate') {
          throw new Error(`Unsupported identity command: ${args.join(' ')}`);
        }
        return this.generateIdentity();
      case 'group':
        if (args[1] !== 'join') {
          throw new Error(`Unsupported group command: ${args.join(' ')}`);
        }
        {
          const parsed = parseJoinArgs(args.slice(2));
          return this.joinConversation(parsed.token, parsed.label);
        }
      case 'send':
        return this.sendText(args[1], args[2] ?? '');
      case 'recv':
        return this.receiveConversation(args[1]);
      case 'gate-approve':
        return this.gateApprove(args[1], parseConversationOption(args.slice(2)));
      case 'gate-disapprove':
        return this.gateDisapprove(args[1], parseConversationOption(args.slice(2)));
      case 'gov':
        if (args[1] === 'approve') {
          return this.govApprove(args[2], parseConversationOption(args.slice(3)));
        }
        if (args[1] === 'disapprove') {
          return this.govDisapprove(args[2], parseConversationOption(args.slice(3)));
        }
        throw new Error(`Unsupported gov command: ${args.join(' ')}`);
      default:
        throw new Error(`Unsupported ts agent command: ${args.join(' ')}`);
    }
  }

  readIdentity(): Record<string, string> {
    const identity = this.requireIdentity();
    return {
      key_id: bytesToHex(identity.keyID),
      public_key: bytesToHex(identity.publicKey),
    };
  }

  readConversation(convId: string): Record<string, unknown> {
    const state = this.getConversation(convId);
    return {
      id: state.id,
      current_epoch: state.conv.currentEpoch,
      keys: {
        root: bytesToHex(state.conv.keys.root),
        aead_key: bytesToHex(state.conv.keys.aeadKey),
        nonce_key: bytesToHex(state.conv.keys.nonceKey),
      },
      participants: [...state.participantKids],
      participant_public_keys: [...state.participantPublicKeys],
    };
  }

  readHistory(convId: string): Array<Record<string, unknown>> {
    return this.getConversation(convId).history.map((entry) => ({ ...entry }));
  }

  private requireIdentity(): Identity {
    if (!this.identity) {
      throw new Error(`${this.name} has no identity`);
    }
    return this.identity;
  }

  private getConversation(convId: string): ConversationState {
    const state = this.conversations.get(convId.toLowerCase());
    if (!state) {
      throw new Error(`Conversation ${convId} not found for ${this.name}`);
    }
    return state;
  }

  private addHistoryEntry(state: ConversationState, entry: HistoryEntry): void {
    if (state.history.some((existing) => existing.message_id === entry.message_id)) {
      return;
    }
    state.history.push(entry);
  }

  private mergeParticipant(state: ConversationState, publicKey: Uint8Array): void {
    const publicKeyHex = bytesToHex(publicKey);
    const kidHex = bytesToHex(keyIDFromPublicKey(publicKey));
    if (!state.participantPublicKeys.includes(publicKeyHex)) {
      state.participantPublicKeys.push(publicKeyHex);
    }
    if (!state.participantKids.includes(kidHex)) {
      state.participantKids.push(kidHex);
    }
  }

  private syncParticipantsFromGroupState(state: ConversationState): void {
    const kids = state.groupState.listMembers().map((kid) => bytesToHex(kid).toLowerCase());
    if (kids.length > 0) {
      state.participantKids = [...new Set(kids)];
    }
  }

  private applyGroupEvent(state: ConversationState, bodyType: string, bodyBytes: Uint8Array): void {
    try {
      if (bodyType === 'group_rekey') {
        const identity = this.requireIdentity();
        const parsed = parseGroupRekeyBody(bodyBytes);
        const wrappedBlob = parsed.wrapped_keys[base64UrlEncode(identity.keyID)];
        if (!wrappedBlob) {
          return;
        }
        const newGroupKey = this.suite.unwrapKeyForRecipient(
          new Uint8Array(wrappedBlob),
          identity.privateKey,
          identity.keyID,
          state.conv.id,
        );
        const { aeadKey, nonceKey } = this.suite.deriveEpochKeys(newGroupKey, state.conv.id, parsed.new_conv_epoch);
        state.conv.currentEpoch = parsed.new_conv_epoch;
        state.conv.keys.root = newGroupKey;
        state.conv.keys.aeadKey = aeadKey;
        state.conv.keys.nonceKey = nonceKey;
        return;
      }

      processGroupMessage(bodyType, bodyBytes, state.groupState);
      this.syncParticipantsFromGroupState(state);
    } catch {
      // Keep malformed group events in history even if local state cannot apply them.
    }
  }

  private async generateIdentity(): Promise<JsonResult> {
    this.identity = generateIdentity();
    return {
      ok: true,
      kind: 'identity.generate',
      data: this.readIdentity(),
    };
  }

  private async joinConversation(token: string, label: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const invite = inviteFromURL(token.trim());
    const keys = deriveConversationKeys(invite);
    const conv = createConversation(invite, keys);
    addParticipant(conv, identity.publicKey);
    const convId = bytesToHex(invite.conv_id).toLowerCase();

    if (!this.conversations.has(convId)) {
      const participantKids = conv.participants.map((participant) => bytesToHex(participant).toLowerCase());
      const participantPublicKeys = [
        bytesToHex(invite.inviter_ik_pk).toLowerCase(),
        bytesToHex(identity.publicKey).toLowerCase(),
      ];
      this.conversations.set(convId, {
        id: convId,
        name: label.trim() || `Chat ${convId.slice(0, 8)}`,
        conv,
        cursor: 0,
        history: [],
        participantKids,
        participantPublicKeys,
        groupState: new GroupState(),
      });
    }

    return {
      ok: true,
      kind: 'group.join',
      data: { conversation_id: convId },
    };
  }

  private async sendRaw(convId: string, bodyType: string, bodyText: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const state = this.getConversation(convId);
    const bodyBytes = new TextEncoder().encode(bodyText);
    const envelope = createMessage(identity, state.conv, bodyType, bodyBytes, undefined, defaultTTL());
    await this.dropbox.postMessage(state.conv.id, serializeEnvelope(envelope));
    this.addHistoryEntry(state, {
      message_id: bytesToHex(envelope.msg_id),
      body_type: bodyType,
      unsafe_body: bodyText,
      sender_kid: base64UrlEncode(identity.keyID),
      direction: 'outgoing',
      created_at: new Date(envelope.created_ts * 1000).toISOString(),
    });
    return {
      ok: true,
      kind: bodyType,
      data: {
        conversation_id: convId,
        message_id: bytesToHex(envelope.msg_id),
      },
    };
  }

  private async sendText(convId: string, text: string): Promise<JsonResult> {
    return this.sendRaw(convId, 'text', text);
  }

  private async receiveConversation(convId: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const state = this.getConversation(convId);
    const result = await this.dropbox.receiveMessages(state.conv.id, state.cursor, 200);
    let accepted = 0;

    for (const rawEnvelope of result.messages) {
      let envelope;
      try {
        envelope = deserializeEnvelope(rawEnvelope);
      } catch {
        continue;
      }

      let decrypted;
      try {
        decrypted = decryptMessage(envelope, state.conv);
      } catch {
        continue;
      }

      const messageId = bytesToHex(envelope.msg_id);
      if (state.history.some((entry) => entry.message_id === messageId)) {
        continue;
      }

      const senderKid = new Uint8Array(decrypted.inner.sender_kid);
      const senderKidHex = bytesToHex(senderKid).toLowerCase();
      const senderKidB64 = base64UrlEncode(senderKid);
      const bodyType = decrypted.inner.body_type || 'text';
      const bodyBytes = new Uint8Array(decrypted.inner.body);
      const bodyText = groupBodyToJson(bodyType, bodyBytes) ?? new TextDecoder().decode(bodyBytes);

      this.applyGroupEvent(state, bodyType, bodyBytes);
      this.mergeParticipant(state, new Uint8Array(decrypted.inner.sender_ik_pk));

      this.addHistoryEntry(state, {
        message_id: messageId,
        body_type: bodyType,
        unsafe_body: bodyText,
        sender_kid: senderKidB64,
        direction: senderKidHex === bytesToHex(identity.keyID).toLowerCase() ? 'outgoing' : 'incoming',
        created_at: new Date(envelope.created_ts * 1000).toISOString(),
      });
      accepted += 1;
    }

    state.cursor = result.sequence;
    return {
      ok: true,
      kind: 'recv',
      data: { count: accepted, up_to_seq: result.sequence },
    };
  }

  private findGateRequest(state: ConversationState, requestId: string): Record<string, unknown> {
    for (const entry of state.history) {
      if (entry.body_type !== 'gate.request') {
        continue;
      }
      try {
        const parsed = JSON.parse(entry.unsafe_body) as Record<string, unknown>;
        if (parsed.request_id === requestId) {
          return parsed;
        }
      } catch {
        continue;
      }
    }
    throw new Error(`Gate request ${requestId} not found in ${state.id}`);
  }

  private findGovProposal(state: ConversationState, proposalId: string): Record<string, unknown> {
    for (const entry of state.history) {
      if (entry.body_type !== 'gov.propose') {
        continue;
      }
      try {
        const parsed = JSON.parse(entry.unsafe_body) as Record<string, unknown>;
        if (parsed.proposal_id === proposalId) {
          return parsed;
        }
      } catch {
        continue;
      }
    }
    throw new Error(`Governance proposal ${proposalId} not found in ${state.id}`);
  }

  private async gateApprove(requestId: string, convId: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const state = this.getConversation(convId);
    const request = this.findGateRequest(state, requestId);
    const signable = {
      conv_id: String(request.conv_id),
      request_id: requestId,
      verb: String(request.verb),
      target_endpoint: String(request.target_endpoint),
      target_service: String(request.target_service),
      target_url: String(request.target_url),
      expires_at_unix: Math.floor(new Date(String(request.expires_at)).getTime() / 1000),
      payload_hash: computePayloadHash((request.payload as unknown) ?? null),
      eligible_signer_kids: Array.isArray(request.eligible_signer_kids)
        ? request.eligible_signer_kids as string[]
        : [],
      required_approvals: Number(request.required_approvals ?? 1),
    };
    const approval = {
      conv_id: String(request.conv_id),
      request_id: requestId,
      request_hash: hashRequest(signable),
    };
    const body = {
      type: 'gate.approval',
      conv_id: String(request.conv_id),
      request_id: requestId,
      signer_kid: base64UrlEncode(identity.keyID),
      signature: base64UrlEncode(signApproval(identity.privateKey, approval)),
    };
    return this.sendRaw(convId, 'gate.approval', JSON.stringify(body));
  }

  private async gateDisapprove(requestId: string, convId: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const state = this.getConversation(convId);
    const request = this.findGateRequest(state, requestId);
    const body = {
      type: 'gate.disapproval',
      conv_id: String(request.conv_id),
      request_id: requestId,
      signer_kid: base64UrlEncode(identity.keyID),
    };
    return this.sendRaw(convId, 'gate.disapproval', JSON.stringify(body));
  }

  private async govApprove(proposalId: string, convId: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const state = this.getConversation(convId);
    const proposal = this.findGovProposal(state, proposalId);
    const signable = {
      conv_id: String(proposal.conv_id),
      proposal_id: proposalId,
      proposal_type: String(proposal.proposal_type) as 'floor_change' | 'rules_change' | 'member_add' | 'member_remove',
      // Preserve nullable proposal fields exactly as they were serialized.
      // Python CLI proposals currently encode absent branches as `null`, and
      // the worker hashes those raw values when verifying gov.approve.
      proposed_floor: proposal.proposed_floor,
      proposed_rules: proposal.proposed_rules,
      proposed_members: proposal.proposed_members,
      removed_member_kids: proposal.removed_member_kids,
      eligible_signer_kids: Array.isArray(proposal.eligible_signer_kids)
        ? proposal.eligible_signer_kids as string[]
        : [],
      required_approvals: Number(proposal.required_approvals ?? 1),
      expires_at_unix: Math.floor(new Date(String(proposal.expires_at)).getTime() / 1000),
    } as Parameters<typeof hashProposal>[0];
    const approval = {
      conv_id: String(proposal.conv_id),
      proposal_id: proposalId,
      proposal_hash: hashProposal(signable),
    };
    const body = {
      type: 'gov.approve',
      conv_id: String(proposal.conv_id),
      proposal_id: proposalId,
      signer_kid: base64UrlEncode(identity.keyID),
      signature: base64UrlEncode(signGovApproval(identity.privateKey, approval)),
    };
    return this.sendRaw(convId, 'gov.approve', JSON.stringify(body));
  }

  private async govDisapprove(proposalId: string, convId: string): Promise<JsonResult> {
    const identity = this.requireIdentity();
    const state = this.getConversation(convId);
    const proposal = this.findGovProposal(state, proposalId);
    const body = {
      type: 'gov.disapprove',
      conv_id: String(proposal.conv_id),
      proposal_id: proposalId,
      signer_kid: base64UrlEncode(identity.keyID),
    };
    return this.sendRaw(convId, 'gov.disapprove', JSON.stringify(body));
  }
}
