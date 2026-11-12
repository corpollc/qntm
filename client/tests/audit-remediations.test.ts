import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  KNOWN_SERVICE_ORIGINS,
  GatewayValidationError,
  GroupState,
  QSP1Suite,
  RekeyUnwrapError,
  addParticipant,
  applyAuthenticatedGroupControl,
  base64UrlEncode,
  createConversation,
  createGateRequestBody,
  createGateSecretBody,
  createGatewayInviteBody,
  createGatewaySession,
  createGroupAddBody,
  createGroupGenesisBody,
  createGroupRekeyBody,
  createInvite,
  createMessage,
  decryptMessage,
  deriveConversationKeys,
  deserializeEnvelope,
  gatewayInvitationHash,
  generateIdentity,
  lookupThreshold,
  lookupThresholdForTarget,
  marshalCanonical,
  normalizeAllowedOrigin,
  normalizeAllowedOriginsList,
  parseAttachment,
  parseGatewayBody,
  pathnameMatchesEndpoint,
  prepareAttachment,
  receiveConversationEvent,
  resolveRecipe,
  resolveRekeyCandidates,
  resolveServiceOrigins,
  sanitizeAttachmentFilename,
  serializeEnvelope,
  sessionGatewayContext,
  unmarshalCanonical,
  validateEnvelope,
  validateGatewayTargetUrl,
  validateInnerPayload,
} from '../src/index.js';
import { CharterRegistryClient, charterKey, createCharter, parseCharterJson } from '../src/charter/index.js';
import type { OuterEnvelope, InnerPayload, Recipe, ThresholdRule } from '../src/index.js';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const encode = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('P0-1: strict TypeScript wire schema validation', () => {
  it('rejects non-Uint8Array and wrong-length fields in validateEnvelope', () => {
    const alice = generateIdentity();
    const invite = createInvite(alice, 'direct');
    const conv = createConversation(invite, deriveConversationKeys(invite));
    const valid = createMessage(alice, conv, 'text', new TextEncoder().encode('ok'));
    expect(() => validateEnvelope(valid)).not.toThrow();

    expect(() => validateEnvelope({ ...valid, msg_id: 1_000_000_000 as unknown as Uint8Array })).toThrow('invalid message ID');
    expect(() => validateEnvelope({ ...valid, msg_id: new Uint8Array(15) })).toThrow('invalid message ID');
    expect(() => validateEnvelope({ ...valid, conv_id: 'abcd' as unknown as Uint8Array })).toThrow('invalid conversation ID');
    expect(() => validateEnvelope({ ...valid, conv_id: new Uint8Array(17) })).toThrow('invalid conversation ID');
    expect(() => validateEnvelope({ ...valid, ciphertext: 1_000_000_000 as unknown as Uint8Array })).toThrow('ciphertext');
    expect(() => validateEnvelope({ ...valid, ciphertext: new Uint8Array(65537) })).toThrow('ciphertext');
    expect(() => validateEnvelope({ ...valid, aad_hash: 1_000_000_000 as unknown as Uint8Array })).toThrow('aad_hash');
    expect(() => validateEnvelope({ ...valid, aad_hash: new Uint8Array(31) })).toThrow('aad_hash');
    expect(() => validateEnvelope({ ...valid, conv_epoch: -1 })).toThrow('invalid conversation epoch');
    expect(() => validateEnvelope({ ...valid, conv_epoch: 1.5 })).toThrow('invalid conversation epoch');
  });

  it('rejects non-Uint8Array and wrong-length fields in validateInnerPayload and session/control guards', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const invite = createInvite(alice, 'group');
    const conv = createConversation(invite, deriveConversationKeys(invite));
    addParticipant(conv, bob.publicKey);
    const env = createMessage(alice, conv, 'text', new TextEncoder().encode('hello'));
    const msg = decryptMessage(env, conv);
    expect(() => validateInnerPayload(msg.inner)).not.toThrow();

    expect(() => validateInnerPayload({ ...msg.inner, sender_ik_pk: new Uint8Array(31) })).toThrow('sender public key');
    expect(() => validateInnerPayload({ ...msg.inner, sender_kid: new Uint8Array(15) })).toThrow('sender key ID');
    expect(() => validateInnerPayload({ ...msg.inner, signature: new Uint8Array(63) })).toThrow('signature');
    expect(() => validateInnerPayload({ ...msg.inner, body: 1_000_000_000 as unknown as Uint8Array })).toThrow('message body');
    expect(() => validateInnerPayload({ ...msg.inner, body_type: 123 as unknown as string })).toThrow('body type');
    expect(() => validateInnerPayload({ ...msg.inner, msg_id: new Uint8Array(8) } as InnerPayload)).toThrow('inner message ID');

    const malformedControlMsg = {
      ...msg,
      inner: { ...msg.inner, body_type: 'group_genesis', body: 1_000_000_000 as unknown as Uint8Array },
    };
    expect(() =>
      applyAuthenticatedGroupControl(
        env,
        malformedControlMsg,
        conv,
        alice,
        { creator: base64UrlEncode(alice.keyID), needsRekey: false, removed: false },
        { [base64UrlEncode(alice.keyID)]: base64UrlEncode(alice.publicKey) },
      ),
    ).toThrow('Invalid group control body');

    // CBOR envelope carrying non-bytes msg_id fails closed on deserializeEnvelope
    const badWire = marshalCanonical({
      v: 1,
      suite: 'QSP-1',
      conv_id: conv.id,
      msg_id: 1_000_000_000,
      created_ts: env.created_ts,
      expiry_ts: env.expiry_ts,
      conv_epoch: 0,
      ciphertext: env.ciphertext,
    });
    expect(() => deserializeEnvelope(badWire)).toThrow('invalid message ID');
  });
});

describe('P0-2, P0-2b & P0-2c: allowed_origins, SSRF defense, endpoint binding & verb case', () => {
  it('implements KNOWN_SERVICE_ORIGINS and resolveServiceOrigins per cross-language contract', () => {
    expect(KNOWN_SERVICE_ORIGINS).toEqual({
      github: ['https://api.github.com'],
      openai: ['https://api.openai.com'],
      anthropic: ['https://api.anthropic.com'],
      gemini: ['https://generativelanguage.googleapis.com'],
      stripe: ['https://api.stripe.com'],
      hackernews: ['https://hacker-news.firebaseio.com'],
      httpbin: ['https://httpbin.org'],
      dadjokes: ['https://icanhazdadjoke.com'],
      trivia: ['https://opentdb.com'],
      dogs: ['https://dog.ceo'],
      fun: ['http://localhost:9090'],
    });

    expect(resolveServiceOrigins('Stripe')).toEqual(['https://api.stripe.com']);
    expect(resolveServiceOrigins('fun')).toEqual(['http://localhost:9090']);
    expect(resolveServiceOrigins('api.custom.example')).toEqual(['https://api.custom.example']);
    expect(resolveServiceOrigins('localhost:8787')).toEqual(['http://localhost:8787']);
    expect(resolveServiceOrigins('127.0.0.1:8787')).toEqual(['http://127.0.0.1:8787']);
    expect(resolveServiceOrigins('[::1]:8787')).toEqual(['http://[::1]:8787']);
    expect(resolveServiceOrigins('https://api.custom.example/')).toEqual(['https://api.custom.example']);
    expect(resolveServiceOrigins('custom', ['https://a.example', 'https://a.example/', 'https://b.example'])).toEqual([
      'https://a.example',
      'https://b.example',
    ]);

    expect(() => resolveServiceOrigins('unknownbare')).toThrow(GatewayValidationError);
    expect(() => resolveServiceOrigins('unknownbare')).toThrow(
      'Unknown service "unknownbare": specify an API hostname (e.g. api.example.com) or pass allowedOrigins',
    );
  });

  it('enforces origin canonicalization and blocks HTTP downgrades & private/metadata hosts', () => {
    expect(() => normalizeAllowedOrigin('http://api.stripe.com')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://api.stripe.com/v1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://api.stripe.com?x=1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://api.stripe.com#frag')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://user:pass@api.stripe.com')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://127.0.0.1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://169.254.169.254')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://10.0.0.1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://172.16.0.1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://192.168.1.1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://100.64.0.1')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://[::1]')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://[fc00::1]')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOrigin('https://[fe80::1]')).toThrow(GatewayValidationError);
    expect(() => normalizeAllowedOriginsList([])).toThrow(GatewayValidationError);
    expect(() =>
      normalizeAllowedOriginsList(Array.from({ length: 17 }, (_, i) => `https://api${i}.example.com`)),
    ).toThrow(GatewayValidationError);
  });

  it('rejects SSRF, dot-segments, and unbound target_endpoint on gate.request', () => {
    expect(() => validateGatewayTargetUrl('https://169.254.169.254/latest/meta-data/')).toThrow(GatewayValidationError);
    expect(() => validateGatewayTargetUrl('https://api.stripe.com/v1/../charges')).toThrow(GatewayValidationError);
    expect(() => validateGatewayTargetUrl('https://api.stripe.com/v1/%2e%2e/charges')).toThrow(GatewayValidationError);
    expect(() => validateGatewayTargetUrl('https://api.stripe.com/./v1/charges')).toThrow(GatewayValidationError);
    expect(() => validateGatewayTargetUrl('http://api.stripe.com/v1/charges')).toThrow(GatewayValidationError);
    expect(validateGatewayTargetUrl('http://localhost:9090/joke').origin).toBe('http://localhost:9090');

    expect(pathnameMatchesEndpoint('/v1/charges', '/v1/charges')).toBe(true);
    expect(pathnameMatchesEndpoint('/v0/topstories.json', '/topstories.json')).toBe(true);
    expect(pathnameMatchesEndpoint('/v1/charges', '/safe')).toBe(false);
    expect(pathnameMatchesEndpoint('/v1/charges/safe', '/safe')).toBe(false);

    const alice = generateIdentity();
    const gateway = generateIdentity();
    const context = {
      conversationId: 'ab'.repeat(16),
      epoch: 0,
      gateway: { kid: base64UrlEncode(gateway.keyID), publicKey: base64UrlEncode(gateway.publicKey) },
      participants: { [base64UrlEncode(alice.keyID)]: base64UrlEncode(alice.publicKey) },
      floor: 1,
      rules: [{ service: 'stripe', endpoint: '/v1/charges', verb: 'POST', m: 1 }],
    };

    expect(() =>
      createGateRequestBody(alice, context, {
        service: 'stripe',
        endpoint: '/safe',
        verb: 'POST',
        targetUrl: 'https://api.stripe.com/v1/charges',
      }),
    ).toThrow('Target endpoint does not match target URL path');

    expect(() =>
      createGateRequestBody(alice, context, {
        service: 'stripe',
        endpoint: '/v1/charges',
        verb: 'post',
        targetUrl: 'https://api.stripe.com/v1/charges',
      }),
    ).toThrow('Invalid verb');

    const secret = createGateSecretBody(alice, context, { service: 'stripe', value: 'sk_test_123' });
    expect(secret.allowed_origins).toEqual(['https://api.stripe.com']);
    const missingOrigins = { ...secret } as Record<string, unknown>;
    delete missingOrigins.allowed_origins;
    expect(() => parseGatewayBody('gate.secret', JSON.stringify(missingOrigins))).toThrow('allowed_origins');
  });

  it('matches verbs case-insensitively, supports {param} templates, and blocks prefix-stripping threshold bypass', () => {
    const rules: ThresholdRule[] = [
      { service: '*', endpoint: '*', verb: '*', m: 1 },
      { service: 'hackernews', endpoint: '/item/{id}.json', verb: 'GET', m: 2 },
      { service: 'hackernews', endpoint: '/item/0.json', verb: 'GET', m: 3 },
      { service: 'stripe', endpoint: '/v1/charges', verb: 'POST', m: 3 },
    ];

    // Case-insensitive verb matching
    expect(lookupThreshold(rules, 'stripe', '/v1/charges', 'post')?.m).toBe(3);
    expect(lookupThreshold(rules, 'stripe', '/v1/charges', 'POST')?.m).toBe(3);

    // Parameterized endpoint template + exact override specificity
    expect(lookupThreshold(rules, 'hackernews', '/item/12345.json', 'GET')?.m).toBe(2);
    expect(lookupThreshold(rules, 'hackernews', '/item/0.json', 'GET')?.m).toBe(3);

    // Prefix-stripping /charges against /v1/charges still enforces m=3
    expect(
      lookupThresholdForTarget(rules, 'stripe', '/charges', 'POST', 'https://api.stripe.com/v1/charges')?.m,
    ).toBe(3);

    // Legitimate prefix /v0/topstories.json with specific /topstories.json read rule keeps m=1
    const readExemptionRules: ThresholdRule[] = [
      { service: '*', endpoint: '*', verb: '*', m: 3 },
      { service: 'hackernews', endpoint: '/topstories.json', verb: 'GET', m: 1 },
    ];
    expect(
      lookupThresholdForTarget(
        readExemptionRules,
        'hackernews',
        '/topstories.json',
        'GET',
        'https://hacker-news.firebaseio.com/v0/topstories.json',
      )?.m,
    ).toBe(1);
  });
});

describe('P1-1, P1-2b & P3-2: group authority, creator protection, rekey unwrap quarantine & creator invite option', () => {
  it('rejects non-admin group promotion, preserves secondary admin roster across gate.accept, and protects creator on gov.applied', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const carol = generateIdentity();
    const gateway = generateIdentity();

    const invite = createInvite(alice, 'group');
    let conv = createConversation(invite, deriveConversationKeys(invite));
    addParticipant(conv, bob.publicKey);
    addParticipant(conv, carol.publicKey);
    let state = createGatewaySession(conv, [alice.publicKey, bob.publicKey, carol.publicKey]);

    const participants = Object.fromEntries(
      [alice, bob, carol].map(i => [base64UrlEncode(i.keyID), base64UrlEncode(i.publicKey)]),
    );
    const invitation = {
      invitation_id: '11'.repeat(16),
      inviter_public_key: base64UrlEncode(bob.publicKey),
      gateway_public_key: base64UrlEncode(gateway.publicKey),
      gateway_kid: base64UrlEncode(gateway.keyID),
      expires_at: Math.floor(Date.now() / 1000) + 600,
    };
    const bobInviteBody = createGatewayInviteBody(invitation, conv, participants, 2, {
      groupCreatorKid: alice.keyID,
    });

    // Non-admin Bob cannot promote a gateway in a group conversation
    const bobPromoteEnv = createMessage(bob, conv, 'gate.promote', encode(bobInviteBody));
    expect(() => receiveConversationEvent(bobPromoteEnv, conv, alice, state)).toThrow(
      'Only a group administrator may promote a gateway',
    );

    // Establish genesis with Bob promoted to secondary admin
    const genesisBody = marshalCanonical({
      created_at: Math.floor(Date.now() / 1000),
      description: '',
      group_name: 'Admins',
      founding_members: [
        { key_id: alice.keyID, public_key: alice.publicKey, role: 'admin', added_at: 1, added_by: alice.keyID },
        { key_id: bob.keyID, public_key: bob.publicKey, role: 'admin', added_at: 1, added_by: alice.keyID },
        { key_id: carol.keyID, public_key: carol.publicKey, role: 'member', added_at: 1, added_by: alice.keyID },
      ],
    });
    const genRes = receiveConversationEvent(createMessage(alice, conv, 'group_genesis', genesisBody), conv, alice, state);
    conv = genRes.conversation;
    state = genRes.state;
    expect(state.groupControl?.roster).toBeDefined();

    // Carol (ordinary member) still cannot promote
    const carolInviteBody = createGatewayInviteBody(
      { ...invitation, inviter_public_key: base64UrlEncode(carol.publicKey) },
      conv,
      participants,
      2,
      { groupCreatorKid: alice.keyID },
    );
    expect(() =>
      receiveConversationEvent(createMessage(carol, conv, 'gate.promote', encode(carolInviteBody)), conv, alice, state),
    ).toThrow('Only a group administrator may promote a gateway');

    // Secondary admin Bob CAN promote, and gate.accept preserves state.groupControl.roster
    const bobPromote2 = createMessage(bob, conv, 'gate.promote', encode(bobInviteBody));
    const promRes = receiveConversationEvent(bobPromote2, conv, alice, state);
    conv = promRes.conversation;
    state = promRes.state;

    const acceptBody = {
      type: 'gate.accept' as const,
      invitation_id: invitation.invitation_id,
      invitation_msg_id: hex(bobPromote2.msg_id),
      invitation_hash: gatewayInvitationHash(JSON.stringify(bobInviteBody)),
      conv_id: hex(conv.id),
      conv_epoch: conv.currentEpoch,
      gateway_kid: invitation.gateway_kid,
      gateway_public_key: invitation.gateway_public_key,
    };
    const accRes = receiveConversationEvent(createMessage(gateway, conv, 'gate.accept', encode(acceptBody)), conv, alice, state);
    conv = accRes.conversation;
    state = accRes.state;
    expect(state.groupControl?.roster).toBeDefined();
    expect(state.gateway?.membershipAuthority).toBe(true);

    // Compromised gateway cannot remove group creator via gov.applied
    const removeCreatorApplied = {
      type: 'gov.applied',
      proposal_id: 'prop-1',
      proposal_type: 'member_remove',
      applied_at: new Date().toISOString(),
      removed_member_kids: [base64UrlEncode(alice.keyID)],
    };
    expect(() =>
      receiveConversationEvent(createMessage(gateway, conv, 'gov.applied', encode(removeCreatorApplied)), conv, alice, state),
    ).toThrow('Gateway cannot remove the group creator');

    // Legacy checkpoint with membershipAuthority: false cannot mutate group participants via gov.applied
    const undelegatedState = structuredClone(state);
    undelegatedState.gateway!.membershipAuthority = false;
    const removeCarolApplied = {
      type: 'gov.applied',
      proposal_id: 'prop-2',
      proposal_type: 'member_remove',
      applied_at: new Date().toISOString(),
      removed_member_kids: [base64UrlEncode(carol.keyID)],
    };
    expect(() =>
      receiveConversationEvent(createMessage(gateway, conv, 'gov.applied', encode(removeCarolApplied)), conv, alice, undelegatedState),
    ).toThrow('Gateway does not have group membership authority');
  });

  it('P3-2: derives group_creator_kid from GroupState / explicit option rather than participants[0]', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const gateway = generateIdentity();
    const invite = createInvite(alice, 'group');
    const conv = createConversation(invite, deriveConversationKeys(invite));
    // Reorder conv.participants so bob is at index 0 while alice is actual creator in GroupState
    conv.participants = [bob.keyID, alice.keyID];
    const groupState = new GroupState();
    groupState.applyGenesis({
      group_name: 'G',
      description: '',
      created_at: 1,
      founding_members: [
        { key_id: alice.keyID, public_key: alice.publicKey, role: 'admin', added_at: 1, added_by: alice.keyID },
        { key_id: bob.keyID, public_key: bob.publicKey, role: 'member', added_at: 1, added_by: alice.keyID },
      ],
    });
    const participants = {
      [base64UrlEncode(bob.keyID)]: base64UrlEncode(bob.publicKey),
      [base64UrlEncode(alice.keyID)]: base64UrlEncode(alice.publicKey),
    };
    const invitation = {
      invitation_id: '22'.repeat(16),
      inviter_public_key: base64UrlEncode(alice.publicKey),
      gateway_public_key: base64UrlEncode(gateway.publicKey),
      gateway_kid: base64UrlEncode(gateway.keyID),
      expires_at: Math.floor(Date.now() / 1000) + 600,
    };
    const body = createGatewayInviteBody(invitation, conv, participants, 1, groupState);
    expect(body.group_creator_kid).toBe(base64UrlEncode(alice.keyID));
  });

  it('P1-2b: throws RekeyUnwrapError instead of silently ignoring corrupt single-envelope group_rekey', () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const invite = createInvite(alice, 'group');
    let conv = createConversation(invite, deriveConversationKeys(invite));
    addParticipant(conv, bob.publicKey);

    const roster = new GroupState();
    const genesisBytes = createGroupGenesisBody('SplitTest', '', alice, [bob.publicKey]);
    let state = createGatewaySession(conv, [alice.publicKey, bob.publicKey]);
    const genEvent = receiveConversationEvent(createMessage(alice, conv, 'group_genesis', genesisBytes), conv, bob, state);
    conv = genEvent.conversation;
    state = genEvent.state;
    roster.applyGenesis({
      group_name: 'SplitTest',
      description: '',
      created_at: 1,
      founding_members: [
        { key_id: alice.keyID, public_key: alice.publicKey, role: 'admin', added_at: 1, added_by: alice.keyID },
        { key_id: bob.keyID, public_key: bob.publicKey, role: 'member', added_at: 1, added_by: alice.keyID },
      ],
    });

    // Craft a valid group_rekey signed by Alice where Bob's wrapped key tag is corrupted
    const rootK1 = new QSP1Suite().generateGroupKey();
    const rawRekey = unmarshalCanonical<{ new_conv_epoch: number; wrapped_keys: Record<string, Uint8Array> }>(
      createGroupRekeyBody(rootK1, 1, [
        { kid: alice.keyID, publicKey: alice.publicKey },
        { kid: bob.keyID, publicKey: bob.publicKey },
      ], conv.id),
    );
    const bobKidStr = base64UrlEncode(bob.keyID);
    const corruptedWrap = new Uint8Array(rawRekey.wrapped_keys[bobKidStr]);
    corruptedWrap[corruptedWrap.length - 1] ^= 0xff;
    rawRekey.wrapped_keys[bobKidStr] = corruptedWrap;

    const poisonedEnv = createMessage(alice, conv, 'group_rekey', marshalCanonical(rawRekey));
    expect(() => resolveRekeyCandidates(bob, conv, roster, [serializeEnvelope(poisonedEnv)])).toThrow(RekeyUnwrapError);

    let caught: unknown;
    try {
      receiveConversationEvent(poisonedEnv, conv, bob, state);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(RekeyUnwrapError);
    const unwrapErr = caught as RekeyUnwrapError;
    expect(unwrapErr.recoveryRequired).toBe(true);
    const quarantined = unwrapErr.quarantinedState as typeof state;
    expect(quarantined.recoveryRequired).toBe(true);
    expect(() => sessionGatewayContext(quarantined)).toThrow('recovery required');
  });
});

describe('P1-6, P2-4b, P2-5 & P3-1: recipes, charter bounds, canonical CBOR, and attachment filenames', () => {
  it('P1-6: URL-encodes path and query parameters in resolveRecipe and rejects dot-segments', () => {
    const recipe: Recipe = {
      name: 'search',
      description: 'Search',
      service: 'github',
      verb: 'GET',
      endpoint: '/repos/{owner}/{repo}/issues',
      target_url: 'https://api.github.com/repos/{owner}/{repo}/issues',
      risk_tier: 'read',
      threshold: 1,
      path_params: [
        { name: 'owner', description: '', required: true, type: 'string' },
        { name: 'repo', description: '', required: true, type: 'string' },
      ],
      query_params: [
        { name: 'q', description: '', required: false, type: 'string' },
      ],
    };

    const encoded = resolveRecipe(recipe, {
      owner: 'my org',
      repo: 'a?b#c/d',
      q: 'foo=1&bar=2#frag',
    });
    expect(encoded.endpoint).toBe('/repos/my%20org/a%3Fb%23c%2Fd/issues');
    expect(encoded.target_url).toBe(
      'https://api.github.com/repos/my%20org/a%3Fb%23c%2Fd/issues?q=foo%3D1%26bar%3D2%23frag',
    );

    expect(() => resolveRecipe(recipe, { owner: '..', repo: 'ok' })).toThrow('invalid path parameter');
    expect(() => resolveRecipe(recipe, { owner: '.', repo: 'ok' })).toThrow('invalid path parameter');
    expect(() => resolveRecipe(recipe, { owner: '%2e%2e', repo: 'ok' })).toThrow('invalid path parameter');
    expect(() => resolveRecipe(recipe, { owner: '../admin', repo: 'ok' })).toThrow('invalid path parameter');
  });

  it('P2-4b: enforces 32 MiB streaming cap and safe JSON integers on CharterRegistryClient', async () => {
    expect(() => parseCharterJson('{"seq":9007199254740992}')).toThrow('Invalid or duplicate-key JSON');
    expect(() => parseCharterJson('{"seq":-9007199254740992}')).toThrow('Invalid or duplicate-key JSON');
    expect(parseCharterJson('{"seq":9007199254740991}')).toEqual({ seq: 9007199254740991 });

    const agent = generateIdentity();
    expect(() =>
      createCharter({
        registry: 'charter.example.test',
        agent,
        governance: null,
        extensions: { unsafe: { n: 9007199254740992 } },
      }),
    ).toThrow('safe integer bounds');

    const registrar = generateIdentity();
    const cancel = vi.fn(async () => undefined);
    vi.stubGlobal('fetch', vi.fn(async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(4 * 1024 * 1024));
      },
      cancel,
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })));

    const client = new CharterRegistryClient('https://charter.example.test', {
      registry: 'charter.example.test',
      registrar: charterKey(registrar.publicKey),
    });
    await expect(client.heads()).rejects.toThrow('Charter response exceeds 32 MiB limit');
    expect(cancel).toHaveBeenCalled();
  });

  it('P2-5: sorts canonical CBOR map keys by UTF-8 byte length then unsigned bytes ("aa" before "é")', () => {
    // "b"  -> UTF-8 [0x62]       (1 byte)
    // "aa" -> UTF-8 [0x61, 0x61] (2 bytes)
    // "é"  -> UTF-8 [0xc3, 0xa9] (2 bytes, despite UTF-16 length === 1!)
    // "aaa"-> UTF-8 [0x61,0x61,0x61] (3 bytes)
    const encoded = marshalCanonical({ 'é': 1, aa: 2, aaa: 3, b: 4 });
    // Expected CBOR: map(4): "b":4, "aa":2, "é":1, "aaa":3
    expect(Array.from(encoded)).toEqual([
      0xa4,
      0x61, 0x62, 0x04,
      0x62, 0x61, 0x61, 0x02,
      0x62, 0xc3, 0xa9, 0x01,
      0x63, 0x61, 0x61, 0x61, 0x03,
    ]);
  });

  it('P3-1: strips bidi/Cf overrides, C1 controls, colons, and prefixes Windows device basenames on attachments', () => {
    expect(sanitizeAttachmentFilename('invoice\u202egnp.exe')).toBe('invoicegnp.exe');
    expect(sanitizeAttachmentFilename('a:b\u0085c.txt')).toBe('abc.txt');
    expect(sanitizeAttachmentFilename('CON')).toBe('_CON');
    expect(sanitizeAttachmentFilename('nul.txt')).toBe('_nul.txt');
    expect(sanitizeAttachmentFilename('com1.tar.gz')).toBe('_com1.tar.gz');
    expect(sanitizeAttachmentFilename('LPT9')).toBe('_LPT9');
    expect(() => sanitizeAttachmentFilename('\u202e\u200f:')).toThrow('Invalid attachment filename');

    const alice = generateIdentity();
    const invite = createInvite(alice, 'direct');
    const conv = createConversation(invite, deriveConversationKeys(invite));
    const prepared = prepareAttachment(alice, conv, new Uint8Array([1, 2, 3]), 'CON.txt\u202e', 'text/plain');
    expect(prepared.descriptor.name).toBe('_CON.txt');
    const parsed = parseAttachment(prepared.body, {
      conversationId: conv.id,
      epoch: conv.currentEpoch,
      senderPublicKey: alice.publicKey,
    });
    expect(parsed.name).toBe('_CON.txt');
  });
});
