import XCTest

@testable import Qntm

final class GatewayInteropTests: XCTestCase {
  func testTypeScriptAndPythonGatewaySignatures() throws {
    guard ProcessInfo.processInfo.environment["QNTM_SWIFT_INTEROP"] == "1" else {
      throw XCTSkip("Set QNTM_SWIFT_INTEROP=1 with built TypeScript and Python clients")
    }
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let alice = try Identity(seed: Data(repeating: 1, count: 32))
    let bob = try Identity(seed: Data(repeating: 2, count: 32))
    let gateway = try Identity(seed: Data(repeating: 3, count: 32))
    let context = try GatewayContext(
      conversationID: String(repeating: "ab", count: 16), epoch: 0,
      gatewayPublicKey: gateway.publicKey,
      participants: [alice.keyID.base64URL: alice.publicKey, bob.keyID.base64URL: bob.publicKey],
      floor: 2, rules: [ThresholdRule(m: 2)])
    let request = try Gateway.createRequest(
      identity: alice, context: context, service: "httpbin", endpoint: "/anything", verb: "POST",
      targetURL: "https://httpbin.org/anything",
      payload: .object([("z", .number(2)), ("a", .string("native"))]), requestID: "swift-cross",
      now: 1_800_000_000)
    let proposal = try Governance.createProposal(
      identity: alice, context: context, change: .floor(1), proposalID: "swift-proposal",
      now: 1_800_000_000)
    let approval = try Gateway.createVote(
      identity: bob, context: context, subject: request, approve: true, now: 1_800_000_000)
    let vote = try Gateway.createVote(
      identity: bob, context: context, subject: proposal, approve: true, now: 1_800_000_000)
    let input = GatewayJSON.object([
      ("alice", .string(try alice.serialize().base64URL)),
      ("bob", .string(try bob.serialize().base64URL)),
      ("gateway", .string(gateway.publicKey.base64URL)), ("request", request.json),
      ("proposal", proposal.json), ("approval", approval.json), ("vote", vote.json),
    ])
    func run(_ command: [String], input: Data) throws -> Data {
      let process = Process()
      process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      process.arguments = command
      process.currentDirectoryURL = root
      let stdin = Pipe()
      let stdout = Pipe()
      let stderr = Pipe()
      process.standardInput = stdin
      process.standardOutput = stdout
      process.standardError = stderr
      try process.run()
      stdin.fileHandleForWriting.write(input)
      try stdin.fileHandleForWriting.close()
      let result = stdout.fileHandleForReading.readDataToEndOfFile()
      let errors = stderr.fileHandleForReading.readDataToEndOfFile()
      process.waitUntilExit()
      XCTAssertEqual(process.terminationStatus, 0, String(decoding: errors, as: UTF8.self))
      return result
    }
    let script = #"""
      import * as q from './client/dist/index.js';
      import fs from 'node:fs';
      const data=JSON.parse(fs.readFileSync(0,'utf8')), b=q.base64UrlDecode;
      const a=q.deserializeIdentity(b(data.alice)),bob=q.deserializeIdentity(b(data.bob));
      const c={conversationId:data.request.conv_id,epoch:0,gateway:{kid:q.base64UrlEncode(q.keyIDFromPublicKey(b(data.gateway))),publicKey:data.gateway},participants:{[q.base64UrlEncode(a.keyID)]:q.base64UrlEncode(a.publicKey),[q.base64UrlEncode(bob.keyID)]:q.base64UrlEncode(bob.publicKey)},floor:2,rules:[{service:'*',endpoint:'*',verb:'*',m:2}]};
      q.assertGateRequest(data.request,c);q.assertGatewayProposal(data.proposal,c);
      if(!q.verifyApproval(bob.publicKey,{conv_id:c.conversationId,request_id:data.request.request_id,request_hash:q.hashRequest(q.gateRequestSignable(data.request))},b(data.approval.signature)))throw Error('Swift request vote invalid');
      if(!q.verifyGovApproval(bob.publicKey,{conv_id:c.conversationId,proposal_id:data.proposal.proposal_id,proposal_hash:q.hashProposal(q.gatewayProposalSignable(data.proposal))},b(data.vote.signature)))throw Error('Swift proposal vote invalid');
      const request=q.createGateRequestBody(a,c,{service:'httpbin',endpoint:'/anything',verb:'POST',targetUrl:'https://httpbin.org/anything',payload:{z:2,a:'typescript'},requestId:'ts-cross',now:1800000000000});
      const proposal=q.createGatewayProposalBody(a,c,{proposalType:'floor_change',proposedFloor:1});
      process.stdout.write(JSON.stringify({request,proposal}));
      """#
    let result = try GatewayJSON(
      data: run(["node", "--input-type=module", "-e", script], input: input.encoded()))
    try Gateway.assertRequest(
      GatewayBody(type: "gate.request", json: XCTUnwrap(result["request"])), context: context)
    try Governance.assertProposal(
      GatewayBody(type: "gov.propose", json: XCTUnwrap(result["proposal"])), context: context)
    let python = #"""
      import json,sys,base64,hashlib,datetime
      from qntm.crypto import QSP1Suite
      from qntm.cbor import marshal_canonical
      from qntm.governance import hash_proposal_body
      d=json.load(sys.stdin);r=d['request'];p=d['proposal'];b=lambda x:base64.urlsafe_b64decode(x+'='*((-len(x))%4))
      import cbor2
      a=cbor2.loads(b(d['alice']));bob=cbor2.loads(b(d['bob']));s=QSP1Suite()
      signable={k:r[k] for k in ['gateway_kid','conv_id','request_id','verb','target_endpoint','target_service','target_url','eligible_signer_kids','required_approvals']}
      signable['expires_at_unix']=int(datetime.datetime.fromisoformat(r['expires_at'].replace('Z','+00:00')).timestamp());signable['payload_hash']=hashlib.sha256(json.dumps(r['payload'],separators=(',',':')).encode()).digest()
      assert s.verify(a['public_key'],marshal_canonical(signable),b(r['signature']))
      assert s.verify(bob['public_key'],marshal_canonical({'conv_id':r['conv_id'],'request_id':r['request_id'],'request_hash':hashlib.sha256(marshal_canonical(signable)).digest()}),b(d['approval']['signature']))
      assert s.verify(bob['public_key'],marshal_canonical({'conv_id':p['conv_id'],'proposal_id':p['proposal_id'],'proposal_hash':hash_proposal_body(p)}),b(d['vote']['signature']))
      print('{"verified":true}')
      """#
    let localPython = root.appendingPathComponent("python-dist/.venv/bin/python").path
    let pythonCommand =
      ProcessInfo.processInfo.environment["QNTM_PYTHON"]
      ?? (FileManager.default.isExecutableFile(atPath: localPython) ? localPython : "python3")
    let pyResult = try GatewayJSON(
      data: run([pythonCommand, "-c", python], input: input.encoded()))
    XCTAssertEqual(pyResult["verified"], .bool(true))
  }
}
