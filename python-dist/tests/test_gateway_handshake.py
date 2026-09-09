import hashlib
import json

from qntm.gate import open_secret, sign_request, verify_request
from qntm.gateway_handshake import create_gateway_invite_body, seal_gateway_bootstrap, matches_gateway_acceptance
from qntm.identity import generate_identity, base64url_encode, base64url_decode


def test_sealed_access_and_acceptance_bind_the_exact_invitation():
    alice, gateway = generate_identity(), generate_identity()
    invitation = {"invitation_id": "ab" * 16, "inviter_public_key": base64url_encode(alice["publicKey"]),
                  "gateway_public_key": base64url_encode(gateway["publicKey"]), "gateway_kid": base64url_encode(gateway["keyID"]), "expires_at": 123456}
    conversation = {"id": bytes([8]) * 16, "keys": {"aeadKey": bytes([1]) * 32, "nonceKey": bytes([2]) * 32}, "currentEpoch": 3}
    body = create_gateway_invite_body(invitation, conversation, {base64url_encode(alice["keyID"]): base64url_encode(alice["publicKey"])}, 1)
    text = json.dumps(body, separators=(",", ":"))
    request = seal_gateway_bootstrap(alice, invitation, conversation, "ef" * 16, 7)
    plaintext = json.loads(open_secret(gateway["privateKey"], alice["publicKey"], base64url_decode(request["sealed"])))
    assert plaintext["invitation_seq"] == 7
    assert plaintext["conv_epoch"] == 3
    assert plaintext["conv_aead_key"] == base64url_encode(bytes([1]) * 32)
    acceptance = {"type": "gate.accept", "invitation_id": invitation["invitation_id"], "invitation_msg_id": "ef" * 16,
                  "invitation_hash": hashlib.sha256(text.encode()).hexdigest(), "conv_id": conversation["id"].hex(), "conv_epoch": 3,
                  "gateway_public_key": invitation["gateway_public_key"], "gateway_kid": invitation["gateway_kid"]}
    assert matches_gateway_acceptance(acceptance, invitation["gateway_kid"], "ef" * 16, text)
    assert not matches_gateway_acceptance(acceptance, base64url_encode(alice["keyID"]), "ef" * 16, text)
    assert not matches_gateway_acceptance(acceptance, invitation["gateway_kid"], "ef" * 16, text + " ")
    assert not matches_gateway_acceptance({**acceptance, "conv_epoch": 4}, invitation["gateway_kid"], "ef" * 16, text)


def test_request_signature_cannot_be_retargeted_to_a_second_gateway():
    alice = generate_identity()
    request = dict(conv_id="ab" * 16, request_id="request", verb="POST", target_endpoint="/counter", target_service="counter",
                   target_url="https://example.test/counter", expires_at_unix=12345, payload_hash=hashlib.sha256(b"").digest(),
                   eligible_signer_kids=[base64url_encode(alice["keyID"])], required_approvals=1, gateway_kid="gateway-a")
    signature = sign_request(alice["privateKey"], **request)
    assert verify_request(alice["publicKey"], signature, **request)
    assert not verify_request(alice["publicKey"], signature, **{**request, "gateway_kid": "gateway-b"})
