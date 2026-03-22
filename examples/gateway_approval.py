#!/usr/bin/env python3
"""M-of-N API approval flow — the qntm API Gateway.

Demonstrates the killer feature: no single agent can make a consequential
API call alone. Multiple signers must cryptographically approve each request.

Think of it as Gnosis Safe for any API — not just on-chain transactions.

Usage:
    pip install "qntm @ git+https://github.com/corpollc/qntm.git#subdirectory=python-dist"
    python gateway_approval.py
"""

import time
import uuid
import qntm


def main():
    print("=== qntm API Gateway: M-of-N Approval ===\n")

    # ── Step 1: Three signers with cryptographic identities ──
    cfo = qntm.generate_identity()
    cto = qntm.generate_identity()
    ceo = qntm.generate_identity()

    cfo_kid = qntm.key_id_to_string(cfo["keyID"])
    cto_kid = qntm.key_id_to_string(cto["keyID"])
    ceo_kid = qntm.key_id_to_string(ceo["keyID"])

    print(f"CFO: {cfo_kid[:20]}...")
    print(f"CTO: {cto_kid[:20]}...")
    print(f"CEO: {ceo_kid[:20]}...")

    # ── Step 2: Define the API request ──
    conv_id = uuid.uuid4().hex
    request_id = uuid.uuid4().hex
    expires = int(time.time()) + 3600  # 1 hour

    request_params = dict(
        conv_id=conv_id,
        request_id=request_id,
        verb="POST",
        target_endpoint="/v1/charges",
        target_service="stripe",
        target_url="https://api.stripe.com/v1/charges",
        expires_at_unix=expires,
        payload_hash=qntm.compute_payload_hash({"amount": 50000, "currency": "usd"}),
        eligible_signer_kids=[cfo_kid, cto_kid, ceo_kid],
        required_approvals=2,  # 2-of-3 must approve
    )

    print(f"\n--- API Request ---")
    print(f"POST https://api.stripe.com/v1/charges")
    print(f"Amount: $500.00 USD")
    print(f"Required approvals: 2 of 3 signers")
    print(f"Expires: {time.strftime('%H:%M:%S', time.localtime(expires))}")

    # ── Step 3: CFO submits and signs the request ──
    cfo_sig = qntm.sign_request(cfo["privateKey"], **request_params)
    assert qntm.verify_request(cfo["publicKey"], cfo_sig, **request_params)
    print(f"\n✅ CFO signed request ({cfo_sig[:8].hex()}...)")

    # Hash the request for approval signatures
    request_hash = qntm.hash_request(**request_params)

    # ── Step 4: CTO reviews and approves ──
    cto_approval = qntm.sign_approval(
        cto["privateKey"],
        conv_id=conv_id,
        request_id=request_id,
        request_hash=request_hash,
    )
    assert qntm.verify_approval(
        cto["publicKey"],
        cto_approval,
        conv_id=conv_id,
        request_id=request_id,
        request_hash=request_hash,
    )
    print(f"✅ CTO approved ({cto_approval[:8].hex()}...)")

    # ── Step 5: Threshold met — execute ──
    approvals = 2  # CFO (submitter) + CTO (approver)
    required = request_params["required_approvals"]

    print(f"\n--- Approval Status ---")
    print(f"Approvals: {approvals}/{required}")
    print(f"Threshold met: {approvals >= required}")

    if approvals >= required:
        print(f"\n🚀 Gateway would execute: POST /v1/charges")
        print(f"   API key decrypted and injected (never visible to signers)")
        print(f"   Response posted back to encrypted conversation")

    # ── Step 6: Show what a single compromised agent CAN'T do ──
    print(f"\n--- Security Properties ---")
    print(f"• No single agent can execute the API call alone")
    print(f"• API keys are encrypted — only the gateway can decrypt them")
    print(f"• All approvals are cryptographically signed (Ed25519)")
    print(f"• The full audit trail lives in the encrypted conversation")
    print(f"• A prompt-injected agent needs {required-1} more compromised signers")

    print(f"\n✅ M-of-N approval verified!")
    print(f"   This is what makes qntm different from every other agent messaging protocol.")
    print(f"\nDocs: https://github.com/corpollc/qntm/blob/main/docs/api-gateway.md")


if __name__ == "__main__":
    main()
