"""Fresh Python peer for the TypeScript welcome interoperability test.

All keys are generated test identities supplied over stdin or created here.
This helper never reads a user profile or contacts a production relay.
"""
import json
import sys

from qntm import (
    QSP1Suite, GroupState, generate_identity, create_invite, create_conversation,
    derive_conversation_keys, create_group_genesis_body, parse_group_genesis_body,
    apply_rekey, create_message, decrypt_message, marshal_canonical, unmarshal,
    prepare_group_addition, open_group_welcome, create_group_link, parse_group_link,
)

request = json.load(sys.stdin)
suite = QSP1Suite()

if request["action"] == "prepare":
    owner, peer, late = generate_identity(), generate_identity(), generate_identity()
    invite = create_invite(owner, "group")
    source = create_conversation(invite, derive_conversation_keys(invite))
    state = GroupState()
    state.apply_genesis(parse_group_genesis_body(create_group_genesis_body("Interop colleagues", "Ω private roster", owner, [peer["publicKey"]])))
    source["participants"] = state.list_members()
    if request["epoch"]:
        apply_rekey(source, suite.generate_group_key(), request["epoch"])
    before = create_message(owner, source, "text", b"before addition")
    addition = prepare_group_addition(owner, source, state, [late["publicKey"]])
    after = create_message(owner, addition["conversation"], "text", b"after addition")
    print(json.dumps({
        "owner": {key: value.hex() for key, value in owner.items()},
        "late": {key: value.hex() for key, value in late.items()},
        "conversation_id": source["id"].hex(),
        "welcome": marshal_canonical(addition["welcomes"][0]).hex(),
        "before": marshal_canonical(before).hex(), "after": marshal_canonical(after).hex(),
        "root": addition["conversation"]["keys"]["root"].hex(),
        "addition_id": addition["addition"]["msg_id"].hex(), "rekey_id": addition["rekey"]["msg_id"].hex(),
        "link": create_group_link(source["id"], owner["publicKey"], "https://inbox.qntm.corpo.llc"),
    }))
elif request["action"] == "open":
    identity = {key: bytes.fromhex(value) for key, value in request["identity"].items()}
    locator = parse_group_link(request["link"])
    assert locator["conversation_id"].hex() == request["conversation_id"]
    assert locator["inviter_public_key"].hex() == request["inviter_public_key"]
    joined = open_group_welcome(identity, bytes.fromhex(request["welcome"]),
                                conversation_id=locator["conversation_id"],
                                inviter_public_key=locator["inviter_public_key"])
    old_decrypts = False
    try:
        decrypt_message(unmarshal(bytes.fromhex(request["before"])), joined["conversation"])
        old_decrypts = True
    except Exception:
        pass
    after = decrypt_message(unmarshal(bytes.fromhex(request["after"])), joined["conversation"])
    reply = create_message(identity, joined["conversation"], "text", b"Python recipient reply")
    print(json.dumps({"old_decrypts": old_decrypts, "after": after["inner"]["body"].decode(),
                      "epoch": joined["conversation"]["currentEpoch"], "reply": marshal_canonical(reply).hex()}))
else:
    raise ValueError("Unknown test operation")
