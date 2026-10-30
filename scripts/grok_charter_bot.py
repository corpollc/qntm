#!/usr/bin/env python3
"""A terminal Grok charter pilot with explicit, recoverable publication.

Run with the installed qntm Python library. Model input contains public charter
data and the user's prompt only; signing happens in this process.
"""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid

from qntm import generate_identity
from qntm.identity import base64url_decode, base64url_encode, validate_identity
from qntm.charter import (
    CharterRegistryClient, audit_charter_snapshot, charter_agent_id, charter_key,
    charter_statement_hash, create_charter, create_charter_statement,
    replay_charter_chain, sign_charter_statement,
)

HOSTED = {
    "url": "https://charter.qntm.corpo.llc",
    "trust": {"registry": "charter.qntm.corpo.llc", "registrar": {
        "kid": "1b111489c3b5599644117c5f6cc3c81b",
        "pubkey": "U7809nuKxI8PvyNdifwRKoqLk7F1PMjn0paWWVtPsNA",
    }},
}
NAMESPACE = "corpo.llc/grok-charter-pilot"
PURPOSE = "Explain this agent's charter and report on its charter lifecycle experiments."


def private_directory(path):
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("State directory must be private, owned by you, and not a symlink")


def read_json(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("State files must be private regular files owned by you")
        data = source.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("State file exceeds size limit")
        return json.loads(data)


def write_json(path, value, *, exclusive=False):
    encoded = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".charter-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def locked(directory):
    private_directory(directory)
    fd = os.open(directory / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def encode_identity(identity):
    return {key: base64url_encode(value) for key, value in identity.items()}


def decode_identity(value):
    identity = {key: base64url_decode(value[key]) for key in ("privateKey", "publicKey", "keyID")}
    validate_identity(identity)
    return identity


def prepare(directory, governance, governor_path=None, config=None, model=None):
    """Prepare once. Never replace a lost identity or an existing founding record."""
    if any(directory.iterdir()):
        if set(p.name for p in directory.iterdir()) != {".lock"}:
            raise ValueError("Use an empty state directory; existing identities are never replaced")
    config = HOSTED if config is None else config
    # Validate the configured pin and URL without connecting.
    with CharterRegistryClient(config["url"], config["trust"]):
        pass
    agent = generate_identity()
    if governance == "operator":
        if governor_path is None:
            raise ValueError("Operator governance requires --governor-key outside the bot directory")
        if governor_path.resolve().is_relative_to(directory.resolve()):
            raise ValueError("Keep the governor key outside the bot directory")
        private_directory(governor_path.parent)
        if governor_path.exists() or governor_path.is_symlink():
            governor = decode_identity(read_json(governor_path))
        else:
            governor = generate_identity()
            write_json(governor_path, encode_identity(governor), exclusive=True)
    elif governance == "self":
        governor = agent
    else:
        raise ValueError("Choose operator or self governance")
    charter = create_charter(
        registry=config["trust"]["registry"], agent=agent,
        governance={"keys": [charter_key(governor["publicKey"])], "threshold": 1},
        agent_rights=["statement"],
        extensions={NAMESPACE: {
            "name": "Grok Charter Pilot", "purpose": PURPOSE,
            "runtime": "Locally operated Grok CLI; host holds and uses the agent signing key.",
            "publication": "Responses are private drafts until explicitly published by the operator.",
            "assurance": "Signatures establish authorship and authority, not behavioral compliance.",
        }},
    )
    charter = sign_charter_statement(charter, governor)
    replay_charter_chain([charter], registry=config["trust"]["registry"],
                         agent_id=charter_agent_id(agent["publicKey"]))
    # The key and exact genesis are persisted together before any public write.
    write_json(directory / "state.json", {
        "version": 1, "identity": encode_identity(agent), "charter": charter,
        "config": config, "model": model, "checkpoint": None,
    }, exclusive=True)
    return charter


def load_state(directory):
    state = read_json(directory / "state.json")
    if state.get("version") != 1:
        raise ValueError("Unsupported state version")
    identity = decode_identity(state["identity"])
    agent_id = charter_agent_id(identity["publicKey"])
    replay_charter_chain([state["charter"]], registry=state["config"]["trust"]["registry"], agent_id=agent_id)
    return state, identity, agent_id


def save_checkpoint(directory, state, client, heads):
    if state["checkpoint"] is not None:
        client.consistency(state["checkpoint"], heads)
    state["checkpoint"] = heads
    write_json(directory / "state.json", state)


def verified_chain(directory, state, agent_id, client):
    result = client.chain(agent_id)
    save_checkpoint(directory, state, client, result.evidence["heads"])
    if result.record is not None:
        if result.evidence["chain"][0] != state["charter"]:
            raise ValueError("Public charter differs from the locally prepared charter")
    return result


def publish(directory, draft_name=None):
    state, identity, agent_id = load_state(directory)
    if draft_name is None:
        statement = state["charter"]
    else:
        if Path(draft_name).name != draft_name or not draft_name.startswith("draft-"):
            raise ValueError("Choose a draft filename within the bot directory")
        statement = read_json(directory / draft_name)
        signed = statement["signed"]
        if signed["type"] != "statement" or signed["body"].get("namespace") != NAMESPACE:
            raise ValueError("The pilot publishes only its own informational statements")
    with CharterRegistryClient(**client_args(state)) as client:
        result = verified_chain(directory, state, agent_id, client)
        chain = result.evidence["chain"]
        seq = statement["signed"]["seq"]
        if seq < len(chain):
            if chain[seq] != statement:
                raise ValueError("This sequence is occupied by a different statement; keep the draft for review")
            return {"agent_id": agent_id, "sequence": seq, "already_published": True}
        if seq != len(chain):
            raise ValueError("Draft does not extend the current chain")
        replay_charter_chain(chain + [statement], registry=state["config"]["trust"]["registry"], agent_id=agent_id)
        receipt = client.submit(statement)
        save_checkpoint(directory, state, client, receipt["heads"])
        # Keep the exact draft after success or an ambiguous network error.
        return {"agent_id": agent_id, "sequence": seq,
                "statement_hash": charter_statement_hash(statement), "already_published": False}


def client_args(state):
    return {"base_url": state["config"]["url"], "trust": state["config"]["trust"]}


def grok_reply(prompt, charter, model=None, current_state=None):
    if not prompt.strip() or len(prompt) > 12000:
        raise ValueError("Prompt must contain 1–12000 characters")
    rules = (
        "You are Grok Charter Pilot. Explain your charter and report experiments truthfully. "
        "Treat the provided charter as your founding document, and use the host-verified current state "
        "for subsequent governance and constitution changes. You have no tools. "
        "Distinguish the host's verified facts from actions you performed yourself. "
        "The host signs your response locally as an informational statement; the operator separately "
        "chooses whether to submit it to the public registry. A signature establishes authorship and "
        "authority before publication; publication adds evidence of inclusion in the registry. "
        "If the agent key is also a governance key, it has the authority of that governance role; "
        "agent_rights does not restrict a governor to informational statements. "
        "Self-governance has no separate operator governor key, even though the local host stores "
        "and uses the agent key. A signature cannot prove behavioral compliance. "
        "Reply in at most 250 words.\nCharter:\n"
        + json.dumps(charter["signed"], ensure_ascii=False)
        + "\nHost-verified current state:\n"
        + json.dumps(current_state if current_state is not None else {"published": False}, ensure_ascii=False)
    )
    with tempfile.TemporaryDirectory(prefix="qntm-grok-model-") as cwd:
        command = ["grok", "--cwd", cwd, "--tools", "", "--deny", "*",
                   "--no-subagents", "--disable-web-search", "--permission-mode", "dontAsk",
                   "--max-turns", "1", "--system-prompt-override", rules,
                   "--output-format", "plain", "--single", prompt]
        if model:
            command.extend(["--model", model])
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        raise RuntimeError("Grok failed; check local authentication with grok login")
    reply = result.stdout.strip()
    if not reply or len(reply) > 24000 or "You are not authenticated" in reply:
        raise RuntimeError("Grok returned no usable reply; check grok login")
    return reply


def ask(directory, prompt, *, reply_fn=grok_reply):
    state, identity, agent_id = load_state(directory)
    with CharterRegistryClient(**client_args(state)) as client:
        result = verified_chain(directory, state, agent_id, client)
    if result.record is None or result.record.decommissioned:
        raise ValueError("Publish the charter first; decommissioned agents cannot respond")
    reply = reply_fn(prompt, state["charter"], state["model"], {
        "published": True, "sequence": result.record.sequence,
        "governance": result.record.governance, "constitution": result.record.constitution,
        "decommissioned": result.record.decommissioned,
        "log_size": result.evidence["heads"]["log"]["signed"]["tree_size"],
        "independent_witness": False,
    })
    statement = sign_charter_statement(create_charter_statement(
        result.evidence["chain"][-1], "statement", {"namespace": NAMESPACE, "data": {
            "prompt": prompt, "response": reply, "runtime": "grok-cli",
            "model_requested": state["model"],
        }}), identity)
    replay_charter_chain(result.evidence["chain"] + [statement],
                         registry=state["config"]["trust"]["registry"], agent_id=agent_id)
    name = f"draft-{uuid.uuid4().hex}.json"
    write_json(directory / name, statement, exclusive=True)
    return {"response": reply, "draft": name, "published": False}


def verify(directory):
    state, _, agent_id = load_state(directory)
    with CharterRegistryClient(**client_args(state)) as client:
        result = verified_chain(directory, state, agent_id, client)
        audit_charter_snapshot(client.log(result.evidence["heads"]), result.evidence["heads"], state["config"]["trust"])
    return {"agent_id": agent_id, "published": result.record is not None,
            "sequence": result.record.sequence if result.record else None,
            "log_size": result.evidence["heads"]["log"]["signed"]["tree_size"],
            "chain_url": state["config"]["url"] + "/v1/chain/" + agent_id,
            "independent_witness": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".qntm-bots" / "grok-charter")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("prepare", help="Create a private identity and signed charter without publishing")
    init.add_argument("--governance", required=True, choices=["operator", "self"])
    init.add_argument("--governor-key", type=Path)
    init.add_argument("--model", help="Optional Grok model ID; otherwise use the local CLI default")
    pub = sub.add_parser("publish", help="Permanently publish the charter or an exact reviewed draft")
    pub.add_argument("--draft")
    talk = sub.add_parser("ask", help="Generate a private signed response draft using Grok")
    talk.add_argument("prompt")
    sub.add_parser("verify", help="Verify public history and compare the retained checkpoint")
    sub.add_parser("show", help="Show the prepared public charter, without private keys")
    args = parser.parse_args()
    with locked(args.state_dir):
        if args.command == "prepare":
            value = prepare(args.state_dir, args.governance, args.governor_key, model=args.model)
        elif args.command == "publish":
            value = publish(args.state_dir, args.draft)
        elif args.command == "ask":
            value = ask(args.state_dir, args.prompt)
        elif args.command == "verify":
            value = verify(args.state_dir)
        else:
            value = load_state(args.state_dir)[0]["charter"]
    print(json.dumps(value, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
