"""Persistent identity, authority, publication recovery and model boundaries."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from qntm import generate_identity
from qntm.charter import CharterError, charter_key, create_charter_statement, replay_charter_chain, sign_charter_statement

SPEC = importlib.util.spec_from_file_location(
    "grok_charter_bot", Path(__file__).resolve().parents[2] / "scripts" / "grok_charter_bot.py")
bot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bot)


@pytest.fixture
def directory(tmp_path):
    path = tmp_path / "bot"
    bot.private_directory(path)
    return path


def test_self_charter_survives_restart_and_cannot_be_replaced(directory):
    with bot.locked(directory):
        original = bot.prepare(directory, "self")
    state, identity, agent_id = bot.load_state(directory)
    assert state["charter"] == original
    assert original["signed"]["body"]["governance"] == {
        "keys": [charter_key(identity["publicKey"])], "threshold": 1}
    assert (directory / "state.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="existing identities"):
        bot.prepare(directory, "self")
    assert bot.load_state(directory)[2] == agent_id
    (directory / "state.json").unlink()
    bot.write_json(directory / "draft-preserved.json", {"evidence": "keep"})
    with pytest.raises(ValueError, match="existing identities"):
        bot.prepare(directory, "self")


def test_self_governance_authorizes_bot_but_not_unrelated_signer(directory):
    charter = bot.prepare(directory, "self")
    state, identity, agent_id = bot.load_state(directory)
    successor = create_charter_statement(charter, "governance.rotate", {
        "governance": {"keys": [charter_key(generate_identity()["publicKey"])], "threshold": 1}})
    record = replay_charter_chain([charter, sign_charter_statement(successor, identity)],
                                 registry=bot.HOSTED["trust"]["registry"], agent_id=agent_id)
    assert record.sequence == 1
    with pytest.raises(CharterError):
        replay_charter_chain([charter, sign_charter_statement(successor, generate_identity())],
                             registry=state["config"]["trust"]["registry"], agent_id=agent_id)


def test_operator_key_is_separate_and_not_saved_in_bot_state(directory, tmp_path):
    key = tmp_path / "operator" / "governor.json"
    bot.prepare(directory, "operator", key)
    assert bot.read_json(key)["privateKey"] not in (directory / "state.json").read_text()
    _, agent, agent_id = bot.load_state(directory)
    charter = bot.load_state(directory)[0]["charter"]
    change = create_charter_statement(charter, "governance.rotate", {
        "governance": {"keys": [charter_key(agent["publicKey"])], "threshold": 1}})
    with pytest.raises(CharterError):
        replay_charter_chain([charter, sign_charter_statement(change, agent)],
                             registry=bot.HOSTED["trust"]["registry"], agent_id=agent_id)


def test_private_state_rejects_symlinks_and_overlapping_processes(directory):
    bot.prepare(directory, "self")
    state = directory / "state.json"
    state.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        bot.load_state(directory)
    state.chmod(0o600)
    state.rename(directory / "original.json")
    state.symlink_to(directory / "original.json")
    with pytest.raises(OSError):
        bot.load_state(directory)
    with bot.locked(directory), pytest.raises(BlockingIOError):
        with bot.locked(directory):
            pass


def test_model_gets_public_charter_only_and_no_tools(directory):
    charter = bot.prepare(directory, "self")
    state = bot.load_state(directory)[0]
    completed = subprocess.CompletedProcess([], 0, stdout="I can explain my charter.", stderr="")
    with patch.object(bot.subprocess, "run", return_value=completed) as run:
        assert bot.grok_reply("Explain your purpose.", charter) == completed.stdout
    command = run.call_args.args[0]
    assert state["identity"]["privateKey"] not in " ".join(command)
    assert command[command.index("--tools") + 1] == ""
    assert command[command.index("--deny") + 1] == "*"
    assert "--no-subagents" in command
    assert not Path(command[command.index("--cwd") + 1]).exists()


def test_no_authentication_is_not_mistaken_for_a_model_reply(directory):
    charter = bot.prepare(directory, "self")
    for code, output in [(0, "You are not authenticated."), (1, "error"), (0, "")]:
        with patch.object(bot.subprocess, "run", return_value=subprocess.CompletedProcess([], code, output, "")):
            with pytest.raises(RuntimeError):
                bot.grok_reply("Hello", charter)


@pytest.mark.skipif(not os.environ.get("QNTM_CHARTER_TEST_BINARY"), reason="Set QNTM_CHARTER_TEST_BINARY for real Go lifecycle")
def test_real_registrar_lifecycle_recovery_conflicts_and_restart(directory, tmp_path):
    """A deterministic reply exercises the host, not Grok authentication/inference."""
    binary = os.environ["QNTM_CHARTER_TEST_BINARY"]
    process = None
    info = None

    def start(listen="127.0.0.1:0"):
        nonlocal process, info
        process = subprocess.Popen([binary, "--listen", listen, "--data-dir", str(tmp_path / "registry"),
                                    "--registry", "pilot.test"], stdout=subprocess.PIPE, text=True)
        info = json.loads(process.stdout.readline())

    def stop():
        process.terminate()
        process.wait(timeout=15)
        process.stdout.close()

    start()
    try:
        config = {"url": "http://" + info["listen"], "trust": {"registry": "pilot.test", "registrar": info["registrar"]}}
        bot.prepare(directory, "self", config=config)
        assert bot.verify(directory)["published"] is False
        assert bot.publish(directory)["sequence"] == 0
        assert bot.publish(directory)["already_published"] is True
        first = bot.ask(directory, "What is your purpose?", reply_fn=lambda *args: "I explain my charter.")
        conflict = bot.ask(directory, "Describe the pilot", reply_fn=lambda *args: "A different statement.")
        assert first["published"] is False
        assert bot.verify(directory)["sequence"] == 0

        actual_submit = bot.CharterRegistryClient.submit

        def lost_ack(client, statement):
            actual_submit(client, statement)
            raise ConnectionError("response lost after durable commit")

        with patch.object(bot.CharterRegistryClient, "submit", lost_ack):
            with pytest.raises(ConnectionError):
                bot.publish(directory, first["draft"])
        assert bot.publish(directory, first["draft"])["already_published"] is True
        with pytest.raises(ValueError, match="different statement"):
            bot.publish(directory, conflict["draft"])
        assert (directory / conflict["draft"]).exists()
        before = bot.verify(directory)
        address = info["listen"]
        stop()
        start(address)
        assert bot.verify(directory) == before
        assert before["sequence"] == 1
        assert before["log_size"] == 2
        # A valid historical head is still a rollback relative to our checkpoint.
        state = bot.load_state(directory)[0]
        with bot.CharterRegistryClient(**bot.client_args(state)) as client:
            with pytest.raises(CharterError):
                bot.save_checkpoint(directory, state, client, client.heads(1))
        assert bot.load_state(directory)[0]["checkpoint"]["log"]["signed"]["tree_size"] == 2
    finally:
        if process is not None and process.poll() is None:
            stop()
