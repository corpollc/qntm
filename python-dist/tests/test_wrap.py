"""Tests for key wrapping (group rekey, v1.1)."""

import os

from qntm import generate_identity, QSP1Suite


def test_wrap_unwrap_roundtrip():
    """Wrap and unwrap a group key for a recipient."""
    suite = QSP1Suite()
    recipient = generate_identity()
    recipient_kid = recipient["keyID"]
    conv_id = os.urandom(16)
    new_group_key = os.urandom(32)

    wrapped = suite.wrap_key_for_recipient(
        new_group_key, recipient["publicKey"], recipient_kid, conv_id
    )

    unwrapped = suite.unwrap_key_for_recipient(
        wrapped, recipient["privateKey"], recipient_kid, conv_id
    )

    assert unwrapped == new_group_key


def test_wrap_wrong_recipient_fails():
    """Wrong recipient cannot unwrap."""
    suite = QSP1Suite()
    recipient = generate_identity()
    wrong_recipient = generate_identity()
    conv_id = os.urandom(16)
    new_group_key = os.urandom(32)

    wrapped = suite.wrap_key_for_recipient(
        new_group_key, recipient["publicKey"], recipient["keyID"], conv_id
    )

    try:
        suite.unwrap_key_for_recipient(
            wrapped, wrong_recipient["privateKey"], wrong_recipient["keyID"], conv_id
        )
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrap_multiple_recipients():
    """Wrap key for multiple recipients, each can unwrap."""
    suite = QSP1Suite()
    conv_id = os.urandom(16)
    new_group_key = os.urandom(32)

    recipients = [generate_identity() for _ in range(5)]
    wrapped_keys = {}

    for r in recipients:
        wrapped_keys[r["keyID"]] = suite.wrap_key_for_recipient(
            new_group_key, r["publicKey"], r["keyID"], conv_id
        )

    for r in recipients:
        unwrapped = suite.unwrap_key_for_recipient(
            wrapped_keys[r["keyID"]], r["privateKey"], r["keyID"], conv_id
        )
        assert unwrapped == new_group_key
