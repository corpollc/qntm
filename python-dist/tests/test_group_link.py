from urllib.parse import urlsplit

import pytest

from qntm import (create_group_link, parse_group_link, generate_identity, marshal_canonical, unmarshal,
                  base64url_decode, base64url_encode)


def test_public_fragment_locator_and_legacy_query_removal():
    public_key, conversation_id = generate_identity()["publicKey"], bytes([9]) * 16
    link = create_group_link(conversation_id, public_key, "https://inbox.qntm.corpo.llc",
                             "https://chat.corpo.llc/path?old=secret#old-secret")
    assert parse_group_link(link) == {"conversation_id": conversation_id, "inviter_public_key": public_key,
                                      "relay_url": "https://inbox.qntm.corpo.llc"}
    url = urlsplit(link)
    assert url.path == "/path" and not url.query and url.fragment.startswith("group=")
    body = unmarshal(base64url_decode(url.fragment[6:]))
    assert set(body) == {"v", "type", "conv_id", "inviter_ik_pk", "relay_url"}
    assert "secret" not in link


def test_local_relay():
    key = generate_identity()["publicKey"]
    link = create_group_link(bytes(16), key, "http://127.0.0.1:1234/")
    assert parse_group_link(link)["relay_url"] == "http://127.0.0.1:1234"


@pytest.mark.parametrize("relay", ["file:///etc/passwd", "https://user:pass@example.com", "https://example.com/?secret=x",
                                     "https://example.com/#fragment", "https:example.com", "https://example.com:99999",
                                     "https://example.com\\path"])
def test_invalid_relay(relay):
    with pytest.raises(ValueError):
        create_group_link(bytes(16), generate_identity()["publicKey"], relay)


def test_strict_locator_schema_and_encoding():
    link = create_group_link(bytes(16), generate_identity()["publicKey"], "https://inbox.qntm.corpo.llc")
    body = unmarshal(base64url_decode(urlsplit(link).fragment[6:]))
    for bad in [{**body, "group_key": bytes(32)}, {**body, "inviter_ik_pk": bytes(32)},
                {**body, "conv_id": bytes(15)}, {**body, "v": 2}, {**body, "type": "qntm.join"}]:
        with pytest.raises(ValueError):
            parse_group_link("https://chat.corpo.llc/#group=" + base64url_encode(marshal_canonical(bad)))
    for bad in [link.replace("#group=", "?group="), link + "=", "https://chat.corpo.llc/#group=" + "a" * 9000]:
        with pytest.raises(ValueError):
            parse_group_link(bad)
