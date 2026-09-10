import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time
from unittest.mock import patch

import pytest

from qntm.attachment import (AttachmentError, AttachmentContext, prepare_attachment,
    parse_attachment, assemble_attachment, attachment_context, MAX_ATTACHMENT_BYTES)
from qntm.identity import generate_identity
from qntm.invite import create_invite, invite_to_token, invite_from_url, create_conversation, derive_conversation_keys
from qntm.message import create_message, serialize_envelope, deserialize_envelope, decrypt_message


def prepared(data=b'signed file bytes'):
    identity = generate_identity()
    invite = create_invite(identity, 'group')
    parent = create_conversation(invite, derive_conversation_keys(invite))
    value = prepare_attachment(identity, parent, data, 'agreement.pdf', 'application/pdf')
    context = AttachmentContext(parent['id'], parent['currentEpoch'], identity['publicKey'])
    return identity, parent, invite, value, context


@pytest.mark.parametrize('size', [0,1,32768,32769,70003,MAX_ATTACHMENT_BYTES])
def test_roundtrip_exact_part_boundaries(size):
    data = bytes((index % 251 for index in range(size)))
    _, _, _, value, context = prepared(data)
    assert assemble_attachment(value.body, context, reversed(value.envelopes)) == data
    assert len(value.envelopes) == max(1,(size+32767)//32768)
    assert all(len(wire) <= 65536 for wire in value.envelopes)


def test_typescript_fixture_authenticates_and_reassembles():
    path = Path(__file__).parents[2]/'client/tests/attachment-typescript.json'
    fixture = json.loads(path.read_text())
    invite = invite_from_url(fixture['parent_invite_token'])
    parent = create_conversation(invite, derive_conversation_keys(invite))
    message = decrypt_message(deserialize_envelope(base64.b64decode(fixture['parent_envelope_b64'])), parent)
    data = assemble_attachment(message['inner']['body'], attachment_context(message),
                               [base64.b64decode(wire) for wire in fixture['parts_b64']])
    assert data == base64.b64decode(fixture['plaintext_b64'])


@pytest.mark.parametrize('change', [
    {'name':'../secret'}, {'name':'a\\b'}, {'name':'bad\x00name'}, {'name':'x'*256},
    {'size':MAX_ATTACHMENT_BYTES+1}, {'size':True}, {'parent_epoch':True}, {'media_type':'text/plain; charset=utf8'},
    {'arbitrary_url':'https://attacker.invalid'}, {'expires_ts':0}, {'parts':[]},
])
def test_malformed_descriptor_fails_closed(change):
    _, _, _, value, context = prepared()
    body = json.dumps({**value.descriptor,**change}).encode()
    with pytest.raises(AttachmentError):
        parse_attachment(body, context)


def test_context_sender_channel_and_epoch_are_bound():
    _, _, _, value, context = prepared()
    for bad in (replace(context, sender_public_key=generate_identity()['publicKey']),
                replace(context, conversation_id=b'x'*16), replace(context, epoch=1)):
        with pytest.raises(AttachmentError):
            assemble_attachment(value.body, bad, value.envelopes)


def test_tamper_missing_wrong_whole_hash_expiry_and_replay_limit():
    _, _, _, value, context = prepared(b'x'*70000)
    with pytest.raises(AttachmentError):
        assemble_attachment(value.body, context, value.envelopes[:-1])
    tampered = list(value.envelopes)
    tampered[0] = tampered[0][:-1] + bytes([tampered[0][-1]^1])
    with pytest.raises(AttachmentError):
        assemble_attachment(value.body, context, tampered)
    for change in ({'sha256':'0'*64}, {'expires_ts':value.descriptor['expires_ts']-1}):
        with pytest.raises(AttachmentError):
            assemble_attachment(json.dumps({**value.descriptor,**change}).encode(), context, value.envelopes)
    with patch('qntm.attachment.time.time', return_value=value.descriptor['expires_ts']+1):
        with pytest.raises(AttachmentError):
            assemble_attachment(value.body, context, value.envelopes)
    with pytest.raises(AttachmentError):
        assemble_attachment(value.body, context, [value.envelopes[0]]*513)
    assert assemble_attachment(value.body, context, [*value.envelopes,*value.envelopes]) == b'x'*70000


def test_forged_part_signed_by_other_identity_rejected_even_with_valid_wire_hash():
    _, _, _, value, context = prepared()
    invite = invite_from_url(value.descriptor['invite_token'])
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    from qntm.cbor import marshal_canonical
    envelope = create_message(generate_identity(), conversation, 'blob.part', marshal_canonical({'v':1,'index':0,'data':b'signed file bytes'}))
    wire = serialize_envelope(envelope)
    descriptor = {**value.descriptor, 'expires_ts':envelope['expiry_ts'],
                  'parts':[{'message_id':envelope['msg_id'].hex(),'sha256':hashlib.sha256(wire).hexdigest()}]}
    with pytest.raises(AttachmentError):
        assemble_attachment(json.dumps(descriptor).encode(), context, [wire])


def test_parent_must_be_verified_blobref():
    for value in ({}, {'verified':False}, {'verified':True,'inner':{'body_type':'text'}}):
        with pytest.raises(AttachmentError):
            attachment_context(value)


def test_bounded_relay_replay_and_upload_before_parent(monkeypatch):
    from qntm.attachment import receive_attachment_envelopes, upload_attachment
    import websockets.sync.client
    _,_,_,value,context=prepared()
    class Socket:
        def __init__(self,frames):self.frames=iter(frames)
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def recv(self,timeout):return next(self.frames)
    frames=[json.dumps({'type':'message','envelope_b64':base64.b64encode(value.envelopes[0]).decode()}),json.dumps({'type':'ready'})]
    def connect(url,**options):
        assert '/v1/subscribe?' in url and 'from_seq=0' in url
        assert options['max_size']==96*1024
        return Socket(frames)
    monkeypatch.setattr(websockets.sync.client,'connect',connect)
    assert receive_attachment_envelopes('https://relay.test',b'a'*16)==list(value.envelopes)
    frames[:]=[json.dumps({'type':'message','envelope_b64':'a'*100000})]
    with pytest.raises(AttachmentError):receive_attachment_envelopes('https://relay.test',b'a'*16)
    posted=[]
    upload_attachment(value,context,lambda conv,wire:posted.append(wire))
    assert posted==list(value.envelopes)


def test_replay_limit_and_timeout_fail_closed(monkeypatch):
    from qntm.attachment import receive_attachment_envelopes
    import websockets.sync.client
    class Socket:
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def recv(self,timeout):return json.dumps({'type':'message','envelope_b64':'YQ=='})
    monkeypatch.setattr(websockets.sync.client,'connect',lambda *a,**kw:Socket())
    with pytest.raises(AttachmentError):receive_attachment_envelopes('https://relay.test',b'a'*16,max_messages=1)
    def timeout(self,**_):raise TimeoutError('private socket details')
    monkeypatch.setattr(Socket,'recv',timeout)
    with pytest.raises(AttachmentError,match='Could not read'):receive_attachment_envelopes('https://relay.test',b'a'*16)


def test_archived_parent_signature_is_reverified_without_old_epoch_keys():
    from qntm.attachment import verify_archived_attachment
    from qntm.cbor import marshal_canonical
    identity,parent,_,value,context=prepared()
    envelope=create_message(identity,parent,'blobref',value.body)
    message=decrypt_message(envelope,parent)
    wire=serialize_envelope(envelope)
    original=marshal_canonical(message['inner'])
    verified=verify_archived_attachment(wire,original)
    assert verified['inner']['body']==value.body
    changed={**message['inner'],'body':value.body.replace(b'agreement.pdf',b'different.pdf')}
    with pytest.raises(AttachmentError):verify_archived_attachment(wire,marshal_canonical(changed))
    with pytest.raises(AttachmentError):verify_archived_attachment(serialize_envelope({**envelope,'conv_epoch':1}),original)


def test_upload_rejects_unreferenced_cached_wires_before_sending():
    from qntm.attachment import upload_attachment
    _,_,_,value,context=prepared()
    with pytest.raises(AttachmentError):
        upload_attachment(replace(value,envelopes=value.envelopes+(b'junk',)),context,lambda *_:pytest.fail('unreferenced wire sent'))
