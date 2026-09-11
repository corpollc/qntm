"""Participant-held attachments over standard QSP envelopes; docs/attachments.md.

Parsing requires context taken from an authenticated parent message. These
helpers perform no group-policy decisions: callers authorize the parent first.
"""
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass

from .cbor import marshal_canonical, unmarshal
from .invite import create_invite, invite_to_token, invite_from_url, create_conversation, derive_conversation_keys
from .message import create_message, decrypt_message, serialize_envelope, deserialize_envelope

ATTACHMENT_TYPE = 'qntm.attachment.v1'
ATTACHMENT_PART_BYTES = 32768
MAX_ATTACHMENT_BYTES = 8 * 1024 * 1024
MAX_ATTACHMENT_PARTS = 256
MAX_ATTACHMENT_DESCRIPTOR_BYTES = 48 * 1024
MAX_ATTACHMENT_ENVELOPE_BYTES = 65536
MAX_ATTACHMENT_REPLAY = 512


class AttachmentError(ValueError):
    """Safe, content-free attachment validation failure."""


@dataclass(frozen=True)
class AttachmentContext:
    conversation_id: bytes
    epoch: int
    sender_public_key: bytes


@dataclass(frozen=True)
class PreparedAttachment:
    descriptor: dict
    body: bytes
    envelopes: tuple[bytes, ...]


def _fail(message='Invalid attachment descriptor'):
    raise AttachmentError(message)


def _record(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        _fail()


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail()


def _hex(value, length):
    if not isinstance(value, str) or re.fullmatch('[a-f0-9]{'+str(length)+'}', value) is None:
        _fail()


def _label(value, maximum):
    if not isinstance(value, str) or not value.strip() or len(value.encode('utf-8')) > maximum or re.search(r'[\x00-\x1f\x7f]', value):
        _fail()


def parse_attachment(body: bytes, context: AttachmentContext) -> dict:
    """Validate a descriptor against the verified parent sender and envelope."""
    if not isinstance(body, bytes) or len(body) > MAX_ATTACHMENT_DESCRIPTOR_BYTES:
        _fail()
    try:
        value = json.loads(body.decode('utf-8'))
        _record(value, ('type','name','media_type','size','sha256','parent_conv_id','parent_epoch','invite_token','expires_ts','parts'))
        if value['type'] != ATTACHMENT_TYPE:
            _fail('Unsupported attachment format')
        _label(value['name'], 255)
        if '/' in value['name'] or '\\' in value['name'] or value['name'] in ('.','..'):
            _fail('Invalid attachment filename')
        _label(value['media_type'], 120)
        if re.fullmatch(r'[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+', value['media_type']) is None:
            _fail('Invalid attachment media type')
        _integer(value['size'], 0, MAX_ATTACHMENT_BYTES)
        _hex(value['sha256'], 64)
        _hex(value['parent_conv_id'], 32)
        _integer(value['parent_epoch'], 0, 0xffffffff)
        _integer(value['expires_ts'], 1, 2**53-1)
        if len(context.conversation_id) != 16 or len(context.sender_public_key) != 32 or value['parent_conv_id'] != context.conversation_id.hex() or value['parent_epoch'] != context.epoch:
            _fail('Attachment belongs to a different conversation or epoch')
        token = value['invite_token']
        if not isinstance(token, str) or len(token) > 2048 or re.fullmatch('[A-Za-z0-9_-]+', token) is None:
            _fail()
        invite = invite_from_url(token)
        if invite['type'] != 'direct' or len(invite['conv_id']) != 16 or invite['inviter_ik_pk'] != context.sender_public_key or invite['conv_id'] == context.conversation_id:
            _fail('Attachment sender or channel mismatch')
        parts = value['parts']
        if not isinstance(parts, list) or len(parts) != max(1, math.ceil(value['size']/ATTACHMENT_PART_BYTES)) or len(parts) > MAX_ATTACHMENT_PARTS:
            _fail('Invalid attachment part count')
        ids = set()
        for part in parts:
            _record(part, ('message_id','sha256'))
            _hex(part['message_id'], 32)
            _hex(part['sha256'], 64)
            if part['message_id'] in ids:
                _fail('Duplicate attachment part')
            ids.add(part['message_id'])
        return value
    except AttachmentError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError):
        _fail()


def prepare_attachment(identity: dict, parent: dict, data: bytes, name: str,
                       media_type='application/octet-stream') -> PreparedAttachment:
    """Encrypt/sign offline. Persist exact returned wires before any network write."""
    if not isinstance(data, bytes) or len(data) > MAX_ATTACHMENT_BYTES:
        _fail('Attachments are limited to 8 MiB')
    invite = create_invite(identity, 'direct')
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    envelopes, parts, expiries = [], [], []
    for index in range(max(1, math.ceil(len(data)/ATTACHMENT_PART_BYTES))):
        content = data[index*ATTACHMENT_PART_BYTES:(index+1)*ATTACHMENT_PART_BYTES]
        envelope = create_message(identity, conversation, 'blob.part', marshal_canonical({'v':1,'index':index,'data':content}))
        wire = serialize_envelope(envelope)
        envelopes.append(wire)
        parts.append({'message_id':envelope['msg_id'].hex(),'sha256':hashlib.sha256(wire).hexdigest()})
        expiries.append(envelope['expiry_ts'])
    descriptor = {'type':ATTACHMENT_TYPE, 'name':name,'media_type':media_type,'size':len(data),
                  'sha256':hashlib.sha256(data).hexdigest(),'parent_conv_id':parent['id'].hex(),
                  'parent_epoch':parent['currentEpoch'],'invite_token':invite_to_token(invite),
                  'expires_ts':min(expiries),'parts':parts}
    body = json.dumps(descriptor, separators=(',',':'), ensure_ascii=False).encode('utf-8')
    parse_attachment(body, AttachmentContext(parent['id'], parent['currentEpoch'], identity['publicKey']))
    return PreparedAttachment(descriptor, body, tuple(envelopes))


def assemble_attachment(body: bytes, context: AttachmentContext, envelopes) -> bytes:
    """Return bytes only after exact wire hashes, QSP signatures and file hash pass."""
    descriptor = parse_attachment(body, context)
    if int(time.time()) > descriptor['expires_ts']:
        _fail('Attachment has expired; ask its sender to resend it')
    wires = {}
    for count, wire in enumerate(envelopes, 1):
        if count > MAX_ATTACHMENT_REPLAY:
            _fail('Attachment replay exceeds the message limit')
        if not isinstance(wire, bytes) or len(wire) > MAX_ATTACHMENT_ENVELOPE_BYTES:
            _fail('Attachment envelope exceeds the size limit')
        wires[hashlib.sha256(wire).hexdigest()] = wire
    invite = invite_from_url(descriptor['invite_token'])
    conversation = create_conversation(invite, derive_conversation_keys(invite))
    chunks, expiries = [], []
    for index, part in enumerate(descriptor['parts']):
        wire = wires.get(part['sha256'])
        if wire is None:
            _fail('Attachment parts are missing or expired; ask its sender to resend it')
        try:
            envelope = deserialize_envelope(wire)
            if envelope['msg_id'].hex() != part['message_id'] or envelope['conv_epoch'] != 0 or envelope['expiry_ts'] < descriptor['expires_ts']:
                _fail('Attachment part identity mismatch')
            message = decrypt_message(envelope, conversation)
            inner = message['inner']
            if inner['body_type'] != 'blob.part' or inner['sender_ik_pk'] != context.sender_public_key:
                _fail('Attachment part sender mismatch')
            payload = unmarshal(inner['body'])
            _record(payload, ('v','index','data'))
            expected = min(ATTACHMENT_PART_BYTES, descriptor['size'] - index*ATTACHMENT_PART_BYTES)
            if type(payload['v']) is not int or payload['v'] != 1 or type(payload['index']) is not int or payload['index'] != index or not isinstance(payload['data'], bytes) or len(payload['data']) != expected:
                _fail('Attachment part order or size mismatch')
            chunks.append(payload['data'])
            expiries.append(envelope['expiry_ts'])
        except AttachmentError:
            raise
        except Exception:
            _fail('Attachment part authentication failed')
    if min(expiries) != descriptor['expires_ts']:
        _fail('Attachment expiry does not match its signed parts')
    data = b''.join(chunks)
    if len(data) != descriptor['size'] or hashlib.sha256(data).hexdigest() != descriptor['sha256']:
        _fail('Attachment SHA-256 verification failed')
    return data


def attachment_context(message: dict) -> AttachmentContext:
    """Extract context only from an already authenticated parent blobref."""
    if message.get('verified') is not True or message.get('inner',{}).get('body_type') != 'blobref':
        _fail('A verified parent attachment message is required')
    return AttachmentContext(bytes(message['envelope']['conv_id']), message['envelope']['conv_epoch'], bytes(message['inner']['sender_ik_pk']))


def verify_archived_attachment(envelope_wire: bytes, inner_wire: bytes) -> dict:
    """Reverify the original signed parent body from participant-held history.

    This does not accept live messages or authorize actions. The original signed
    descriptor binds the epoch even after the old group encryption keys rotate.
    """
    from .message import validate_envelope, validate_inner_payload, verify_message_signature
    from .identity import key_id_from_public_key
    try:
        if len(envelope_wire) > MAX_ATTACHMENT_ENVELOPE_BYTES or len(inner_wire) > MAX_ATTACHMENT_ENVELOPE_BYTES:
            _fail('Archived attachment parent exceeds the size limit')
        envelope, inner = deserialize_envelope(envelope_wire), unmarshal(inner_wire)
        validate_envelope(envelope)
        validate_inner_payload(inner)
        if bytes(inner['sender_kid']) != key_id_from_public_key(bytes(inner['sender_ik_pk'])) or not verify_message_signature(envelope, inner):
            _fail('Archived attachment parent signature is invalid')
        message = {'envelope':envelope,'inner':inner,'verified':True}
        parse_attachment(inner['body'], attachment_context(message))
        return message
    except AttachmentError:
        raise
    except Exception:
        _fail('Archived attachment parent authentication failed')


def receive_attachment_envelopes(dropbox_url: str, conversation_id: bytes, *, timeout=30, max_messages=MAX_ATTACHMENT_REPLAY):
    """Bounded replay on the parent's configured relay; no cursors or chat import."""
    import base64
    from . import cli as qcli
    from websockets.sync.client import connect
    if not isinstance(conversation_id, bytes) or len(conversation_id) != 16:
        _fail('Invalid attachment channel')
    if not 0 < timeout <= 60 or type(max_messages) is not int or not 0 < max_messages <= MAX_ATTACHMENT_REPLAY:
        _fail('Invalid attachment replay bounds')
    url = qcli._subscribe_url(dropbox_url, conversation_id.hex(), 0)
    options = {'open_timeout':min(10,timeout), 'close_timeout':2, 'max_size':96*1024}
    if url.startswith('wss://'):
        options['ssl'] = qcli._ssl_context
    deadline = time.monotonic()+timeout
    wires = []
    try:
        with connect(url, **options) as websocket:
            for _ in range(max_messages+32):
                remaining = deadline-time.monotonic()
                if remaining <= 0:
                    _fail('Attachment replay timed out')
                raw = websocket.recv(timeout=remaining)
                if not isinstance(raw, (str, bytes)) or len(raw) > 96*1024:
                    _fail('Attachment relay frame exceeds the size limit')
                frame = json.loads(raw)
                if frame.get('type') == 'ready':
                    return wires
                if frame.get('type') != 'message':
                    continue
                if len(wires) >= max_messages:
                    _fail('Attachment replay exceeds the message limit')
                encoded = frame.get('envelope_b64')
                if not isinstance(encoded, str) or len(encoded) > 4*((MAX_ATTACHMENT_ENVELOPE_BYTES+2)//3):
                    _fail('Attachment envelope exceeds the size limit')
                wire = base64.b64decode(encoded, validate=True)
                if len(wire) > MAX_ATTACHMENT_ENVELOPE_BYTES:
                    _fail('Attachment envelope exceeds the size limit')
                wires.append(wire)
        _fail('Attachment replay exceeds the frame limit')
    except AttachmentError:
        raise
    except Exception:
        _fail('Could not read attachment parts from the configured relay')


def upload_attachment(prepared: PreparedAttachment, context: AttachmentContext, post_message):
    """Post exact prepared part wires. Caller persists them and sends parent last.

    post_message(channel_bytes, wire_bytes) must validate relay acknowledgement;
    any error propagates and the caller keeps the attempt pending for retry.
    """
    descriptor = parse_attachment(prepared.body, context)
    # Validate cached parts before network writes, including on a resumed send.
    if len(prepared.envelopes) != len(descriptor['parts']):
        _fail('Saved attachment parts do not match the descriptor')
    assemble_attachment(prepared.body, context, prepared.envelopes)
    invite = invite_from_url(descriptor['invite_token'])
    for wire in prepared.envelopes:
        post_message(bytes(invite['conv_id']), wire)


def download_attachment(body: bytes, context: AttachmentContext, dropbox_url: str) -> bytes:
    descriptor = parse_attachment(body, context)
    invite = invite_from_url(descriptor['invite_token'])
    return assemble_attachment(body, context, receive_attachment_envelopes(dropbox_url, bytes(invite['conv_id'])))
