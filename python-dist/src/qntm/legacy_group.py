"""Durable genesis delivery for legacy bearer-invite groups.

This is a local send journal, not an ordinary-group session or relay registration.
Keep the original ciphertext and receipt separate from mutable conversation metadata.
"""
import base64
import os
import time
from urllib.error import HTTPError

from . import cli
from .group import GroupState, create_group_genesis_body, parse_group_genesis_body
from .message import decrypt_message, deserialize_envelope, check_expiry
from .storage import private_lock


class LegacyCreationError(Exception):
    def __init__(self, conversation_id, message_id, cause, *, delivery='unknown'):
        self.data = {
            'conversation_id': conversation_id, 'message_id': message_id,
            'delivery': delivery, 'cause': type(cause).__name__,
            'retry': f'qntm group retry {conversation_id}', 'retry_tool': 'group_retry',
        }
        if isinstance(cause, HTTPError):
            self.data['http_status'] = cause.code
        # Transport exception strings can contain credentials; expose only type.
        detail = str(cause) if isinstance(cause, ValueError) else type(cause).__name__
        super().__init__(f'Legacy group creation did not complete ({detail}). '
                         f'Keep this profile and use qntm group retry {conversation_id}; '
                         'the original genesis is saved.')


def _path(config_dir, conversation_id):
    return os.path.join(config_dir, 'groups', conversation_id + '.creation.json')


def has_creation(config_dir, conversation_id):
    return os.path.lexists(_path(config_dir, conversation_id))


def assert_creation_complete(config_dir, conversation_id):
    journal = cli._load_json(_path(config_dir, conversation_id))
    receipt = journal.get('receipt') if isinstance(journal, dict) else None
    if journal is not None and (not isinstance(receipt, dict) or type(receipt.get('seq')) is not int or receipt['seq'] < 1
                                or receipt.get('evidence') not in {'relay_acknowledgement', 'exact_replay'}):
        raise ValueError(f'Legacy genesis delivery is pending; use group retry {conversation_id} before changing group mode')


def _operation_lock(config_dir, conversation_id):
    return private_lock(os.path.join(config_dir, 'groups', conversation_id + '.operation.lock'))


def create(config_dir, identity, relay_url, name, description=''):
    invite = cli.create_invite(identity, 'group')
    keys = cli.derive_conversation_keys(invite)
    conversation = cli.create_conversation(invite, keys)
    cli.add_participant(conversation, identity['publicKey'])
    cid = conversation['id'].hex()
    body = create_group_genesis_body(name, description, identity, [])
    state = GroupState()
    state.apply_genesis(parse_group_genesis_body(body))
    record = {
        'id': cid, 'name': name, 'type': 'group', 'relay_url': relay_url.rstrip('/'),
        'keys': {'root': keys['root'].hex(), 'aead_key': keys['aeadKey'].hex(), 'nonce_key': keys['nonceKey'].hex()},
        'participants': [identity['keyID'].hex()], 'participant_public_keys': [identity['publicKey'].hex()],
        'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'current_epoch': 0, 'invite_token': cli.invite_to_token(invite),
    }
    envelope = cli.create_message(identity, conversation, 'group_genesis', body, None, cli.default_ttl())
    journal = {'version': 1, 'conversation_id': cid, 'relay_url': record['relay_url'],
               'creator_public_key': identity['publicKey'].hex(),
               'envelope_b64': base64.b64encode(cli.serialize_envelope(envelope)).decode()}
    with _operation_lock(config_dir, cid):
        with private_lock(os.path.join(config_dir, 'receive.lock')):
            # Every write finishes (including fsync) before the first POST.
            cli._save_json(_path(config_dir, cid), journal)
            try:
                records = cli._load_conversations(config_dir)
                records.append(record)
                cli._save_conversations(config_dir, records)
                cli._save_group_state(config_dir, cid, state)
                cli._merge_participant_public_key(config_dir, cid, identity['publicKey'])
            except Exception as error:
                raise LegacyCreationError(cid, envelope['msg_id'].hex(), error, delivery='not_sent') from error
        return _resume(config_dir, identity, relay_url, cid, first_attempt=True)


def retry(config_dir, identity, relay_url, conversation_id):
    with _operation_lock(config_dir, conversation_id):
        return _resume(config_dir, identity, relay_url, conversation_id)


def _resume(config_dir, identity, relay_url, cid, *, first_attempt=False):
    message_id, delivery = None, 'not_sent' if first_attempt else 'unknown'
    try:
        journal = cli._load_json(_path(config_dir, cid))
        if not isinstance(journal, dict) or journal.get('version') != 1 or journal.get('conversation_id') != cid:
            raise ValueError('Invalid saved legacy creation')
        if journal.get('relay_url') != relay_url.rstrip('/'):
            raise ValueError('Retry must use the original relay')
        if journal.get('creator_public_key') != identity['publicKey'].hex():
            raise ValueError('Retry must use the original identity')
        record = cli._find_conversation(cli._load_conversations(config_dir), cid)
        if not record or record.get('type') != 'group' or record.get('group_session'):
            raise ValueError('Saved legacy group is missing or changed mode')
        wire = base64.b64decode(journal['envelope_b64'], validate=True)
        envelope = deserialize_envelope(wire)
        message_id = envelope['msg_id'].hex()
        # Recover the original epoch-zero keys without changing live group state.
        invite = cli.invite_from_url(record['invite_token'])
        initial = cli.create_conversation(invite, cli.derive_conversation_keys(invite))
        message = decrypt_message(envelope, initial, allow_expired=True)
        if (initial['id'].hex() != cid or envelope.get('conv_epoch', 0) != 0
                or message['inner']['body_type'] != 'group_genesis'
                or message['inner']['sender_ik_pk'] != identity['publicKey']):
            raise ValueError('Invalid saved legacy genesis')
        genesis = GroupState()
        genesis.apply_genesis(parse_group_genesis_body(message['inner']['body']))
        receipt = journal.get('receipt')
        if receipt is not None and (not isinstance(receipt, dict) or type(receipt.get('seq')) is not int or receipt['seq'] < 1
                                    or receipt.get('evidence') not in {'relay_acknowledgement', 'exact_replay'}):
            raise ValueError('Invalid saved genesis receipt')
        if receipt is None and not first_attempt:
            # Read-only reconciliation precedes expiry/state refusal. A POST may
            # already have committed even if the process never saved its ACK.
            try:
                sequence = cli._find_sent_envelope(relay_url, cid, wire)
            except Exception:
                sequence = None
            if sequence is not None:
                receipt = {'seq': sequence, 'evidence': 'exact_replay'}
        if receipt is None:
            if check_expiry(envelope):
                raise ValueError('Saved genesis expired without an accepted receipt; keep the journal for reconciliation')
            with private_lock(os.path.join(config_dir, 'receive.lock')):
                record = cli._find_conversation(cli._load_conversations(config_dir), cid)
                if record.get('current_epoch', 0) != 0 or cli._conv_to_crypto(record)['keys'] != initial['keys']:
                    raise ValueError('Group keys changed before genesis delivery was confirmed')
                current = cli._load_group_state(config_dir, cid)
                if current.member_count() == 0 and record['participants'] == [identity['keyID'].hex()]:
                    # Interrupted preparation, before any network write.
                    cli._save_group_state(config_dir, cid, genesis)
                elif current.to_dict() != genesis.to_dict():
                    raise ValueError('Group membership changed before genesis delivery was confirmed')
            delivery = 'unknown'
            result = cli._http_send(relay_url, cid, wire)
            receipt = {'seq': result['seq'], 'evidence': ('exact_replay' if result.get('acknowledgement') == 'reconciled'
                                                        else 'relay_acknowledgement')}
        delivery = 'accepted'
        journal['receipt'] = receipt
        cli._save_json(_path(config_dir, cid), journal)
        return {'conversation_id': cid, 'type': 'group', 'name': record.get('name', ''),
                'invite_token': record['invite_token'], 'members': cli._load_group_state(config_dir, cid).member_count(),
                'message_id': message_id, 'delivery': delivery, 'seq': receipt['seq'], 'evidence': receipt['evidence']}
    except Exception as error:
        if isinstance(error, HTTPError) and 400 <= error.code < 500:
            delivery = 'rejected'
        raise LegacyCreationError(cid, message_id, error, delivery=delivery) from error
