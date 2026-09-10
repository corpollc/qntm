"""Private CLI orchestration for ordinary groups and contact-addressed welcomes.

The shared group_session reducer owns protocol decisions. This module owns
local files, transport progress and the exact pending operation. No server-side
admission or stranger-entry request is involved.
"""
import base64
import copy
import os
import re
import time

from nacl.exceptions import CryptoError

from . import cli
from .cbor import unmarshal
from .crypto import QSP1Suite
from .ed25519 import is_valid_ed25519_public_key
from .group import GroupState, create_group_remove_body, create_rekey
from .group_link import create_group_link, parse_group_link
from .group_session import (
    create_group_session, restore_group_session, receive_group_event, group_session_conversation,
    prepare_group_session_addition, assert_group_addition_accepted, assert_group_can_send,
    prepare_group_welcome_refresh, assert_group_welcome_refresh_current, prepare_group_session_rekey,
    check_group_replay_coverage, check_expired_group_control, group_session_from_welcome,
    create_group_control_message,
)
from .group_welcome import open_group_welcome, is_group_welcome_envelope
from .identity import base64url_decode, key_id_from_public_key
from .message import deserialize_envelope, serialize_envelope
from .receive import create_receive_event
from .storage import private_lock

_suite = QSP1Suite()
MAX_PENDING_MESSAGES = 256
MAX_PENDING_BYTES = 4 * 1024 * 1024


def _recovery_challenge(value):
    if value == '':
        return None
    if not isinstance(value, str) or not re.fullmatch('[0-9a-fA-F]{64}', value):
        raise ValueError('Recovery challenge must be 64 hexadecimal characters')
    return bytes.fromhex(value)


def public_key(value):
    """Decode a full signing address, never a short key ID."""
    if not isinstance(value, str):
        raise ValueError('Contact public key must be text')
    value = value.strip()
    try:
        key = bytes.fromhex(value) if re.fullmatch('[0-9a-fA-F]{64}', value) else base64url_decode(value)
    except (ValueError, TypeError) as error:
        raise ValueError('Invalid contact public key') from error
    if len(key) != 32 or not is_valid_ed25519_public_key(key):
        raise ValueError('Invalid contact public key')
    return key


def contacts(config_dir):
    value = cli._load_json(os.path.join(config_dir, 'contacts.json'), {'version': 1, 'contacts': []})
    if not isinstance(value, dict) or value.get('version') != 1 or not isinstance(value.get('contacts'), list):
        raise ValueError('Invalid local contact book')
    names = set()
    for contact in value['contacts']:
        if (not isinstance(contact, dict) or set(contact) != {'name', 'public_key'}
                or not isinstance(contact['name'], str) or not contact['name'].strip()
                or len(contact['name'].encode()) > 128 or contact['name'].casefold() in names):
            raise ValueError('Invalid local contact')
        public_key(contact['public_key'])
        names.add(contact['name'].casefold())
    return value['contacts']


def set_contact(config_dir, name, address):
    key = public_key(address)
    name = name.strip()
    if not name or len(name.encode()) > 128:
        raise ValueError('Contact name must be 1 to 128 UTF-8 bytes')
    with private_lock(os.path.join(config_dir, 'contacts.lock')):
        rows = contacts(config_dir)
        existing = next((row for row in rows if row['name'].casefold() == name.casefold()), None)
        if existing and public_key(existing['public_key']) != key:
            raise ValueError('Contact name already pins another key; remove that contact before replacing it')
        if not existing:
            rows.append({'name': name, 'public_key': key.hex()})
        cli._save_json(os.path.join(config_dir, 'contacts.json'), {'version': 1, 'contacts': rows})
    return {'name': name, 'public_key': key.hex(), 'key_id': key_id_from_public_key(key).hex()}


def remove_contact(config_dir, name):
    with private_lock(os.path.join(config_dir, 'contacts.lock')):
        rows = contacts(config_dir)
        remaining = [row for row in rows if row['name'].casefold() != name.casefold()]
        if len(remaining) == len(rows):
            raise ValueError('Contact not found')
        cli._save_json(os.path.join(config_dir, 'contacts.json'), {'version': 1, 'contacts': remaining})


def resolve_contact(config_dir, value):
    match = next((row for row in contacts(config_dir) if row['name'].casefold() == value.casefold()), None)
    return public_key(match['public_key'] if match else value)


def _group(state):
    group = GroupState()
    group.apply_genesis(unmarshal(base64url_decode(state['snapshot'])))
    return group


def _install(record, state):
    crypto = group_session_conversation(state)
    record['group_session'] = state
    record['current_epoch'] = crypto['currentEpoch']
    record['keys'] = {'root': crypto['keys']['root'].hex(), 'aead_key': crypto['keys']['aeadKey'].hex(), 'nonce_key': crypto['keys']['nonceKey'].hex()}
    record['participants'] = [kid.hex() for kid in crypto['participants']]
    record['participant_public_keys'] = [member['public_key'].hex() for member in _group(state).snapshot()['founding_members']]


def _history_entry(message, sequence, order):
    envelope, inner = message['envelope'], message['inner']
    sender = inner['sender_kid'].hex()
    kind, body = inner['body_type'], inner['body']
    entry = {'msg_id': envelope['msg_id'].hex(), 'direction': 'incoming', 'sender_kid': sender,
             'body_type': kind, 'created_ts': envelope['created_ts'], 'verified': True,
             'sequence': sequence, 'receive_order': order, 'receive_event': create_receive_event(message, sequence)}
    group_text = cli._decode_group_body(kind, body)
    if group_text is not None:
        entry['unsafe_body'] = group_text
        formatted = cli._format_group_event(kind, group_text, sender)
        if formatted:
            entry['system_message'] = formatted
    else:
        try:
            entry['unsafe_body'] = body.decode('utf-8')
        except UnicodeDecodeError:
            entry['unsafe_body_b64'] = base64.b64encode(body).decode()
    return entry


def receive_batch(record, identity, raw_messages, head):
    """Stage a whole batch in a detached record, including recoverable ciphertext.

    Callers persist the returned record atomically before advancing transport or
    hook progress. The public sequence remains the original relay sequence;
    receive_order lets hooks notice a late-decrypted message after a rewind.
    """
    if type(head) is not int or head < 0:
        raise ValueError('Invalid group receive cursor')
    result = copy.deepcopy(record)
    state = restore_group_session(identity, result['group_session'])
    history = result.setdefault('group_history', [])
    floor = result.get('group_cursor', 0)
    # A concurrent receiver may already have committed beyond this fetch's head.
    head = max(head, floor)
    receipts = result.get('group_delivery_receipts', [])
    known_sequences = [row.get('relay_receipt_sequence') for row in history
                       if row.get('body_type') == 'text' and type(row.get('relay_receipt_sequence')) is int
                       and floor < row['relay_receipt_sequence'] <= head]
    known_sequences += [seq for seq in receipts if type(seq) is int and floor < seq <= head]
    state = check_group_replay_coverage(state, floor, head, [row['seq'] for row in raw_messages] + known_sequences)
    known_history = {entry['msg_id']: entry for entry in history}
    order = max(result.get('group_order', 0), result.get('group_cursor', 0),
                max((entry.get('receive_order', entry.get('sequence', 0)) for entry in history), default=0))
    pending = {}
    for raw in [*result.get('group_pending', []), *raw_messages]:
        try:
            sequence = raw['seq']
            if type(sequence) is not int or sequence <= 0:
                continue
            wire = base64.b64decode(raw['envelope_b64'], validate=True)
            envelope = deserialize_envelope(wire)
            if (type(envelope.get('expiry_ts')) is not int or type(envelope.get('conv_epoch')) is not int
                    or not isinstance(envelope.get('msg_id'), bytes) or len(envelope['msg_id']) != 16):
                continue
            if envelope['conv_id'].hex() != result['id'] or is_group_welcome_envelope(envelope):
                continue
            # Key by exact bytes: conflicting IDs must still reach the reducer.
            pending[_suite.hash(wire).hex()] = {'seq': sequence, 'envelope_b64': base64.b64encode(wire).decode()}
        except (ValueError, TypeError, KeyError):
            continue
    output = []
    remaining = sorted(pending.values(), key=lambda row: row['seq'])
    while remaining:
        retry, changed = [], False
        for raw in remaining:
            envelope = deserialize_envelope(base64.b64decode(raw['envelope_b64']))
            if envelope['expiry_ts'] < int(time.time()):
                if raw['seq'] > result.get('group_bootstrap_sequence', 0):
                    state = check_expired_group_control(identity, state, envelope, raw['seq'])
                if envelope['conv_epoch'] > state['epoch'] and not state['recovery'] and not state['removed']:
                    retry.append(raw)
                continue
            if state['recovery']:
                continue
            try:
                event = receive_group_event(identity, envelope, state)
            except CryptoError:
                if not state['removed']:
                    retry.append(raw)
                continue
            except (ValueError, TypeError, KeyError) as error:
                # A child on the eventual winning branch can arrive before its
                # parent. Its ID need not beat the losing branch's child ID.
                epoch = envelope.get('conv_epoch')
                branch_may_rewind = type(epoch) is int and any(frame['epoch'] < epoch for frame in state['rekeys'])
                if (not state['removed'] and type(epoch) is int
                        and (epoch > state['epoch'] or branch_may_rewind
                             and str(error) == 'Stale, future or superseded group epoch')):
                    retry.append(raw)
                continue
            state = event['state']
            if event['duplicate']:
                continue
            changed = True
            message = event['message']
            if state['removed']:
                result['group_removed_sequence'] = max(result.get('group_removed_sequence', 0), raw['seq'])
            mid = envelope['msg_id'].hex()
            previous_entry = known_history.get(mid)
            if previous_entry is None or 'receive_event' not in previous_entry:
                order = max(order + 1, raw['seq'])
                entry = _history_entry(message, raw['seq'], order)
                if previous_entry is None:
                    history.append(entry)
                    known_history[mid] = entry
                else:
                    # A sent message already has a local history row, but its
                    # verified relay echo must still reach --include-self hooks.
                    previous_entry.update(entry)
                output.append({'conversation_id': result['id'], 'message_id': mid, 'sender': entry['sender_kid'][:3],
                               **{key: value for key, value in entry.items() if key not in {'msg_id', 'direction', 'receive_event', 'receive_order'}}})
        remaining = retry
        if not changed:
            break
    if len(remaining) > MAX_PENDING_MESSAGES or sum(len(row['envelope_b64']) for row in remaining) > MAX_PENDING_BYTES * 4 // 3:
        raise ValueError('Group receive backlog exceeds its local bound; receive progress was not advanced')
    _install(result, state)
    result['group_pending'] = remaining
    result['group_cursor'] = max(result.get('group_cursor', 0), head)
    result['group_delivery_receipts'] = [seq for seq in receipts if seq > head]
    result['group_order'] = order
    return result, output


def receive_batch_locked(config_dir, identity, records, record, raw, head):
    updated, output = receive_batch(record, identity, raw, head)
    records[records.index(record)] = updated
    cli._save_conversations(config_dir, records)
    return output


class GroupClient:
    def __init__(self, config_dir, identity, relay_url):
        self.config_dir, self.identity, self.relay_url = config_dir, identity, relay_url.rstrip('/')

    def _lock(self):
        return private_lock(os.path.join(self.config_dir, 'receive.lock'))

    def _load(self, conversation_id):
        records = cli._load_conversations(self.config_dir)
        record = cli._resolve_conversation(records, conversation_id)
        if record is None or record.get('type') != 'group':
            raise ValueError('Group conversation not found')
        if record.get('gateway'):
            raise ValueError('Gateway groups require their governed membership operation')
        if record.get('relay_url') and record['relay_url'].rstrip('/') != self.relay_url:
            raise ValueError('Group relay differs from its saved configuration')
        return records, record

    def enable(self, conversation_id):
        with self._lock():
            records, record = self._load(conversation_id)
            if not record.get('group_session'):
                group = cli._load_group_state(self.config_dir, record['id'])
                state = create_group_session(self.identity, cli._conv_to_crypto(record), group, signed_epoch=False)
                record['group_history'] = cli._load_history(self.config_dir, record['id'])
                record['group_cursor'] = cli._load_cursors(self.config_dir).get(record['id'], 0)
                record['group_pending'] = []
                record['relay_url'] = self.relay_url
                _install(record, state)
                cli._save_conversations(self.config_dir, records)
            return copy.deepcopy(record)

    def sync(self, conversation_id):
        _, record = self._load(conversation_id)
        raw, head = cli._recv_once(self.relay_url, record['id'], record.get('group_cursor', 0))
        if head < record.get('group_cursor', 0):
            raise ValueError('Relay replay head is older than saved progress; group state was not changed')
        cli._process_received_messages(self.config_dir, self.identity, [], record, raw, head)
        return self._load(record['id'])[1]

    def _save_operation(self, conversation_id, operation):
        with self._lock():
            records, record = self._load(conversation_id)
            if record.get('group_operation'):
                raise ValueError('A group operation is pending; use group retry')
            record['group_operation'] = operation
            cli._save_conversations(self.config_dir, records)

    def _operation_lock(self, conversation_id):
        return private_lock(os.path.join(self.config_dir, 'groups', conversation_id + '.operation.lock'))

    def add(self, conversation_id, address, challenge=''):
        recovery_challenge = _recovery_challenge(challenge)
        key = resolve_contact(self.config_dir, address)
        record = self.enable(conversation_id)
        with self._operation_lock(record['id']):
            record = self.sync(record['id'])
            if record.get('group_operation'):
                raise ValueError('A group operation is pending; use group retry')
            operation = prepare_group_session_addition(self.identity, record['group_session'], [key], recovery_challenge=recovery_challenge)
            expected = create_group_session(self.identity, operation['conversation'], operation['state'], signed_epoch=record['group_session']['signedEpoch'])
            self._save_operation(record['id'], {'kind': 'add', 'controls': [base64.b64encode(serialize_envelope(operation[name])).decode() for name in ('addition', 'rekey')],
                                                'welcomes': [base64.b64encode(serialize_envelope(w)).decode() for w in operation['welcomes']],
                                                'expected': expected, 'welcomes_sent': 0, 'member': key_id_from_public_key(key).hex()})
            return self._resume(record['id'])

    def change(self, conversation_id, member=None, reason=''):
        record = self.enable(conversation_id)
        with self._operation_lock(record['id']):
            record = self.sync(record['id'])
            state = record['group_session']
            if member is not None:
                assert_group_can_send(self.identity, state)
            conversation, group = group_session_conversation(state), _group(state)
            controls = []
            if member is not None:
                kid = bytes.fromhex(member) if re.fullmatch('[0-9a-fA-F]{32}', member) else key_id_from_public_key(resolve_contact(self.config_dir, member))
                envelope = create_group_control_message(self.identity, conversation, 'group_remove', create_group_remove_body([kid], reason))
                applied = receive_group_event(self.identity, envelope, state)
                group = applied['group']
                controls.append(envelope)
            if member is None:
                controls.append(prepare_group_session_rekey(self.identity, state)['rekey'])
            else:
                body, _ = create_rekey(self.identity, conversation, group, conversation['id'])
                controls.append(create_group_control_message(self.identity, conversation, 'group_rekey', body))
            # Verify every transition locally before saving or sending any part.
            trial = state
            for envelope in controls:
                trial = receive_group_event(self.identity, envelope, trial)['state']
            self._save_operation(record['id'], {'kind': 'remove' if member is not None else 'rekey',
                                                'controls': [base64.b64encode(serialize_envelope(e)).decode() for e in controls],
                                                'welcomes': [], 'welcomes_sent': 0, 'expected': trial})
            return self._resume(record['id'])

    def refresh(self, conversation_id, address, challenge=''):
        recovery_challenge = _recovery_challenge(challenge)
        key = resolve_contact(self.config_dir, address)
        record = self.enable(conversation_id)
        with self._operation_lock(record['id']):
            record = self.sync(record['id'])
            operation = prepare_group_welcome_refresh(self.identity, record['group_session'], [key], recovery_challenge=recovery_challenge)
            expected = create_group_session(self.identity, operation['conversation'], operation['state'],
                                            signed_epoch=record['group_session']['signedEpoch'])
            self._save_operation(record['id'], {'kind': 'refresh', 'controls': [],
                                                'welcomes': [base64.b64encode(serialize_envelope(w)).decode() for w in operation['welcomes']],
                                                'welcomes_sent': 0, 'expected': expected})
            return self._resume(record['id'])

    def retry(self, conversation_id):
        _, record = self._load(conversation_id)
        with self._operation_lock(record['id']):
            return self._resume(record['id'])

    def link(self, conversation_id):
        _, record = self._load(conversation_id)
        return {'conversation_id': record['id'],
                'group_link': create_group_link(bytes.fromhex(record['id']), self.identity['publicKey'], self.relay_url)}

    def _resume(self, conversation_id):
        record = self.sync(conversation_id)
        operation = record.get('group_operation')
        if not operation:
            raise ValueError('No pending group operation')
        if record['group_session'].get('recovery'):
            raise ValueError('Group history is incomplete; open a fresh welcome from a current member before retrying')
        for encoded in operation['controls']:
            wire = base64.b64decode(encoded, validate=True)
            envelope = deserialize_envelope(wire)
            state = record['group_session']
            known = state['seen'].get(envelope['msg_id'].hex())
            if not known:
                receive_group_event(self.identity, envelope, state)  # preflight against the latest accepted state
                cli._http_send(self.relay_url, conversation_id, wire)
            elif known['digest'] != _suite.hash(wire).hex():
                raise ValueError('Pending group message conflicts with accepted state')
            record = self.sync(conversation_id)
            if record['group_session']['seen'].get(envelope['msg_id'].hex(), {}).get('digest') != _suite.hash(wire).hex():
                raise ValueError('Group control is not yet verified in relay replay; use group retry')
        if operation['kind'] == 'add':
            prepared = {'conversation': group_session_conversation(operation['expected']), 'state': _group(operation['expected']),
                        'addition': deserialize_envelope(base64.b64decode(operation['controls'][0])),
                        'rekey': deserialize_envelope(base64.b64decode(operation['controls'][1]))}
            assert_group_addition_accepted(self.identity, record['group_session'], prepared)
        elif operation['kind'] == 'refresh':
            prepared = {'conversation': group_session_conversation(operation['expected']), 'state': _group(operation['expected']),
                        'welcomes': [deserialize_envelope(base64.b64decode(w)) for w in operation['welcomes']]}
            assert_group_welcome_refresh_current(self.identity, record['group_session'], prepared)
        for position in range(operation['welcomes_sent'], len(operation['welcomes'])):
            receipt = cli._http_send(self.relay_url, conversation_id, base64.b64decode(operation['welcomes'][position], validate=True))
            with self._lock():
                records, record = self._load(conversation_id)
                record['group_operation']['welcomes_sent'] = position + 1
                # Own welcome receipts can fill a future retention hole without
                # treating an unknown missing membership control as harmless.
                seq = receipt.get('seq')
                if type(seq) is int and seq > record.get('group_cursor', 0):
                    record.setdefault('group_delivery_receipts', []).append(seq)
                cli._save_conversations(self.config_dir, records)
        with self._lock():
            records, record = self._load(conversation_id)
            record.pop('group_operation')
            cli._save_conversations(self.config_dir, records)
        return {'conversation_id': conversation_id, 'current_epoch': record['current_epoch'], 'members': len(record['participants']),
                'group_link': create_group_link(bytes.fromhex(conversation_id), self.identity['publicKey'], self.relay_url),
                **({'added_key_id': operation['member']} if 'member' in operation else {})}


def join(config_dir, identity, link, name=''):
    locator = parse_group_link(link)
    conversation_id, relay = locator['conversation_id'].hex(), locator['relay_url']
    raw, head = cli._recv_once(relay, conversation_id, 0)
    candidates = []
    for row in raw:
        try:
            welcome = open_group_welcome(identity, base64.b64decode(row['envelope_b64'], validate=True),
                                         conversation_id=locator['conversation_id'], inviter_public_key=locator['inviter_public_key'])
            candidates.append((welcome, row['seq']))
        except Exception:
            continue
    # At a given epoch, a later refresh is the inviter's latest signed current
    # snapshot. Addition-only candidates retain the canonical rekey-ID order.
    candidates.sort(key=lambda candidate: (-candidate[0]['conversation']['currentEpoch'],
                    0 if candidate[0]['purpose'] == 'refresh' else 1,
                    -candidate[1] if candidate[0]['purpose'] == 'refresh' else candidate[0]['rekey_id']))
    with private_lock(os.path.join(config_dir, 'receive.lock')):
        records = cli._load_conversations(config_dir)
        previous = cli._find_conversation(records, conversation_id)
        saved = None
        if previous:
            if previous.get('type') != 'group' or previous.get('gateway') or previous.get('relay_url', relay).rstrip('/') != relay:
                raise ValueError('Group link conflicts with the saved conversation')
            saved = previous.get('group_session')
            if saved:
                # Existing keys can often catch up directly. Persist any detected
                # recovery requirement even if no usable welcome remains.
                updated, _ = receive_batch(previous, identity, raw, head)
                records[records.index(previous)] = updated
                cli._save_conversations(config_dir, records)
                previous = updated
                saved = restore_group_session(identity, updated['group_session'])
                if not saved['removed'] and not saved['needsRekey'] and not saved['recovery']:
                    return {'conversation_id': conversation_id, 'current_epoch': saved['epoch'], 'removed': False}
        if saved and saved['recovery']:
            challenge = bytes.fromhex(saved['recovery']['challenge'])
            candidates = [candidate for candidate in candidates
                          if candidate[0].get('recovery_challenge') == challenge
                          and candidate[1] > saved['recovery']['afterSequence']]
            if not candidates:
                raise ValueError('No welcome answers the current recovery challenge; use recv to retrieve it and ask a current member for group refresh --challenge')
        if not candidates:
            raise ValueError('No current welcome for this identity; ask the contact to add or welcome this identity')
        welcome, welcome_sequence = candidates[0]
        if previous:
            if not saved and (welcome['conversation']['currentEpoch'] < previous.get('current_epoch', 0)
                              or welcome['conversation']['currentEpoch'] == previous.get('current_epoch', 0)
                              and welcome['conversation']['keys']['root'].hex() != previous['keys']['root']):
                raise ValueError('Welcome is older than or conflicts with saved group state')
            if saved:
                if saved['removed'] and welcome['purpose'] == 'refresh':
                    readmissions = [candidate for candidate in candidates if candidate[0]['purpose'] == 'addition'
                                    and candidate[0]['conversation']['currentEpoch'] > saved['epoch']
                                    and candidate[1] > previous.get('group_removed_sequence', 0)]
                    if not readmissions:
                        raise ValueError('A welcome refresh cannot undo saved removal; a new admission welcome is required')
                    welcome, welcome_sequence = readmissions[0]
                if saved['removed'] and welcome_sequence <= previous.get('group_removed_sequence', 0):
                    raise ValueError('Welcome predates the saved removal')
        record = {'id': conversation_id, 'type': 'group', 'name': name or welcome['state'].group_name,
                  'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'relay_url': relay,
                  'group_cursor': welcome_sequence, 'group_bootstrap_sequence': welcome_sequence,
                  'group_pending': [], 'group_history': copy.deepcopy(cli._load_history(config_dir, conversation_id)) if previous else [],
                  'inviter_public_key': locator['inviter_public_key'].hex()}
        if previous and 'group_revision' in previous:
            record['group_revision'] = previous['group_revision']
        if previous and previous.get('group_operation'):
            record['group_operation'] = copy.deepcopy(previous['group_operation'])
        _install(record, group_session_from_welcome(identity, welcome, welcome_sequence, saved))
        record, _ = receive_batch(record, identity, raw, head)
        if previous:
            records[records.index(previous)] = record
        else:
            records.append(record)
        cli._save_conversations(config_dir, records)
    return {'conversation_id': conversation_id, 'name': record['name'], 'type': 'group',
            'current_epoch': record['current_epoch'], 'participants': len(record['participants']),
            'removed': record['group_session']['removed'], 'recovery_required': bool(record['group_session'].get('recovery'))}
