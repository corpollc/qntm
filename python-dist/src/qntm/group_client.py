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
from .cbor import unmarshal, marshal_canonical
from .crypto import QSP1Suite
from .ed25519 import is_valid_ed25519_public_key
from .group import GroupState, create_group_remove_body, create_rekey, create_group_genesis_body, parse_group_genesis_body
from .group_link import create_group_link, parse_group_link
from .group_session import (
    create_group_session, restore_group_session, receive_group_event, group_session_conversation,
    prepare_group_session_addition, assert_group_addition_accepted, assert_group_can_send,
    prepare_group_welcome_refresh, assert_group_welcome_refresh_current, prepare_group_session_rekey,
    check_group_replay_coverage, check_group_welcome_replay, check_group_unverifiable_epoch, check_expired_group_control, group_session_from_welcome,
    create_group_control_message,
    prepare_group_admission_renewal, assert_group_admission_renewal_current,
)
from .group_welcome import open_group_welcome, is_group_welcome_envelope
from .identity import base64url_decode, key_id_from_public_key
from .message import deserialize_envelope, serialize_envelope, decrypt_message
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
             'sequence': sequence, 'receive_order': order, 'receive_event': create_receive_event(message, sequence),
             'receive_binding': {'digest': _suite.hash(serialize_envelope(envelope)).hex(),
                                 'epoch': envelope['conv_epoch'], 'valid': True}}
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


def _creation_message(identity, record, envelope):
    """Recognize only the exact locally prepared genesis, never a new genesis."""
    operation = record.get('group_operation') or {}
    wire = serialize_envelope(envelope)
    if operation.get('kind') != 'create' or operation.get('controls') != [base64.b64encode(wire).decode()]:
        return None
    state = record['group_session']
    message = decrypt_message(envelope, group_session_conversation(state))
    body = unmarshal(message['inner']['body'])
    if (message['inner']['body_type'] != 'group_genesis' or message['inner']['sender_kid'] != identity['keyID']
            or state['epoch'] != 0 or not isinstance(body, dict) or type(body.get('group_epoch')) is not int
            or body['group_epoch'] != 0 or {key: value for key, value in body.items() if key != 'group_epoch'} != _group(state).snapshot()):
        raise ValueError('Saved creation differs from its local group state')
    return message


def receive_batch(record, identity, raw_messages, head, *, bootstrap=False):
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
    retained_wires = {row['envelope_b64'] for row in result.get('group_pending', [])}
    creation = result.get('group_operation') or {}
    for raw in [*result.get('group_pending', []), *raw_messages]:
        try:
            sequence = raw['seq']
            if type(sequence) is not int or sequence <= 0:
                continue
            wire = base64.b64decode(raw['envelope_b64'], validate=True)
            if (not bootstrap and sequence <= floor and raw['envelope_b64'] not in retained_wires
                    and not (creation.get('kind') == 'create' and raw['envelope_b64'] in creation.get('controls', []))):
                continue
            envelope = deserialize_envelope(wire)
            if (type(envelope.get('expiry_ts')) is not int or type(envelope.get('conv_epoch')) is not int
                    or not isinstance(envelope.get('msg_id'), bytes) or len(envelope['msg_id']) != 16):
                continue
            if envelope['conv_id'].hex() != result['id'] or is_group_welcome_envelope(envelope):
                continue
            if bootstrap and envelope['conv_epoch'] < state['epoch']:
                # The welcome preflight already checked exact signed hashes and
                # the trusted anchor. Never retain pre-admission ciphertext as
                # if fetching its older keys were a recovery strategy.
                continue
            # Key by exact bytes: conflicting IDs must still reach the reducer.
            pending[_suite.hash(wire).hex()] = {'seq': sequence, 'envelope_b64': base64.b64encode(wire).decode()}
        except (ValueError, TypeError, KeyError):
            continue
    if not bootstrap:
        for raw in sorted(pending.values(), key=lambda row: row['seq']):
            state = check_group_unverifiable_epoch(state, deserialize_envelope(base64.b64decode(raw['envelope_b64'])), raw['seq'])
    output = []
    remaining = sorted(pending.values(), key=lambda row: row['seq'])
    while remaining:
        retry, changed = [], False
        for raw in remaining:
            envelope = deserialize_envelope(base64.b64decode(raw['envelope_b64']))
            if envelope['expiry_ts'] < int(time.time()):
                # A control can race ahead of a welcome's POST. Its source epoch
                # still matters even when its relay sequence precedes that welcome.
                state = check_expired_group_control(identity, state, envelope, raw['seq'])
                if envelope['conv_epoch'] > state['epoch'] and not state['recovery'] and not state['removed']:
                    retry.append(raw)
                continue
            if state['recovery']:
                continue
            try:
                creation = _creation_message(identity, {**result, 'group_session': state}, envelope)
                if creation:
                    mid = envelope['msg_id'].hex()
                    event = {'state': state, 'duplicate': mid in state['seen'], 'message': creation}
                    state['seen'][mid] = {'digest': _suite.hash(serialize_envelope(envelope)).hex(), 'epoch': 0}
                else:
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
            if event.get('rewound'):
                superseded = {frame['messageId'] for frame in state['rekeys'] if frame['epoch'] >= envelope['conv_epoch']}
                for entry in history:
                    binding = entry.get('receive_binding')
                    if binding and (binding['epoch'] > envelope['conv_epoch'] or entry['msg_id'] in superseded):
                        binding['valid'] = False
            state = event['state']
            if event['duplicate']:
                continue
            changed = True
            message = event['message']
            if state['removed']:
                result['group_removed_sequence'] = max(result.get('group_removed_sequence', 0), raw['seq'])
            mid = envelope['msg_id'].hex()
            previous_entry = known_history.get(mid)
            digest = _suite.hash(serialize_envelope(envelope)).hex()
            if (previous_entry is None or 'receive_event' not in previous_entry
                    or previous_entry.get('receive_binding', {}).get('digest') != digest
                    or not previous_entry.get('receive_binding', {}).get('valid')):
                order = max(order + 1, raw['seq'])
                entry = _history_entry(message, raw['seq'], order)
                if previous_entry is None:
                    history.append(entry)
                    known_history[mid] = entry
                else:
                    # A sent message already has a local history row, but its
                    # verified relay echo must still reach --include-self hooks.
                    if 'receive_event' in previous_entry:
                        previous_entry.clear()
                    previous_entry.update(entry)
                output.append((mid, digest, {'conversation_id': result['id'], 'message_id': mid, 'sender': entry['sender_kid'][:3],
                               **{key: value for key, value in entry.items() if key not in {'msg_id', 'direction', 'receive_event', 'receive_order', 'receive_binding'}}}))
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
    return result, ([] if state['recovery'] else [row for mid, digest, row in output
        if known_history[mid].get('receive_binding', {}).get('valid')
        and known_history[mid]['receive_binding']['digest'] == digest])


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
                from .legacy_group import assert_creation_complete
                assert_creation_complete(self.config_dir, record['id'])
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
        # An acknowledged genesis can be missing from a prior replay. Retain the
        # initial cursor until its exact bytes have actually been observed.
        pending_creation = (record.get('group_operation') or {}).get('kind') == 'create'
        raw, head = cli._recv_once(self.relay_url, record['id'], 0 if pending_creation else record.get('group_cursor', 0))
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

    def create(self, name, description=''):
        """Persist a new contact group and its exact genesis before any network write."""
        invite = cli.create_invite(self.identity, 'group')
        conversation = cli.create_conversation(invite, cli.derive_conversation_keys(invite))
        body = create_group_genesis_body(name, description, self.identity, [])
        group = GroupState()
        group.apply_genesis(parse_group_genesis_body(body))
        conversation['participants'] = group.list_members()
        state = create_group_session(self.identity, conversation, group)
        genesis = create_group_control_message(self.identity, conversation, 'group_genesis', body)
        cid = conversation['id'].hex()
        record = {'id': cid, 'type': 'group', 'name': name, 'relay_url': self.relay_url,
                  'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  'group_cursor': 0, 'group_pending': [], 'group_history': [],
                  'group_operation': {'kind': 'create', 'controls': [base64.b64encode(serialize_envelope(genesis)).decode()],
                                      'welcomes': [], 'welcomes_sent': 0, 'expected': state}}
        _install(record, state)
        with self._operation_lock(cid):
            with self._lock():
                records = cli._load_conversations(self.config_dir)
                records.append(record)
                cli._save_conversations(self.config_dir, records)
            result = self._resume(cid)
        return {**result, 'type': 'group', 'name': name}

    def add(self, conversation_id, address, challenge=''):
        recovery_challenge = _recovery_challenge(challenge)
        key = resolve_contact(self.config_dir, address)
        record = self.enable(conversation_id)
        with self._operation_lock(record['id']):
            record = self.sync(record['id'])
            if record.get('group_operation'):
                raise ValueError('A group operation is pending; use group retry')
            operation = prepare_group_session_addition(self.identity, record['group_session'], [key],
                recovery_challenge=recovery_challenge, replay_from_sequence=record.get('group_cursor', 0))
            expected = create_group_session(self.identity, operation['conversation'], operation['state'], signed_epoch=record['group_session']['signedEpoch'])
            self._save_operation(record['id'], {'kind': 'add', 'controls': [base64.b64encode(serialize_envelope(operation[name])).decode() for name in ('addition', 'rekey')],
                                                'welcomes': [base64.b64encode(serialize_envelope(w)).decode() for w in operation['welcomes']],
                                                'expected': expected, 'welcomes_sent': 0, 'member': key_id_from_public_key(key).hex(),
                                                'recovery_challenge': recovery_challenge.hex() if recovery_challenge else None})
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
            state = restore_group_session(self.identity, record['group_session'])
            admission = state['admissions'].get(key_id_from_public_key(key).hex())
            if admission and admission['completion']:
                operation = prepare_group_admission_renewal(self.identity, state, key,
                    {name: admission[name] for name in ('addId', 'addDigest')},
                    recovery_challenge=recovery_challenge, replay_from_sequence=record.get('group_cursor', 0))
            else:
                operation = prepare_group_welcome_refresh(self.identity, state, [key],
                    recovery_challenge=recovery_challenge, replay_from_sequence=record.get('group_cursor', 0))
            expected = create_group_session(self.identity, operation['conversation'], operation['state'],
                                            signed_epoch=state['signedEpoch'], admissions=state['admissions'])
            self._save_operation(record['id'], {'kind': 'renewal' if admission and admission['completion'] else 'refresh', 'controls': [],
                                                'welcomes': [base64.b64encode(serialize_envelope(w)).decode() for w in operation['welcomes']],
                                                'welcomes_sent': 0, 'expected': expected,
                                                **({'recipient': key.hex(), 'admission': copy.deepcopy(admission),
                                                    'recovery_challenge': recovery_challenge.hex() if recovery_challenge else None}
                                                   if admission and admission['completion'] else {})})
            return self._resume(record['id'])

    def retry(self, conversation_id):
        from .legacy_group import has_creation, retry
        record = cli._resolve_conversation(cli._load_conversations(self.config_dir), conversation_id)
        if record and record.get('type') == 'group' and not record.get('group_session') and has_creation(self.config_dir, record['id']):
            return retry(self.config_dir, self.identity, self.relay_url, record['id'])
        _, record = self._load(conversation_id)
        with self._operation_lock(record['id']):
            return self._resume(record['id'], reconcile=True)

    def _addition_proof(self, record, operation):
        """Compare an original local intent with accepted, source-bound evidence."""
        wire = base64.b64decode(operation['controls'][0], validate=True)
        addition = deserialize_envelope(wire)
        if serialize_envelope(addition) != wire or addition['conv_id'].hex() != record['id']:
            raise ValueError('Invalid saved addition context')
        expected = {'addId': addition['msg_id'].hex(), 'addDigest': _suite.hash(wire).hex()}
        state = restore_group_session(self.identity, record['group_session'])
        admission = state['admissions'].get(operation['member'])
        if not admission or any(admission[key] != value for key, value in expected.items()):
            return None
        recipient = next((member['public_key'] for member in _group(operation['expected']).snapshot()['founding_members']
                          if member['key_id'].hex() == operation['member']), None)
        if recipient is None:
            raise ValueError('Saved addition omits its intended recipient')
        return state, recipient, expected, admission

    def _addition_challenge(self, operation, recipient):
        """Older draft journals kept their optional challenge only in the box."""
        if 'recovery_challenge' in operation:
            value = operation['recovery_challenge']
            return None if value is None else _recovery_challenge(value)
        from .gate import open_secret
        envelope = deserialize_envelope(base64.b64decode(operation['welcomes'][0], validate=True))
        plain = open_secret(self.identity['privateKey'], recipient, envelope['ciphertext'])
        signed = unmarshal(plain)
        payload = signed['payload']
        addition = deserialize_envelope(base64.b64decode(operation['controls'][0], validate=True))
        rekey = deserialize_envelope(base64.b64decode(operation['controls'][1], validate=True))
        if (plain != marshal_canonical(signed) or payload['inviter_ik_pk'] != self.identity['publicKey']
                or payload['recipient_ik_pk'] != recipient or payload['proto'] != 'qntm/group-welcome/v1'
                or envelope['conv_id'] != addition['conv_id'] or payload['addition_id'] != addition['msg_id']
                or payload['rekey_id'] != rekey['msg_id']
                or marshal_canonical(payload['envelope']) != marshal_canonical({key: value for key, value in envelope.items() if key != 'ciphertext'})
                or not _suite.verify(self.identity['publicKey'], marshal_canonical(payload), signed['signature'])):
            raise ValueError('Invalid saved welcome challenge binding')
        challenge = payload.get('recovery_challenge')
        if challenge is not None and (not isinstance(challenge, bytes) or len(challenge) != 32):
            raise ValueError('Invalid saved welcome recovery challenge')
        return challenge

    def _prepared_welcome(self, operation):
        return {'conversation': group_session_conversation(operation['expected']), 'state': _group(operation['expected']),
                'welcomes': [deserialize_envelope(base64.b64decode(w, validate=True)) for w in operation['welcomes']]}

    def _assert_exact_addition_current(self, record, operation):
        proof = self._addition_proof(record, operation)
        if proof is None or proof[3]['completion'] is None:
            raise ValueError('Original addition is not the current accepted admission')
        wire = base64.b64decode(operation['controls'][1], validate=True)
        rekey = deserialize_envelope(wire)
        if proof[3]['completion'] != {'rekeyId': rekey['msg_id'].hex(), 'rekeyDigest': _suite.hash(wire).hex()}:
            raise ValueError('Original completing rekey is no longer canonical')
        assert_group_welcome_refresh_current(self.identity, proof[0], self._prepared_welcome(operation))

    def _reconcile_addition(self, conversation_id, original):
        # The operation lock excludes other producers; receive.lock additionally
        # excludes resident receive while comparing and replacing the journal.
        with self._lock():
            records, record = self._load(conversation_id)
            if marshal_canonical(record.get('group_operation')) != marshal_canonical(original):
                raise ValueError('Pending operation changed before reconciliation; use group retry')
            proof = self._addition_proof(record, original)
            if proof is None:
                source = deserialize_envelope(base64.b64decode(original['controls'][0], validate=True))['conv_epoch']
                if record['group_session']['epoch'] > source or original['member'] in record['group_session'].get('admissions', {}):
                    raise ValueError('Original addition is no longer the accepted admission; operation preserved')
                return record, False
            if proof[3]['completion'] is None:
                return record, False  # Exact rotation retry remains available; expired rotation stays blocked.
            state, recipient, expected, _ = proof
            assert_group_can_send(self.identity, state)
            try:
                self._assert_exact_addition_current(record, original)
                return record, True
            except ValueError:
                pass
            challenge = self._addition_challenge(original, recipient)
            renewed = prepare_group_admission_renewal(self.identity, state, recipient, expected,
                                                       recovery_challenge=challenge, replay_from_sequence=record.get('group_cursor', 0))
            # Retain original ciphertext and delivery uncertainty once, without
            # nesting checkpoints or duplicating obsolete plaintext group roots.
            origin = {key: copy.deepcopy(original[key]) for key in ('kind', 'controls', 'welcomes', 'welcomes_sent', 'member')}
            origin.update(admission=expected, recipient=recipient.hex(), delivery='unknown')
            record['group_operation'] = {'kind': 'renewal', 'controls': [],
                'welcomes': [base64.b64encode(serialize_envelope(w)).decode() for w in renewed['welcomes']], 'welcomes_sent': 0,
                'expected': create_group_session(self.identity, renewed['conversation'], renewed['state'],
                                                signed_epoch=state['signedEpoch'], admissions=renewed['admissions']),
                'member': original['member'], 'recipient': recipient.hex(), 'admission': renewed['admission'],
                'recovery_challenge': challenge.hex() if challenge else None, 'origin': origin}
            cli._save_conversations(self.config_dir, records)
            return record, False

    def link(self, conversation_id):
        _, record = self._load(conversation_id)
        return {'conversation_id': record['id'],
                'group_link': create_group_link(bytes.fromhex(record['id']), self.identity['publicKey'], self.relay_url)}

    def _resume(self, conversation_id, *, reconcile=False):
        record = self.sync(conversation_id)
        operation = record.get('group_operation')
        if not operation:
            raise ValueError('No pending group operation')
        if (operation.get('welcomes') and type(operation.get('welcomes_sent')) is int
                and operation['welcomes_sent'] == len(operation['welcomes'])):
            return self._finish_operation(conversation_id, operation)
        if record['group_session'].get('recovery'):
            raise ValueError('Group history is incomplete; open a fresh welcome from a current member before retrying')
        exact_addition_proof = False
        if reconcile and operation['kind'] == 'add':
            record, exact_addition_proof = self._reconcile_addition(conversation_id, operation)
            operation = record['group_operation']
        for encoded in ([] if exact_addition_proof else operation['controls']):
            wire = base64.b64decode(encoded, validate=True)
            envelope = deserialize_envelope(wire)
            state = record['group_session']
            known = state['seen'].get(envelope['msg_id'].hex())
            if not known:
                if operation['kind'] == 'create':
                    if not _creation_message(self.identity, record, envelope):
                        raise ValueError('Invalid saved group creation')
                else:
                    receive_group_event(self.identity, envelope, state)  # preflight against the latest accepted state
                receipt = cli._http_send(self.relay_url, conversation_id, wire)
                if operation['kind'] == 'create':
                    with self._lock():
                        records, record = self._load(conversation_id)
                        seq = receipt.get('seq')
                        if type(seq) is int and seq > record.get('group_cursor', 0):
                            record.setdefault('group_delivery_receipts', []).append(seq)
                        cli._save_conversations(self.config_dir, records)
            elif known['digest'] != _suite.hash(wire).hex():
                raise ValueError('Pending group message conflicts with accepted state')
            record = self.sync(conversation_id)
            if record['group_session']['seen'].get(envelope['msg_id'].hex(), {}).get('digest') != _suite.hash(wire).hex():
                raise ValueError('Group control is not yet verified in relay replay; use group retry')
        if operation['kind'] == 'add' and not exact_addition_proof:
            prepared = {'conversation': group_session_conversation(operation['expected']), 'state': _group(operation['expected']),
                        'addition': deserialize_envelope(base64.b64decode(operation['controls'][0])),
                        'rekey': deserialize_envelope(base64.b64decode(operation['controls'][1]))}
            assert_group_addition_accepted(self.identity, record['group_session'], prepared)
        elif operation['kind'] == 'refresh':
            prepared = {'conversation': group_session_conversation(operation['expected']), 'state': _group(operation['expected']),
                        'welcomes': [deserialize_envelope(base64.b64decode(w)) for w in operation['welcomes']]}
            assert_group_welcome_refresh_current(self.identity, record['group_session'], prepared)
        for position in range(operation['welcomes_sent'], len(operation['welcomes'])):
            wire = base64.b64decode(operation['welcomes'][position], validate=True)
            if deserialize_envelope(wire)['expiry_ts'] < int(time.time()):
                raise ValueError('Saved welcome expired; preserve the operation for reconciliation')
            with self._lock():
                records, record = self._load(conversation_id)
                if marshal_canonical(record.get('group_operation')) != marshal_canonical(operation):
                    raise ValueError('Pending operation changed before welcome release; use group retry')
                if deserialize_envelope(wire)['expiry_ts'] < int(time.time()):
                    raise ValueError('Saved welcome expired while waiting to release; preserve the operation for reconciliation')
                if operation['kind'] == 'renewal':
                    prepared = {**self._prepared_welcome(operation), 'recipient': bytes.fromhex(operation['recipient']),
                                'admission': operation['admission'], 'admissions': operation['expected']['admissions']}
                    assert_group_admission_renewal_current(self.identity, record['group_session'], prepared)
                elif operation['kind'] == 'add' and exact_addition_proof:
                    self._assert_exact_addition_current(record, operation)
                elif operation['kind'] == 'add':
                    assert_group_addition_accepted(self.identity, record['group_session'], prepared)
                elif operation['kind'] == 'refresh':
                    assert_group_welcome_refresh_current(self.identity, record['group_session'], self._prepared_welcome(operation))
                receipt = cli._http_send(self.relay_url, conversation_id, wire)
                record['group_operation']['welcomes_sent'] = position + 1
                # Own welcome receipts can fill a future retention hole without
                # treating an unknown missing membership control as harmless.
                seq = receipt.get('seq')
                if type(seq) is int and seq > record.get('group_cursor', 0):
                    record.setdefault('group_delivery_receipts', []).append(seq)
                cli._save_conversations(self.config_dir, records)
                operation = copy.deepcopy(record['group_operation'])
        return self._finish_operation(conversation_id, operation)

    def _finish_operation(self, conversation_id, operation):
        with self._lock():
            records, record = self._load(conversation_id)
            if marshal_canonical(record.get('group_operation')) != marshal_canonical(operation):
                raise ValueError('Pending operation changed before completion; use group retry')
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
    # Fresh current-state attestations use relay order, never their historical
    # admission's completing rekey ID. Additions retain canonical rekey order.
    candidates.sort(key=lambda candidate: (-candidate[0]['conversation']['currentEpoch'],
                    1 if candidate[0]['purpose'] == 'addition' else 0,
                    candidate[0]['rekey_id'] if candidate[0]['purpose'] == 'addition' else -candidate[1]))
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
                if saved['removed']:
                    readmissions = []
                    for candidate, sequence in candidates:
                        if (candidate['purpose'] == 'refresh' or candidate['conversation']['currentEpoch'] <= saved['epoch']
                                or sequence <= previous.get('group_removed_sequence', 0)):
                            continue
                        try:
                            group_session_from_welcome(identity, candidate, sequence, saved)
                        except ValueError:
                            continue
                        readmissions.append((candidate, sequence))
                    if not readmissions:
                        raise ValueError('A welcome refresh cannot undo saved removal; a new admission or valid admission renewal is required')
                    welcome, welcome_sequence = readmissions[0]
                if saved['removed'] and welcome_sequence <= previous.get('group_removed_sequence', 0):
                    raise ValueError('Welcome predates the saved removal')
        record = {'id': conversation_id, 'type': 'group', 'name': name or welcome['state'].group_name,
                  'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'relay_url': relay,
                  'group_cursor': welcome['replay_from_sequence'], 'group_bootstrap_sequence': welcome_sequence,
                  'group_pending': [], 'group_history': copy.deepcopy(cli._load_history(config_dir, conversation_id)) if previous else [],
                  'inviter_public_key': locator['inviter_public_key'].hex()}
        # A fresh checkpoint establishes current authority, not the validity of
        # undelivered plaintext from the replaced checkpoint's branch.
        for entry in record['group_history']:
            if entry.get('receive_binding'):
                entry['receive_binding']['valid'] = False
        if previous and 'group_revision' in previous:
            record['group_revision'] = previous['group_revision']
        if previous and previous.get('group_operation'):
            record['group_operation'] = copy.deepcopy(previous['group_operation'])
        state = group_session_from_welcome(identity, welcome, welcome_sequence, saved)
        state = check_group_welcome_replay(state, welcome, head,
            [{'seq': row['seq'], 'envelope': base64.b64decode(row['envelope_b64'])} for row in raw])
        _install(record, state)
        record, _ = receive_batch(record, identity, raw, head, bootstrap=True)
        if previous:
            records[records.index(previous)] = record
        else:
            records.append(record)
        cli._save_conversations(config_dir, records)
    return {'conversation_id': conversation_id, 'name': record['name'], 'type': 'group',
            'current_epoch': record['current_epoch'], 'participants': len(record['participants']),
            'removed': record['group_session']['removed'], 'recovery_required': bool(record['group_session'].get('recovery'))}
