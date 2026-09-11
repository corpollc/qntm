"""Bridge authenticated gateway invitations to private group control state.

The gateway remains a delegated executor, never a roster member or creator.
Call acceptance only after the existing exact invitation/acceptance verification.
"""
from .identity import base64url_decode, base64url_encode, key_id_from_public_key
from .ed25519 import is_valid_ed25519_public_key
from .group_session import state_for_record, save_state


def accept_gateway_membership(record, invite, inviter_key_id, invitation_message_id):
    if record.get('type') != 'group':
        return None
    state = state_for_record(record)
    if any(record.get(flag) for flag in ('needs_rekey', 'pending_control', 'excluded', 'recovery_required')):
        return None
    if state.creator is None:
        return None
    if invite.get('conv_id') != record['id'] or invite.get('conv_epoch') != record.get('current_epoch', 0):
        raise ValueError('Gateway invitation has the wrong group context')
    participants = invite.get('participants')
    if not isinstance(participants, dict) or not 1 <= len(participants) <= 128:
        raise ValueError('Invalid gateway participant roster')
    members = []
    for kid, public_key in participants.items():
        public = base64url_decode(public_key)
        key = key_id_from_public_key(public)
        if (not is_valid_ed25519_public_key(public) or base64url_encode(public) != public_key
                or base64url_encode(key) != kid or kid == invite['gateway_kid']):
            raise ValueError('Invalid gateway participant key')
        members.append({'key_id': key, 'public_key': public, 'role': 'member',
                        'added_at': state.created_at, 'added_by': inviter_key_id})
    keys = {member['key_id'] for member in members}
    if state.creator not in keys or inviter_key_id not in keys:
        raise ValueError('Gateway roster must retain the creator and inviting participant')
    legacy = record.get('current_epoch', 0) == 0 and not record.get('group_checkpoint')
    if not legacy and not state.is_admin(inviter_key_id):
        # API acceptance is distinct from permission to change a strict roster.
        return None
    if not legacy and keys != set(state.list_members()):
        raise ValueError('Gateway invitation differs from the current authenticated roster')
    if not state.is_admin(inviter_key_id):
        return None
    if legacy:
        # An administrator-signed invitation asserts the gateway's initial participant
        # roster. Preserve existing roles; never infer a new administrator.
        if not set(state.list_members()).issubset(keys):
            raise ValueError('Gateway invitation omits an existing group member')
        state.apply_add({'new_members': [member for member in members if not state.is_member(member['key_id'])]})
        save_state(record, state)
    return {'invitation_message_id': invitation_message_id, 'creator_key_id': state.creator.hex()}


def control_delegate(record):
    gateway = record.get('gateway') or {}
    authority = gateway.get('membership_authority') or {}
    state = state_for_record(record)
    if (gateway.get('status') != 'active' or not authority.get('invitation_message_id')
            or state.creator is None or authority.get('creator_key_id') != state.creator.hex()):
        return None
    try:
        public = base64url_decode(gateway['publicKey'])
        if (is_valid_ed25519_public_key(public) and base64url_encode(public) == gateway['publicKey']
                and base64url_encode(key_id_from_public_key(public)) == gateway['keyId']):
            return public
    except (ValueError, KeyError, TypeError):
        pass
    return None


def _verified_votes(record, history, before_sequence):
    """Reverify original ciphertexts in relay order, not cached body/verified flags."""
    import base64
    import json
    from .message import deserialize_envelope, decrypt_message
    from .group_session import crypto
    if type(before_sequence) is not int or before_sequence < 1 or len(history) > 10000:
        return []
    events, seen = [], set()
    for row in sorted((row for row in history if isinstance(row, dict) and type(row.get('sequence')) is int), key=lambda row: row['sequence']):
        sequence = row.get('sequence')
        encoded = row.get('gateway_envelope_b64')
        if type(sequence) is not int or not 0 < sequence < before_sequence or not isinstance(encoded, str) or len(encoded) > 87384:
            continue
        try:
            envelope = deserialize_envelope(base64.b64decode(encoded, validate=True))
            if envelope['conv_epoch'] != record.get('current_epoch', 0) or envelope['msg_id'] in seen:
                continue
            # These ciphertexts already passed live receive. A retained withdrawal
            # must not disappear merely because its transport TTL has elapsed.
            message = decrypt_message(envelope, crypto(record), allow_expired=True)
            if not message['verified'] or message['inner']['body_type'] not in ('gov.propose', 'gov.approve', 'gov.disapprove'):
                continue
            body = json.loads(message['inner']['body'])
            if (not isinstance(body, dict) or not all(isinstance(body.get(key), str) for key in ('type', 'proposal_id', 'conv_id', 'gateway_kid', 'signer_kid'))
                    or body.get('type') != message['inner']['body_type'] or body.get('conv_id') != record['id']
                    or body.get('gateway_kid') != record['gateway']['keyId']
                    or body.get('signer_kid') != base64url_encode(message['inner']['sender_kid'])):
                continue
            seen.add(envelope['msg_id']); events.append((body, message['inner']['sender_ik_pk']))
        except (ValueError, KeyError, TypeError):
            continue
    return events


def _approved_membership(record, control, events, at):
    import cbor2
    from datetime import datetime
    from .crypto import QSP1Suite
    from .cbor import marshal_canonical
    from .governance import _proposal_signable_map
    suite = QSP1Suite()
    state = state_for_record(record)
    legacy = record.get('current_epoch', 0) == 0 and not record.get('group_checkpoint')
    public_keys = record['gateway'].get('membership_offer') if legacy else {
        base64url_encode(kid): base64url_encode(member['public_key']) for kid, member in state.members.items()}
    if not isinstance(public_keys, dict) or not 1 <= len(public_keys) <= 128:
        return None
    try:
        keys = {kid: base64url_decode(public) for kid, public in public_keys.items()}
        if any(not is_valid_ed25519_public_key(public) or base64url_encode(key_id_from_public_key(public)) != kid for kid, public in keys.items()):
            return None
        if not {base64url_encode(kid) for kid in state.list_members()}.issubset(keys) or record['gateway']['keyId'] in keys:
            return None
    except (ValueError, TypeError):
        return None
    for index, (proposal, public) in enumerate(events):
        try:
            if proposal['type'] != 'gov.propose' or proposal.get('proposal_id') in record.get('used_governed_membership', []):
                continue
            kind = proposal.get('proposal_type')
            if kind == 'member_add' and 'new_members' in control:
                actual = sorted((base64url_encode(member['key_id']), base64url_encode(member['public_key'])) for member in control['new_members'])
                wanted = sorted((member['kid'], member['public_key']) for member in proposal['proposed_members'])
                if actual != wanted or any(member['role'] != 'member' or member['key_id'] == key_id_from_public_key(base64url_decode(record['gateway']['publicKey'])) for member in control['new_members']):
                    continue
            elif kind == 'member_remove' and 'removed_members' in control:
                if sorted(base64url_encode(kid) for kid in control['removed_members']) != sorted(proposal['removed_member_kids']) or state.creator in control['removed_members']:
                    continue
            else:
                continue
            eligible = proposal['eligible_signer_kids']
            if not isinstance(eligible, list) or len(eligible) != len(keys) or set(eligible) != set(keys):
                continue
            required = proposal['required_approvals']
            if type(required) is not int or not 1 <= required <= len(keys):
                continue
            if not isinstance(proposal.get('expires_at'), str):
                continue
            expiry_time = datetime.fromisoformat(proposal['expires_at'].replace('Z', '+00:00'))
            if expiry_time.tzinfo is None:
                continue
            expires = int(expiry_time.timestamp())
            if at >= expires:
                continue
            signable = _proposal_signable_map(conv_id=record['id'], proposal_id=proposal['proposal_id'], proposal_type=kind,
                proposed_floor=proposal.get('proposed_floor', cbor2.undefined), proposed_rules=proposal.get('proposed_rules', cbor2.undefined),
                proposed_members=proposal.get('proposed_members', cbor2.undefined), removed_member_kids=proposal.get('removed_member_kids', cbor2.undefined),
                eligible_signer_kids=eligible, required_approvals=required, expires_at_unix=expires, gateway_kid=record['gateway']['keyId'])
            signer = proposal['signer_kid']
            if keys.get(signer) != public or not suite.verify(public, marshal_canonical(signable), base64url_decode(proposal['signature'])):
                continue
            digest = suite.hash(marshal_canonical(signable))
            votes = {signer: True}
            for vote, vote_public in events[index + 1:]:
                # A proposal is immutable once its exact signed hash is selected.
                # Later proposal messages are not votes; only approvals bound to
                # this hash, and authenticated withdrawals, update its tally.
                if vote.get('proposal_id') != proposal['proposal_id'] or vote['type'] == 'gov.propose':
                    continue
                voter = vote['signer_kid']
                if keys.get(voter) != vote_public:
                    continue
                if vote['type'] == 'gov.disapprove':
                    votes[voter] = False
                elif vote['type'] == 'gov.approve':
                    try:
                        if suite.verify(vote_public, marshal_canonical({
                                'conv_id': record['id'], 'proposal_id': proposal['proposal_id'], 'proposal_hash': digest}), base64url_decode(vote['signature'])):
                            votes[voter] = True
                    except (ValueError, KeyError, TypeError):
                        continue
            admins = {base64url_encode(kid) for kid in state.list_admins()}
            if sum(votes.values()) < max(required, len(keys) // 2 + 1) or not any(votes.get(admin) for admin in admins):
                continue
            # The administrator's signature binds this exact proposal, roster
            # and approval threshold. It does not appoint the gateway as admin.
            missing = [{'key_id': key_id_from_public_key(public), 'public_key': public, 'role': 'member',
                        'added_at': at, 'added_by': state.creator} for public in keys.values() if not state.is_member(key_id_from_public_key(public))]
            state.apply_add({'new_members': missing})
            return proposal['proposal_id'], state
        except (ValueError, KeyError, TypeError, OverflowError):
            continue
    return None


def prepare_gateway_control(record, envelope, message, history, sequence):
    """Prepare a copy of local state; caller commits it only after control validation."""
    from .cbor import unmarshal
    import time
    delegate = control_delegate(record)
    if delegate is not None:
        return delegate
    gateway = record.get('gateway') or {}
    try:
        public = base64url_decode(gateway['publicKey'])
        if (gateway.get('status') != 'active' or not is_valid_ed25519_public_key(public)
                or base64url_encode(public) != gateway['publicKey']
                or base64url_encode(key_id_from_public_key(public)) != gateway['keyId']):
            return None
    except (ValueError, KeyError, TypeError):
        return None
    epoch = record.get('current_epoch', 0)
    pending = record.get('pending_governed_membership')
    kind = message['inner']['body_type']
    if kind == 'group_rekey':
        # Snapshot every authorized signer at this source transition, even when
        # an ordinary member's rekey arrives first. A delayed lower gateway rekey
        # must be judged against the same source authorization after rotation.
        return public if pending and pending['epoch'] == envelope['conv_epoch'] == epoch and pending['gateway_public_key'] == public.hex() else None
    if message['inner']['sender_ik_pk'] != public:
        return None
    if kind not in ('group_add', 'group_remove') or pending or any(record.get(flag) for flag in ('needs_rekey', 'excluded', 'recovery_required')):
        return None
    approved = _approved_membership(record, unmarshal(message['inner']['body']), _verified_votes(record, history, sequence), int(time.time()))
    if approved is None:
        return None
    proposal_id, state = approved
    save_state(record, state)
    record.setdefault('used_governed_membership', []).append(proposal_id)
    record['pending_governed_membership'] = {'proposal_id': proposal_id, 'epoch': epoch, 'gateway_public_key': public.hex()}
    return public
