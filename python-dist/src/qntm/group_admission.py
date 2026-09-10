"""Bounded, local admission provenance and its signed welcome encoding.

This is a current member's attestation when carried in a pinned welcome. It is
not independently verifiable historical ciphertext or a grant of membership.
"""
import copy
import re


def _require(value):
    if not value:
        raise ValueError('Invalid group admission provenance')


def _hex(value, size):
    return isinstance(value, str) and len(value) == size * 2 and re.fullmatch('[0-9a-f]+', value) is not None


def validate_admissions(value, members, epoch, *, complete=False):
    """Copy a private JSON map; an absent member entry means unknown provenance."""
    _require(isinstance(value, dict) and len(value) <= 128)
    for kid, admission in value.items():
        _require(_hex(kid, 16) and kid in members and isinstance(admission, dict)
                 and set(admission) == {'addId', 'addDigest', 'sourceEpoch', 'completion'})
        source = admission['sourceEpoch']
        _require(_hex(admission['addId'], 16) and _hex(admission['addDigest'], 32)
                 and type(source) is int and 0 <= source <= min(epoch, 0xffffffff))
        completion = admission['completion']
        if completion is None:
            _require(not complete and source == epoch)
        else:
            _require(isinstance(completion, dict) and set(completion) == {'rekeyId', 'rekeyDigest'}
                     and _hex(completion['rekeyId'], 16) and _hex(completion['rekeyDigest'], 32)
                     and source < epoch)
    return copy.deepcopy(value)


def encode_admissions(value, members, epoch):
    admissions = validate_admissions(value, members, epoch, complete=True)
    return {kid: {'add_id': bytes.fromhex(admission['addId']),
                  'add_hash': bytes.fromhex(admission['addDigest']),
                  'source_epoch': admission['sourceEpoch'],
                  'rekey_id': bytes.fromhex(admission['completion']['rekeyId']),
                  'rekey_hash': bytes.fromhex(admission['completion']['rekeyDigest'])}
            for kid, admission in admissions.items()}


def decode_admissions(value, members, epoch):
    _require(isinstance(value, dict) and len(value) <= 128)
    admissions = {}
    for kid, wire in value.items():
        _require(isinstance(wire, dict) and set(wire) == {'add_id', 'add_hash', 'source_epoch', 'rekey_id', 'rekey_hash'})
        for name, size in (('add_id', 16), ('add_hash', 32), ('rekey_id', 16), ('rekey_hash', 32)):
            _require(isinstance(wire[name], bytes) and len(wire[name]) == size)
        admissions[kid] = {'addId': wire['add_id'].hex(), 'addDigest': wire['add_hash'].hex(),
                           'sourceEpoch': wire['source_epoch'],
                           'completion': {'rekeyId': wire['rekey_id'].hex(), 'rekeyDigest': wire['rekey_hash'].hex()}}
    return validate_admissions(admissions, members, epoch, complete=True)
