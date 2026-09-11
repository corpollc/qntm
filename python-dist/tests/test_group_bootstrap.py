import copy
import pytest
from qntm.identity import generate_identity,base64url_decode,base64url_encode
from qntm.invite import create_invite,derive_conversation_keys,create_conversation
from qntm.message import create_message,serialize_envelope,decrypt_message
from qntm.group import GroupState,create_group_genesis_body,parse_group_genesis_body,create_rekey,apply_rekey
from qntm.group_bootstrap import create_current_epoch_invite,open_current_epoch_invite,resolve_rekey_candidates,group_snapshot
from qntm.cbor import marshal_canonical,unmarshal

def setup():
    owner,member,outsider=(generate_identity()for _ in range(3))
    invite=create_invite(owner,'group');original=create_conversation(invite,derive_conversation_keys(invite))
    state=GroupState();state.apply_genesis(parse_group_genesis_body(create_group_genesis_body('Company','',owner,[member['publicKey']])))
    body,root=create_rekey(owner,original,state,original["id"]);envelope=create_message(owner,original,'group_rekey',body)
    current=copy.deepcopy(original);apply_rekey(current,root,1)
    return owner,member,outsider,state,original,current,envelope

def test_current_keys_only_and_immutable_creator():
    owner,member,outsider,state,original,current,envelope=setup()
    token=create_current_epoch_invite(owner,current,state,member['publicKey'],envelope['msg_id'])
    joined=open_current_epoch_invite(member,token,conversation_id=current['id'],creator_public_key=owner['publicKey'])
    assert joined['conversation']['keys']==current['keys']
    assert joined['conversation']['currentEpoch']==1
    assert group_snapshot(joined['state'])==group_snapshot(state)
    assert 'epochKeys' not in joined['conversation'] and 'inviteToken' not in joined['conversation']
    old=create_message(owner,original,'text',b'Prior private history')
    with pytest.raises(Exception):decrypt_message(old,joined['conversation'])
    assert decrypt_message(create_message(owner,current,'text',b'Current work'),joined['conversation'])['verified']

def test_wrong_identity_creator_context_expiry_and_tamper():
    owner,member,outsider,state,original,current,envelope=setup()
    with pytest.raises(ValueError,match='admitted'):create_current_epoch_invite(owner,current,state,outsider['publicKey'],envelope['msg_id'])
    with pytest.raises(ValueError,match='creator'):create_current_epoch_invite(member,current,state,owner['publicKey'],envelope['msg_id'])
    token=create_current_epoch_invite(owner,current,state,member['publicKey'],envelope['msg_id'],1000,600)
    for identity,kwargs,match in [(outsider,{},'another participant'),(member,{'creator_public_key':outsider['publicKey']},'creator'),(member,{'conversation_id':bytes(16)},'different')]:
        with pytest.raises(ValueError,match=match):open_current_epoch_invite(identity,token,at=1100,**kwargs)
    with pytest.raises(ValueError,match='expired'):open_current_epoch_invite(member,token,at=1600)
    outer=unmarshal(base64url_decode(token));outer['sealed']=bytes([outer['sealed'][0]^1])+outer['sealed'][1:]
    with pytest.raises(ValueError,match='signature'):open_current_epoch_invite(member,base64url_encode(marshal_canonical(outer)),at=1100)

def test_signed_control_source_epoch():
    owner,member,_,_,_,current,_=setup()
    env=create_message(owner,current,'group_remove',marshal_canonical({'removed_members':[member['keyID']],'removed_at':100,'reason':''}))
    assert unmarshal(decrypt_message(env,current)['inner']['body'])['group_epoch']==1

def test_same_lowest_winner_in_both_orders_for_both_participants():
    owner,member,outsider,state,original,current,envelope=setup()
    candidates=sorted([create_message(owner,original,'group_rekey',create_rekey(owner,original,state,original["id"])[0])for _ in range(2)],key=lambda x:x['msg_id'])
    wires=[serialize_envelope(env)for env in candidates];expected=resolve_rekey_candidates(owner,original,state,wires)
    for identity in (owner,member):
        for order in (wires,list(reversed(wires))):
            actual=resolve_rekey_candidates(identity,original,state,order)
            assert actual['envelope']['msg_id']==candidates[0]['msg_id']
            assert actual['conversation']['keys']==expected['conversation']['keys']
    unauthorized=serialize_envelope(create_message(outsider,original,'group_rekey',create_rekey(outsider,original,state,original["id"])[0]))
    assert resolve_rekey_candidates(member,original,state,[unauthorized,*wires])['envelope']['msg_id']==candidates[0]['msg_id']

@pytest.mark.parametrize('language',['typescript','python'])
def test_shared_current_epoch_and_rekey_vectors(language):
    import json,base64
    from pathlib import Path
    f=json.loads((Path(__file__).resolve().parents[2]/'client/tests'/f'group-bootstrap-{language}.json').read_text())
    member={k:bytes.fromhex(v) for k,v in f['member'].items()}
    joined=open_current_epoch_invite(member,f['token'],conversation_id=bytes.fromhex(f['source']['id']),creator_public_key=bytes.fromhex(f['owner']['publicKey']),at=f['at']+1)
    assert joined['conversation']['keys']['root'].hex()==f['root']
    source={'id':bytes.fromhex(f['source']['id']),'type':'group','currentEpoch':0,'participants':[],'keys':{k:bytes.fromhex(v) for k,v in f['source']['keys'].items()}}
    state=GroupState();state.apply_genesis(unmarshal(base64.b64decode(f['roster_b64'])))
    wires=[base64.b64decode(x) for x in f['wires']]
    for order in (wires,list(reversed(wires))):
        result=resolve_rekey_candidates(member,source,state,order,allow_expired=True)
        assert result['envelope']['msg_id'].hex()==f['winner_id'] and result['conversation']['keys']['root'].hex()==f['root']
