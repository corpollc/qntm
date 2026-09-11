"""Generate reverse synthetic vector from the shared TS source context."""
import json,base64
from pathlib import Path
from qntm.group import GroupState,create_rekey
from qntm.group_bootstrap import resolve_rekey_candidates,create_current_epoch_invite
from qntm.message import create_message,serialize_envelope
from qntm.cbor import unmarshal
root=Path(__file__).resolve().parents[2]/'client/tests'
f=json.loads((root/'group-bootstrap-typescript.json').read_text())
owner={k:bytes.fromhex(v) for k,v in f['owner'].items()};member={k:bytes.fromhex(v) for k,v in f['member'].items()}
source={'id':bytes.fromhex(f['source']['id']),'type':'group','currentEpoch':0,'participants':[],'keys':{k:bytes.fromhex(v) for k,v in f['source']['keys'].items()}}
state=GroupState();state.apply_genesis(unmarshal(base64.b64decode(f['roster_b64'])))
wires=[serialize_envelope(create_message(owner,source,'group_rekey',create_rekey(owner,source,state,source['id'])[0])) for _ in range(2)]
winner=resolve_rekey_candidates(owner,source,state,wires)
f['token']=create_current_epoch_invite(owner,winner['conversation'],state,member['publicKey'],winner['envelope']['msg_id'],f['at'])
f['wires']=[base64.b64encode(w).decode() for w in wires];f['winner_id']=winner['envelope']['msg_id'].hex();f['root']=winner['conversation']['keys']['root'].hex()
(root/'group-bootstrap-python.json').write_text(json.dumps(f,indent=2)+'\n')
