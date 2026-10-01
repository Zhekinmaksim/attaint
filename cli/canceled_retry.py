"""One explicit replacement per immutable canceled transaction hash."""
import hashlib,json,re

def load_manifest(document,report):
    if document.get('version')!=1 or document.get('chainId')!=4221:
        raise ValueError('invalid canceled retry manifest version/chain')
    for key in ('contract','code_sha256','policy_id','policy_hash'):
        if document.get(key)!=report.get(key):raise ValueError('canceled retry manifest identity mismatch: '+key)
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}',document.get('requester','')):raise ValueError('manifest must pin the requester')
    entries=document.get('rows',[])
    if not 1<=len(entries)<=18 or document.get('maximum_fresh_requests')!=len(entries):raise ValueError('manifest must cap 1–18 fresh requests')
    result={}
    for entry in entries:
        index=entry.get('index')
        if type(index)is not int or not 0<=index<45 or index in result:raise ValueError('invalid/duplicate manifest index')
        row=report['controls'][index];hash=entry.get('expected_old_hash','')
        if not re.fullmatch(r'0x[0-9a-fA-F]{64}',hash) or entry.get('envelope_hash')!=row['envelope_hash']:raise ValueError('manifest old hash/envelope mismatch')
        archived=any(r['hash']==hash for r in row.get('canceled_consensus_attempts',[]))
        if row.get('transaction_hash')!=hash and not archived:raise ValueError('manifest does not anchor the current original transaction')
        result[index]={**entry,'requester':document['requester']}
    return result

def prove_canceled(journal,entry,read_raw,read_gates):
    hash=entry['expected_old_hash'];args=journal['args'];sender=entry['requester']
    if journal.get('hash')!=hash or args[5]!=entry['envelope_hash']:raise ValueError('canceled retry anchor mismatch')
    raw=read_raw(journal,sender)
    if (raw.get('chainId')!=4221 or raw.get('hash')!=hash or raw.get('raw_status')!=8
        or raw.get('recipient')!=journal['address'] or str(raw.get('sender','')).lower()!=sender.lower()
        or raw.get('calldata_matches')is not True or raw.get('value_wei')!='0'
        or raw.get('outside_pending_queue')is not True
        or hash in raw.get('queue',{}).get('pending_hashes',[hash])):
        raise ValueError('no exact raw CANCELED/outside-queue/calldata proof')
    expected=dict(policy_id=args[0],package=args[1],from_version=args[2],to_version=args[3])
    states=[]
    for variant in ('latest-final','latest-nonfinal'):
        state=read_gates(variant);gates=state.get('gates',[])
        if (state.get('chainId')!=4221 or state.get('address')!=journal['address'] or state.get('variant')!=variant
            or state.get('count')!=len(gates) or [g.get('att_id')for g in gates]!=list(range(len(gates)))):
            raise ValueError('no complete stable '+variant+' gate audit')
        if any(all(g.get(k)==v for k,v in expected.items())and str(g.get('requester','')).lower()==sender.lower()for g in gates):
            raise ValueError('release already has a committed attestation')
        states.append(state)
    return {'source':'live-raw-canceled-no-commit-audit','hash':hash,'raw':raw,'states':states,
        'identity':expected,'requester':sender,'envelope_hash':entry['envelope_hash']}

def is_anchored_original(row,entry,journal):
    if journal.get('hash')==entry['expected_old_hash']:return True
    if sum(r['hash']==entry['expected_old_hash']for r in row.get('canceled_consensus_attempts',[]))!=1:
        raise ValueError('a different active hash has no original canceled archive')
    return False  # Even a failed replacement is never authorized by the old anchor.

def require_fresh_manifest(row,entry):
    if row.get('canceled_consensus_attempts')and not entry:
        raise ValueError('fresh canceled replacement requires its explicit immutable manifest')
    if entry and sum(r['hash']==entry['expected_old_hash']for r in row.get('canceled_consensus_attempts',[]))!=1:
        raise ValueError('no unique durable canceled retry archive')

def forbid_replacement_intent_archive(row,journal):
    if row.get('canceled_consensus_attempts')and journal.get('submission_intent'):
        raise ValueError('the one canceled replacement has a signed EVM intent; it cannot be archived or resent under the original authorization')

def archive_canceled(path,row,entry,read_raw,read_gates,save,persist):
    journal=json.loads(path.read_text());proof=prove_canceled(journal,entry,read_raw,read_gates)
    archive=path.parent/'failed-submissions';archive.mkdir(exist_ok=True)
    archived=archive/(path.stem+'-'+entry['expected_old_hash']+'.json')
    proof_path=archive/(path.stem+'-'+entry['expected_old_hash']+'.canceled-no-commit-proof.json')
    if archived.exists()and archived.read_bytes()!=path.read_bytes():raise ValueError('canceled archive changed')
    if not archived.exists():
        temporary=archived.with_suffix('.tmp');temporary.write_bytes(path.read_bytes());temporary.replace(archived)
    if not proof_path.exists():save(proof_path,proof)
    records=row.setdefault('canceled_consensus_attempts',[])
    if not any(r['hash']==entry['expected_old_hash']for r in records):
        records.append({'hash':entry['expected_old_hash'],'status':'RAW_CANCELED','consensus_commit':False,
            'journal':str(archived),'proof':str(proof_path),'proof_sha256':hashlib.sha256(proof_path.read_bytes()).hexdigest(),
            'requester':entry['requester'],'envelope_hash':entry['envelope_hash'],'maximum_replacements':1})
    for key in ('transaction_hash','reason','failure_finalized','failure_receipt','consensus_status','consensus_result','consensus_read_error','raw_consensus_observation','receipt','attestation_id','gate','exit_code'):
        row.pop(key,None)
    row['status']='PINNED';persist(row)  # The audit reference is durable before unlink.
    path.unlink()
