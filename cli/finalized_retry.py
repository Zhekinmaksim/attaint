"""One replacement per immutable FINALIZED nonagreement transaction hash.

Every generation needs its own exact manifest. An EVM signing intent consumes
that generation's allowance even when its submission later reverts.
"""
import hashlib
import json
import re

HISTORY = 'finalized_retry_attempts'


def load_manifest(document, report):
    if (document.get('version') != 1 or document.get('chainId') != 4221
            or document.get('kind') != 'finalized-nonagreement'):
        raise ValueError('invalid finalized retry manifest version/chain/kind')
    for key in ('contract', 'code_sha256', 'policy_id', 'policy_hash'):
        if document.get(key) != report.get(key):
            raise ValueError('finalized retry manifest identity mismatch: ' + key)
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}', document.get('requester', '')):
        raise ValueError('manifest must pin the requester')
    entries = document.get('rows', [])
    if not 1 <= len(entries) <= 3 or document.get('maximum_fresh_requests') != len(entries):
        raise ValueError('finalized manifest must cap 1–3 fresh requests')
    result = {}
    for entry in entries:
        index = entry.get('index')
        if type(index) is not int or not 0 <= index < 45 or index in result:
            raise ValueError('invalid/duplicate finalized manifest index')
        row = report['controls'][index]
        tx_hash = entry.get('expected_old_hash', '')
        if (not re.fullmatch(r'0x[0-9a-fA-F]{64}', tx_hash)
                or entry.get('envelope_hash') != row['envelope_hash']
                or type(entry.get('expected_result')) is not int
                or entry['expected_result'] not in (2, 5)):
            raise ValueError('finalized manifest old hash/envelope/result mismatch')
        archived = any(r['hash'] == tx_hash for r in row.get(HISTORY, []))
        if row.get('transaction_hash') != tx_hash and not archived:
            raise ValueError('finalized manifest does not anchor the current transaction')
        result[index] = {**entry, 'requester': document['requester']}
    return result


def prove_finalized(journal, entry, read_proof, read_gates):
    tx_hash = entry['expected_old_hash']
    args = journal['args']
    sender = entry['requester']
    if (journal.get('hash') != tx_hash or args[5] != entry['envelope_hash']
            or journal.get('chainId') != 4221
            or journal.get('method') != 'request_attestation'):
        raise ValueError('finalized retry anchor mismatch')
    proof = read_proof(journal, sender, entry['expected_result'])
    receipt = proof.get('receipt', {})
    if (proof.get('chainId') != 4221 or proof.get('hash') != tx_hash
            or proof.get('raw_status') != 7 or proof.get('recipient') != journal['address']
            or str(proof.get('sender', '')).lower() != sender.lower()
            or proof.get('calldata_matches') is not True or proof.get('value_wei') != '0'
            or proof.get('outside_pending_queue') is not True
            or tx_hash in proof.get('queue', {}).get('pending_hashes', [tx_hash])
            or receipt.get('txId') != tx_hash or receipt.get('status') != 7
            or receipt.get('statusName') != 'FINALIZED'
            or receipt.get('result') != entry['expected_result']
            or receipt.get('recipient') != journal['address']
            or str(receipt.get('sender', '')).lower() != sender.lower()):
        raise ValueError('no exact raw FINALIZED/nonagreement/outside-queue/calldata proof')
    expected = dict(policy_id=args[0], package=args[1], from_version=args[2], to_version=args[3])
    states = []
    for variant in ('latest-final', 'latest-nonfinal'):
        state = read_gates(variant)
        gates = state.get('gates', [])
        if (state.get('chainId') != 4221 or state.get('address') != journal['address']
                or state.get('variant') != variant or state.get('count') != len(gates)
                or [g.get('att_id') for g in gates] != list(range(len(gates)))):
            raise ValueError('no complete stable ' + variant + ' gate audit')
        if any(all(g.get(k) == v for k, v in expected.items())
               and str(g.get('requester', '')).lower() == sender.lower() for g in gates):
            raise ValueError('release already has a committed attestation')
        states.append(state)
    return {'source': 'live-raw-finalized-nonagreement-no-commit-audit', 'hash': tx_hash,
            'proof': proof, 'states': states, 'identity': expected,
            'requester': sender, 'envelope_hash': entry['envelope_hash']}


def is_anchored_original(row, entry, journal):
    if journal.get('hash') == entry['expected_old_hash']:
        return True
    if sum(r['hash'] == entry['expected_old_hash'] for r in row.get(HISTORY, [])) != 1:
        raise ValueError('different active hash has no original finalized archive')
    return False


def require_fresh_manifest(row, entry):
    if row.get(HISTORY) and not entry:
        raise ValueError('fresh finalized replacement requires its explicit immutable manifest')
    if entry and sum(r['hash'] == entry['expected_old_hash'] for r in row.get(HISTORY, [])) != 1:
        raise ValueError('no unique durable finalized retry archive')


def forbid_replacement_intent_archive(row, journal):
    if (row.get(HISTORY) or journal.get('finalized_retry_anchor')) and journal.get('submission_intent'):
        raise ValueError('the one finalized replacement has a signed EVM intent; it cannot be archived or resent under the original authorization')


def archive_finalized(path, row, entry, read_proof, read_gates, save, persist):
    journal = json.loads(path.read_text())
    proof = prove_finalized(journal, entry, read_proof, read_gates)
    archive = path.parent / 'failed-submissions'
    archive.mkdir(exist_ok=True)
    archived = archive / (path.stem + '-' + entry['expected_old_hash'] + '.json')
    proof_path = archive / (path.stem + '-' + entry['expected_old_hash'] + '.finalized-no-commit-proof.json')
    if archived.exists() and archived.read_bytes() != path.read_bytes():
        raise ValueError('finalized archive changed')
    if not archived.exists():
        temporary = archived.with_suffix('.tmp')
        temporary.write_bytes(path.read_bytes())
        temporary.replace(archived)
    if not proof_path.exists():
        save(proof_path, proof)
    records = row.setdefault(HISTORY, [])
    if not any(r['hash'] == entry['expected_old_hash'] for r in records):
        records.append({'hash': entry['expected_old_hash'], 'status': 'FINALIZED',
                        'result': entry['expected_result'], 'consensus_commit': False,
                        'journal': str(archived), 'proof': str(proof_path),
                        'proof_sha256': hashlib.sha256(proof_path.read_bytes()).hexdigest(),
                        'requester': entry['requester'], 'envelope_hash': entry['envelope_hash'],
                        'maximum_replacements': 1})
    for key in ('transaction_hash', 'reason', 'failure_finalized', 'failure_receipt',
                'consensus_status', 'consensus_result', 'consensus_read_error',
                'raw_consensus_observation', 'receipt', 'attestation_id', 'gate', 'exit_code'):
        row.pop(key, None)
    row['status'] = 'PINNED'
    persist(row)  # History and exact archived bytes are durable before unlink.
    path.unlink()
