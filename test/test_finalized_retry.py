import copy
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'cli'))
import finalized_retry as fr


class FinalizedRetryTests(unittest.TestCase):
    def setUp(self):
        self.h = '0x' + '11' * 32
        self.sender = '0x' + '22' * 20
        self.contract = '0x' + '33' * 20
        self.row = {'transaction_hash': self.h, 'envelope_hash': 'e', 'status': 'FINALIZED_NONAGREEMENT',
                    'failed_consensus_attempts': [{'hash': 'older-generation'}]}
        self.journal = {'chainId': 4221, 'hash': self.h, 'address': self.contract,
                        'method': 'request_attestation', 'args': [0, 'pkg', '1', '2', 1, 'e', 'canonical']}
        self.entry = {'index': 21, 'expected_old_hash': self.h, 'envelope_hash': 'e',
                      'expected_result': 5, 'requester': self.sender}
        self.proof = {'chainId': 4221, 'hash': self.h, 'raw_status': 7, 'recipient': self.contract,
                      'sender': self.sender, 'calldata_matches': True, 'value_wei': '0',
                      'outside_pending_queue': True, 'queue': {'pending_hashes': []},
                      'receipt': {'txId': self.h, 'status': 7, 'statusName': 'FINALIZED',
                                  'result': 5, 'recipient': self.contract, 'sender': self.sender}}
        self.gates = lambda variant: {'chainId': 4221, 'address': self.contract,
                                     'variant': variant, 'count': 0, 'gates': []}

    def prove(self, proof=None, gates=None):
        return fr.prove_finalized(self.journal, self.entry, lambda *a: proof or self.proof, gates or self.gates)

    def test_exact_raw_finality_receipt_result_calldata_requester(self):
        self.prove()
        for change in ({'raw_status': 8}, {'raw_status': 1}, {'calldata_matches': False},
                       {'sender': 'wrong'}, {'outside_pending_queue': False},
                       {'queue': {'pending_hashes': [self.h]}}, {'value_wei': '1'}):
            with self.assertRaises(ValueError):
                self.prove({**self.proof, **change})
        for change in ({'result': 1}, {'result': 2}, {'status': 6}, {'txId': 'wrong'},
                       {'sender': 'wrong'}, {'recipient': 'wrong'}, {'statusName': 'UNDETERMINED'}):
            with self.assertRaises(ValueError):
                self.prove({**self.proof, 'receipt': {**self.proof['receipt'], **change}})
        self.entry['expected_result'] = 2
        self.prove({**self.proof, 'receipt': {**self.proof['receipt'], 'result': 2}})

    def test_both_views_complete_and_no_committed_release_even_other_envelope(self):
        matching = {'att_id': 0, 'policy_id': 0, 'package': 'pkg', 'from_version': '1',
                    'to_version': '2', 'requester': self.sender, 'envelope_hash': 'different'}
        for variant in ('latest-final', 'latest-nonfinal'):
            for change in ({'count': 1}, {'count': 1, 'gates': [matching]},
                           {'count': 1, 'gates': [{**matching, 'att_id': 9}]}):
                with self.assertRaises(ValueError):
                    self.prove(gates=lambda v: {**self.gates(v), **change} if v == variant else self.gates(v))

    def test_archive_before_unlink_preserves_older_history_and_consumes_one_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / '21.transaction.json'
            path.write_text(json.dumps(self.journal))
            original = path.read_bytes()
            save = lambda p, d: p.write_text(json.dumps(d))
            def failed_save(row):
                raise OSError('checkpoint failed')
            with self.assertRaises(OSError):
                fr.archive_finalized(path, self.row, self.entry, lambda *a: self.proof, self.gates, save, failed_save)
            self.assertEqual(path.read_bytes(), original)
            fr.archive_finalized(path, self.row, self.entry, lambda *a: self.proof, self.gates, save, lambda row: None)
            self.assertFalse(path.exists())
            self.assertEqual(self.row['failed_consensus_attempts'], [{'hash': 'older-generation'}])
            self.assertEqual(len(self.row[fr.HISTORY]), 1)
            self.assertEqual(pathlib.Path(self.row[fr.HISTORY][0]['journal']).read_bytes(), original)
            self.assertTrue(fr.is_anchored_original(self.row, self.entry, self.journal))
            self.assertFalse(fr.is_anchored_original(self.row, self.entry, {**self.journal, 'hash': 'replacement'}))
            with self.assertRaises(ValueError):
                fr.require_fresh_manifest(self.row, None)
            fr.require_fresh_manifest(self.row, self.entry)
            for state in ('SIGNED', 'REVERTED', 'CONFIRMED'):
                with self.assertRaises(ValueError):
                    fr.forbid_replacement_intent_archive(self.row, {'submission_intent': {'state': state}})

    def test_manifest_caps_exact_current_generation_and_result(self):
        report = {'contract': self.contract, 'code_sha256': 'c', 'policy_id': 0, 'policy_hash': 'p',
                  'controls': [copy.deepcopy(self.row) for _ in range(45)]}
        document = {'version': 1, 'chainId': 4221, 'kind': 'finalized-nonagreement',
                    **{k: report[k] for k in ('contract', 'code_sha256', 'policy_id', 'policy_hash')},
                    'requester': self.sender, 'maximum_fresh_requests': 1,
                    'rows': [{k: v for k, v in self.entry.items() if k != 'requester'}]}
        self.assertEqual(list(fr.load_manifest(document, report)), [21])
        for change in ({'policy_hash': 'wrong'}, {'maximum_fresh_requests': 2}, {'kind': 'canceled'},
                       {'rows': [{**document['rows'][0], 'expected_result': 1}]},
                       {'rows': [document['rows'][0], document['rows'][0]]}):
            with self.assertRaises(ValueError):
                fr.load_manifest({**document, **change}, report)
        report['controls'][21]['transaction_hash'] = 'new-generation'
        with self.assertRaises(ValueError):
            fr.load_manifest(document, report)
        report['controls'][21][fr.HISTORY] = [{'hash': self.h}]
        fr.load_manifest(document, report)  # Recovery may resume the one already allocated replacement.

    def test_terminal_raw_helpers_keep_canceled_and_finalized_statuses_separate(self):
        code = r"""
import assert from 'node:assert/strict';
import {readCanceledProof,readFinalizedFailureProof} from './scripts/expired_head.mjs';
const hash='0x'+'11'.repeat(32),sender='0x'+'22'.repeat(20),recipient='0x'+'33'.repeat(20);
let status=7,calldata='0xabcd';
const client={getBlock:async()=>({number:100n,timestamp:999n}),readContract:async x=>{
 assert.equal(x.blockNumber,100n);
 switch(x.functionName){
 case 'getAllContractAddresses':return[{key:'TransactionManager',addr:'manager'},{key:'Queues',addr:'queue'}];
 case 'getTransaction':return{id:hash,status,sender,txOrigin:sender,recipient,value:0n,txCalldata:calldata,validUntil:1000n};
 case 'getPendingHead':return 0n;
 case 'getPendingTail':return 0n;
 default:throw Error('unexpected call');
 }}};
const args={publicClient:client,hash,sender,recipient,expectedCalldata:'0xabcd'};
assert.equal((await readFinalizedFailureProof(args)).raw_status,7);
await assert.rejects(readCanceledProof(args),/terminal transaction identity/);
status=8;assert.equal((await readCanceledProof(args)).raw_status,8);
await assert.rejects(readFinalizedFailureProof(args),/terminal transaction identity/);
status=7;calldata='0xdead';await assert.rejects(readFinalizedFailureProof(args),/terminal transaction identity/);
"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code, text=True,
                                capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
