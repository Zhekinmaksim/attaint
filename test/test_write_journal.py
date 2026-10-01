"""Verify crash recovery without signing or broadcasting a real transaction."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class WriteJournalTests(unittest.TestCase):
    def test_ambiguous_write_recovery_and_refusal_to_resend(self):
        code = r"""
import assert from 'node:assert/strict';
import {encodeEventTopics,encodeAbiParameters,parseEventLogs} from 'viem';
import {testnetBradbury as chain} from 'genlayer-js/chains';
import {recordSigningIntent,recoverSigningIntent} from './scripts/write_journal.mjs';
const evmHash='0x'+'1'.repeat(64),txId='0x'+'2'.repeat(64),address=chain.consensusMainContract.address;
const journal={chainId:4221,command:'write',address:'0x'+'3'.repeat(40),method:'request_attestation',args:[0]};
recordSigningIntent(journal,'submission',evmHash,{nonce:9,to:address,chainId:4221});
assert.equal(journal.submission_intent.evm_hash,evmHash);
assert.equal(JSON.stringify(journal).includes('serialized'),false);
assert.throws(()=>recordSigningIntent(journal,'submission',evmHash,{nonce:9,to:address,chainId:4221}),/refusing automatic resend/);
const topics=encodeEventTopics({abi:chain.consensusMainContract.abi,eventName:'CreatedTransaction',args:{txId}});
const receipt={status:'success',transactionHash:evmHash,logs:[{address,topics,data:encodeAbiParameters([{type:'uint256'}],[4n])}]};
let saves=0;
await recoverSigningIntent({journal,kind:'submission',publicClient:{getTransactionReceipt:async()=>receipt},consensusAddress:address,abi:chain.consensusMainContract.abi,parseEventLogs,save:()=>saves++});
assert.equal(journal.hash,txId);assert.equal(journal.submission_intent.state,'CONFIRMED');assert.equal(saves,2);
const unresolved={submission_intent:{evm_hash:evmHash}};
await assert.rejects(recoverSigningIntent({journal:unresolved,kind:'submission',publicClient:{getTransactionReceipt:async()=>{const e=new Error('not found');e.name='TransactionReceiptNotFoundError';throw e;}},save:()=>{}}),/refusing automatic resend/);
const reverted={submission_intent:{evm_hash:evmHash}};
await assert.rejects(recoverSigningIntent({journal:reverted,kind:'submission',publicClient:{getTransactionReceipt:async()=>({status:'reverted',logs:[]})},save:()=>{}}),/reverted/);
const finalization={finalize_intent:{evm_hash:evmHash}};
await recoverSigningIntent({journal:finalization,kind:'finalize',publicClient:{getTransactionReceipt:async()=>receipt},save:()=>{}});
assert.equal(finalization.finalize_hash,evmHash);
const ambiguous={submission_intent:{evm_hash:evmHash}};
await assert.rejects(recoverSigningIntent({journal:ambiguous,kind:'submission',publicClient:{getTransactionReceipt:async()=>({status:'success',logs:[]})},consensusAddress:address,abi:chain.consensusMainContract.abi,parseEventLogs,save:()=>{}}),/unique consensus transaction ID/);
"""
        process = subprocess.run(["node", "--input-type=module", "-"], input=code,
                                 text=True, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)


if __name__ == "__main__":
    unittest.main()
