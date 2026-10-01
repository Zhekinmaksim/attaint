"""Same-nonce recovery checks use fake RPC reads and never broadcast."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SignedRetryTests(unittest.TestCase):
    def test_explicit_same_nonce_recovery_guards(self):
        code = r"""
import assert from 'node:assert/strict';
import {encodeFunctionData,decodeFunctionData} from 'viem';
import {prepareSignedIntentRetry,submissionOperationHash,submissionFieldsHash,validateRetryTransaction} from './scripts/signed_retry.mjs';
import {recordSigningIntent} from './scripts/write_journal.mjs';
const evm='0x'+'1'.repeat(64),sender='0x'+'2'.repeat(40),main='0x'+'3'.repeat(40),recipient='0x'+'0'.repeat(40);
const missing=(name)=>{const e=new Error('not found');e.name=name;throw e;};
const client={getTransactionReceipt:async()=>missing('TransactionReceiptNotFoundError'),getTransaction:async()=>missing('TransactionNotFoundError'),getTransactionCount:async()=>446};
const journal={command:'deploy',chainId:4221,value_wei:'0',source_sha256:'a'.repeat(64),submission_intent:{evm_hash:evm,state:'SIGNED',nonce:'446',to:main,chainId:4221}};
const args={journal,publicClient:client,sender,expectedSender:sender,consensusAddress:main};
const plan=await prepareSignedIntentRetry(args);assert.equal(plan.nonce,446);assert.equal(plan.legacy_sender_assertion,true);
await assert.rejects(prepareSignedIntentRetry({...args,expectedSender:main}),/original signer/);
await assert.rejects(prepareSignedIntentRetry({...args,publicClient:{...client,getTransactionReceipt:async()=>({status:'success'})}}),/receipt is present/);
await assert.rejects(prepareSignedIntentRetry({...args,publicClient:{...client,getTransaction:async()=>({hash:evm})}}),/transaction is present/);
await assert.rejects(prepareSignedIntentRetry({...args,publicClient:{...client,getTransactionCount:async({blockTag})=>blockTag==='pending'?447:446}}),/spent or pending/);
await assert.rejects(prepareSignedIntentRetry({...args,publicClient:{...client,getTransactionReceipt:async()=>{throw Error('transport');}}}),/transport/);
await assert.rejects(prepareSignedIntentRetry({...args,journal:{...journal,hash:'consensus'}}),/unresolved/);
await assert.rejects(prepareSignedIntentRetry({...args,journal:{...journal,command:'recover'}}),/unresolved/);
const fields=[sender,recipient,5n,3n,'0x1234'];
const mkabi=(count)=>[{type:'function',name:'addTransaction',stateMutability:'nonpayable',outputs:[],inputs:[{name:'s',type:'address'},{name:'r',type:'address'},{name:'v',type:'uint256'},{name:'n',type:'uint256'},{name:'d',type:'bytes'},...(count===6?[{name:'expiry',type:'uint256'}]:[])]}];
const encode=(expiry)=>encodeFunctionData({abi:mkabi(expiry?6:5),functionName:'addTransaction',args:[...fields,...(expiry?[expiry]:[])]});
const operationHash=submissionOperationHash(encode(),decodeFunctionData);
assert.equal(operationHash,submissionOperationHash(encode(1n),decodeFunctionData));
assert.equal(operationHash,submissionOperationHash(encode(999n),decodeFunctionData));
assert.equal(operationHash,submissionFieldsHash(fields));
const transaction={account:{address:sender},to:main,nonce:447,chainId:4221,value:0n,data:encode(),gasPrice:20n};
const forced=validateRetryTransaction({journal,plan,transaction,operationHash,expectedOperationHash:operationHash});
assert.equal(forced.nonce,446);assert.equal(transaction.nonce,447);
assert.throws(()=>validateRetryTransaction({journal,plan,transaction:{...transaction,value:1n},operationHash,expectedOperationHash:operationHash}),/value/);
assert.throws(()=>validateRetryTransaction({journal,plan,transaction,operationHash,expectedOperationHash:'different-source'}),/semantics/);
assert.throws(()=>recordSigningIntent(journal,'submission',evm,forced),/automatic resend/);
recordSigningIntent(journal,'submission','0x'+'4'.repeat(64),forced,{retryPlan:plan,operationHash});
assert.equal(journal.submission_intent.nonce,'446');assert.equal(journal.submission_intent.from,sender);
assert.equal(journal.prior_submission_intents[0].evm_hash,evm);assert.equal(journal.submission_intent.manual_same_nonce_retry,true);
assert.throws(()=>recordSigningIntent(journal,'submission',evm,forced,{retryPlan:plan,operationHash}),/automatic resend/);
"""
        process = subprocess.run(["node", "--input-type=module", "-"], input=code,
                                 text=True, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)


if __name__ == "__main__":
    unittest.main()
