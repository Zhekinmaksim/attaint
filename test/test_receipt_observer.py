"""A broken computed view cannot turn an existing hash into a replacement."""
import pathlib
import subprocess
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

class ReceiptObserverTests(unittest.TestCase):
    def test_partial_read_failure_keeps_hashes_and_other_observations(self):
        code=r"""
import assert from 'node:assert/strict';
import {observeReceiptStates} from './scripts/receipt_observer.mjs';
const hashes=['broken','final','unknown','accepted-with-bad-eligibility','leader-revealing'];
const states=await observeReceiptStates({hashes,
  getTransaction:async hash=>{
    if(hash==='broken')throw Error('ValidatorSelectionFailed() https://rpc.example/secret');
    if(hash==='unknown')return{status:99,result:0};
    if(hash==='leader-revealing')return{status:14,result:0};
    return{status:hash==='final'?7:5,statusName:hash==='final'?'FINALIZED':'ACCEPTED',result:1};
  },finalizationCapability:async()=>{throw Error('eligibility unavailable');}});
assert.deepEqual(states.map(s=>s.hash),hashes);
assert.equal(states[0].status,'READ_ERROR');assert.equal(states[0].capability,null);
assert(!states[0].error.includes('/secret'));
assert.equal(states[1].status,'FINALIZED');assert.equal(states[1].result,1);
assert.equal(states[2].status,'UNKNOWN_STATUS_99');assert.equal(states[2].capability,null);
assert.equal(states[3].status,'READ_ERROR');assert.equal(states[3].capability,null);
assert.equal(states[4].status,'LEADER_REVEALING');assert.equal(states[4].result,0);
assert.equal(states[4].capability,null); // An active reveal phase cannot certify a final receipt.
assert(states.filter(s=>s.status==='FINALIZED').length===1);
const partial=await observeReceiptStates({hashes:['canceled','decided'],
 getTransaction:async()=>{throw Error('getTransactionAllData 0x1f90236d');},
 finalizationCapability:async()=>{throw Error('must not check eligibility');},
 getMinimalTransaction:async hash=>({txId:hash,status:hash==='canceled'?8:7,result:hash==='canceled'?0:1,numOfRounds:0})});
assert.equal(partial[0].status,'CANCELED');assert.equal(partial[0].partial_receipt,true);
assert.equal(partial[0].execution,'UNAVAILABLE');assert.equal(partial[0].capability,null);
assert.equal(partial[1].status,'READ_ERROR');
"""
        result=subprocess.run(['node','--input-type=module','-'],input=code,text=True,capture_output=True,cwd=ROOT,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
