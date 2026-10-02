"""Admission stops before a recipient becomes unreadable through the public node."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReadCapacityTests(unittest.TestCase):
    def test_block_pinned_history_limits_and_errors_fail_closed(self):
        code = r"""
import assert from 'node:assert/strict';
import {checkReadCapacity,assertReadCapacity} from './scripts/read_capacity.mjs';
const recipient='0x686C79234138FBF1734C8457c917acD9A6C3Fa7a';
const manager='0x85D7bf947A512Fc640C75327A780c90847267697';
let count=3n, estimate=7000000n, chain=4221, fail='', estimates=0, duplicate=false;
const publicClient={
  getChainId:async()=>chain,
  getBlock:async()=>({number:123n,gasLimit:100000000n}),
  readContract:async q=>{
    assert.equal(q.blockNumber,123n);
    if(fail===q.functionName)throw Error('RPC unavailable');
    if(q.functionName==='getAllContractAddresses')return duplicate?
      [{key:'ConsensusData',addr:manager},{key:'ConsensusData',addr:manager}]:[{key:'ConsensusData',addr:manager}];
    assert.equal(q.address,manager);assert.deepEqual(q.args,[recipient]);return count;
  },
  estimateContractGas:async q=>{
    estimates++;assert.equal(q.blockNumber,123n);assert.equal(q.address,manager);
    assert.equal(q.functionName,'getLatestAcceptedTransactions');
    assert.deepEqual(q.args,[recipient,0n,count]);assert.equal(q.gas,95000000n);
    if(fail==='estimate')throw Error('execution reverted');return estimate;
  }
};
const check=()=>checkReadCapacity({publicClient,recipient});
let result=await check();assert.equal(result.ok,true);assert.equal(result.estimated_gas,'7000000');
assert.equal(result.accepted_count,'3');assert.equal(result.block_number,'123');JSON.stringify(result);
estimate=8000000n;assert.equal((await check()).ok,true);
estimate=8000001n;result=await check();assert.equal(result.ok,false);assert.equal(result.status,'CAPACITY_LIMIT');
await assert.rejects(()=>assertReadCapacity({publicClient,recipient}),e=>e.capacity.status==='CAPACITY_LIMIT');
for(fail of ['getAllContractAddresses','getLatestAcceptedTxCount','estimate'])assert.equal((await check()).ok,false);
fail='';estimate=0n;assert.equal((await check()).ok,false);
estimate=7000000n;duplicate=true;assert.equal((await check()).ok,false);duplicate=false;
count=101n;const prior=estimates;assert.equal((await check()).status,'CAPACITY_LIMIT');assert.equal(estimates,prior);
count=0n;assert.equal((await check()).ok,true);assert.equal(estimates,prior);
for(count of [-1n,3,'3',null])assert.equal((await check()).ok,false);
count=3n;chain=1;assert.equal((await check()).ok,false);chain=4221;
assert.equal((await checkReadCapacity({publicClient,recipient:'0x0000000000000000000000000000000000000000'})).ok,false);
assert.equal((await checkReadCapacity({publicClient,recipient,timeoutMs:NaN})).ok,false);
publicClient.getChainId=()=>new Promise(()=>{});
result=await checkReadCapacity({publicClient,recipient,timeoutMs:10});assert.equal(result.ok,false);assert.match(result.reason,/timed out/);
"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code,
                                text=True, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
