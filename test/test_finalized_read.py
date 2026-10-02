"""A node's latest-final label cannot turn accepted state into a CI decision."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FinalizedReadTests(unittest.TestCase):
    def test_finality_identity_concurrency_and_reorg_guards(self):
        code = r"""
import assert from 'node:assert/strict';
import {testnetBradbury} from 'genlayer-js/chains';
import {readFinalizedContract} from './scripts/finalized_read.mjs';
const hash = digit => '0x'+digit.repeat(64);
const address = '0x'+'a'.repeat(40), manager = '0x'+'b'.repeat(40);
const record = (id,overrides={}) => ({txId:'0x'+id.toString(16).padStart(64,'0'),recipient:address,status:7,result:1,lastRound:{result:1},numOfRounds:6n,txExecutionHash:hash('2'),...overrides});
function setup(overrides={}) {
  let observations=0, viewCalls=0;
  const records=overrides.records ?? [record(1),record(2)];
  const pages=[];
  const client = {chain:testnetBradbury,readContract:async request=>{
    viewCalls++;
    assert.equal(request.transactionHashVariant,'latest-final');
    assert.equal(request.address,address);
    return {decision:'CLEAN'};
  }};
  const publicClient = {
    getChainId:async()=>4221,
    getBlock:async request=>{
      if(request.blockNumber!==undefined)return{number:10n,hash:overrides.reorg?hash('9'):hash('a')};
      observations++;
      return {number:BigInt(9+observations),hash:observations===1?hash('a'):hash('b')};
    },
    readContract:async request=>{
      assert.equal(request.blockNumber,BigInt(9+observations));
      if(request.functionName==='getAllContractAddresses')return [{key:'ConsensusData',addr:manager}];
      assert.equal(request.address,manager);
      assert.equal(request.args[0],address);
      if(overrides.revert)throw Error('execution reverted');
      const current=observations===2 && overrides.after ? overrides.after : records;
      if(request.functionName==='getLatestAcceptedTxCount')return overrides.count ?? BigInt(current.length);
      assert.equal(request.functionName,'getLatestAcceptedTransactions');
      const [,offset,size]=request.args;
      assert(size>0n && size<=5n);pages.push([observations,Number(offset),Number(size)]);
      const page=current.slice(Number(offset),Number(offset+size));
      return overrides.shortPage ? page.slice(1) : page;
    },
  };
  return {run:()=>readFinalizedContract({client,publicClient,address,functionName:'gate',args:[0]}),calls:()=>viewCalls,pages};
}
assert.deepEqual(await setup().run(),{decision:'CLEAN'});
// A finalized accepted execution error may leave the previous state unchanged.
assert.deepEqual(await setup({records:[record(1,{txExecutionResult:2})]}).run(),{decision:'CLEAN'});
// Crucial regression: finalized newest record does not excuse an earlier accepted record.
assert.deepEqual(await setup({records:[record(1,{numOfRounds:0n}),record(2)]}).run(),{decision:'CLEAN'});
for(const older of [{status:5},{status:6},{status:1},{result:2},{lastRound:{result:5}},{recipient:manager},{txId:hash('0')},{numOfRounds:-1n},{txExecutionHash:hash('0')}]) {
  const test=setup({records:[record(2),record(1,older)]});
  await assert.rejects(test.run,/Finalized state could not be verified/);
  assert.equal(test.calls(),0,'Never read gen_call before the whole history is final');
}
for(const changed of [{txId:hash('3')},{numOfRounds:7n},{status:5},{txExecutionHash:hash('4')}]) {
  const test=setup({after:[record(1,changed),record(2)]});
  await assert.rejects(test.run,/Finalized state could not be verified/);
  assert.equal(test.calls(),1,'Discard a result when any consensus record changed');
}
for(const options of [{records:[]},{count:101n},{count:2},{records:[record(1),record(1)]},{shortPage:true}]) {
  const test=setup(options);await assert.rejects(test.run,/Finalized state could not be verified/);assert.equal(test.calls(),0);
}
for(const after of [[record(1)],[record(1),record(2),record(3)],[record(2),record(1)]]) {
  await assert.rejects(setup({after}).run,/accepted history changed/);
}
const paged=setup({records:Array.from({length:11},(_,index)=>record(index+1))});
await paged.run();assert.deepEqual(paged.pages,[[1,0,5],[1,5,5],[1,10,1],[2,0,5],[2,5,5],[2,10,1]]);
// A duplicate across a page boundary must not satisfy the declared count.
const crossPage=setup({records:[...Array.from({length:5},(_,i)=>record(i+1)),record(1)]});
await assert.rejects(crossPage.run,/duplicate transactions/);assert.equal(crossPage.calls(),0);
await assert.rejects(setup({reorg:true}).run,/EVM block changed/);
const reverted=setup({revert:true});
await assert.rejects(reverted.run,/execution reverted/);
assert.equal(reverted.calls(),0);
"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code, text=True,
                                capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
