"""A projected cancellation cannot permit a duplicate still-live request."""
import pathlib
import subprocess
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]

class RawCancellationTests(unittest.TestCase):
    def test_pending_projection_and_identity_fail_closed(self):
        code=r"""
import assert from 'node:assert/strict';
import {confirmProjectedCancellation} from './scripts/raw_cancellation.mjs';
let status=1, recipient='0xrecipient', hash='0xhash', fail=false;
const client={getBlock:async()=>({number:91n,timestamp:100n}),readContract:async request=>{
  assert.equal(request.blockNumber,91n);
  if(request.functionName==='getAllContractAddresses')return[{key:'TransactionManager',addr:'0xmanager'}];
  if(fail)throw Error('RPC unavailable');
  assert.equal(request.address,'0xmanager');
  return{id:hash,recipient,status,validUntil:200n};
}};
const read=()=>confirmProjectedCancellation({publicClient:client,hash:'0xhash',recipient:'0xrecipient'});
for(status of [1,3,5,7,14])assert.equal((await read()).status,'CANCELLATION_UNCONFIRMED');
status=8;assert.equal((await read()).status,'CANCELED');
recipient='0xother';await assert.rejects(read,/identity mismatch/);
recipient='0xrecipient';hash='0xother';await assert.rejects(read,/identity mismatch/);
hash='0xhash';fail=true;await assert.rejects(read,/RPC unavailable/);
"""
        result=subprocess.run(['node','--input-type=module','-'],input=code,text=True,capture_output=True,cwd=ROOT,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
