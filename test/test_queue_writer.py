"""Use fake EVM views and a temporary lock; no network or real signing."""
import pathlib
import subprocess
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]


class QueueWriterTests(unittest.TestCase):
    def test_authoritative_queue_and_single_writer_lock(self):
        code=r"""
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,existsSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {readPendingQueue} from './scripts/queues.mjs';import {acquireWriterLock} from './scripts/writer_lock.mjs';
const recipient='0x'+'1'.repeat(40),queues='0x'+'2'.repeat(40);let reads=[];
const publicClient={getBlock:async()=>({number:9n}),readContract:async(q)=>{reads.push(q);if(q.functionName==='getAllContractAddresses')return [{key:'Queues',addr:queues}];return q.functionName==='maxPendingTxsPerRecipient'?20n:17n;}};
const capacity=await readPendingQueue({publicClient,recipient});assert.equal(capacity.maximum,20);assert.equal(capacity.pending,17);assert.equal(capacity.address,queues);
assert.equal(reads.every(q=>q.blockNumber===9n),true);assert.equal(reads[2].args[0],recipient);
await assert.rejects(readPendingQueue({recipient,publicClient:{...publicClient,readContract:async()=>[]}}),/resolve authoritative/);
const directory=mkdtempSync(join(tmpdir(),'attaint-lock-test-')),path=join(directory,'lock');
try{const release=acquireWriterLock(path);assert.equal(existsSync(path),true);assert.throws(()=>acquireWriterLock(path),/another Bradbury writer/);release();assert.equal(existsSync(path),false);const release2=acquireWriterLock(path);release2();writeFileSync(path,JSON.stringify({pid:99999999,id:'dead'}));assert.throws(()=>acquireWriterLock(path),/stale Bradbury writer lock/);assert.equal(existsSync(path),true);writeFileSync(path,'invalid');assert.throws(()=>acquireWriterLock(path),/invalid writer lock/);}finally{rmSync(directory,{recursive:true,force:true});}
"""
        process=subprocess.run(["node","--input-type=module","-"],input=code,text=True,capture_output=True,cwd=ROOT,timeout=30)
        self.assertEqual(process.returncode,0,process.stderr)


if __name__=="__main__":
    unittest.main()
