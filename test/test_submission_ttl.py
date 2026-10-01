import pathlib,subprocess,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class SubmissionTTLTests(unittest.TestCase):
    def test_deadline_only_and_fail_closed(self):
        code=r'''
import assert from 'node:assert/strict';
import {decodeFunctionData,encodeFunctionData} from 'viem';
import {createSubmissionTTL,submissionV6Abi} from './scripts/submission_ttl.mjs';
import {assertExpiredOwnHead} from './scripts/expired_head.mjs';
const args=['0x'+'11'.repeat(20),'0x'+'22'.repeat(20),5n,3n,'0x123456',4600n];
const data=encodeFunctionData({abi:submissionV6Abi,functionName:'addTransaction',args});
let now=1000;
const ttl=createSubmissionTTL({seconds:21600,decodeFunctionData,encodeFunctionData,now:()=>now});
const encoded=ttl.rewrite(data);now=2000;
assert.equal(ttl.rewrite(data),encoded);assert.equal(ttl.rewrite(encoded),encoded);
const actual=decodeFunctionData({abi:submissionV6Abi,data:encoded}).args;
assert.deepEqual(actual.slice(0,5),args.slice(0,5));assert.equal(actual[5],22600n);
assert.equal(encoded.slice(0,10),data.slice(0,10));
for(const seconds of [0,3599,21601,1.5,NaN])assert.throws(()=>createSubmissionTTL({seconds,decodeFunctionData,encodeFunctionData}));
const v5=[{...submissionV6Abi[0],inputs:submissionV6Abi[0].inputs.slice(0,5)}];
assert.throws(()=>createSubmissionTTL({seconds:21600,decodeFunctionData,encodeFunctionData}).rewrite(encodeFunctionData({abi:v5,functionName:'addTransaction',args:args.slice(0,5)})),/V6/);
assert.throws(()=>ttl.rewrite(encodeFunctionData({abi:submissionV6Abi,functionName:'addTransaction',args:[...args.slice(0,4),'0x99',args[5]]})),/changed/);
const proof={hash:'h',head:'h',sender:'a',recipient:'b',timestamp:100n,raw:{id:'h',sender:'a',txOrigin:'a',recipient:'b',status:1,validUntil:99n}};
assertExpiredOwnHead(proof);
for(const change of [{head:'other'},{timestamp:99n},{raw:{...proof.raw,status:8}},{raw:{...proof.raw,sender:'other'}}])assert.throws(()=>assertExpiredOwnHead({...proof,...change}));
'''
        result=subprocess.run(['node','--input-type=module','-'],input=code,text=True,capture_output=True,cwd=ROOT,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
