"""Exercise actual browser lifecycle functions with delayed RPC responses."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class BrowserLifecycleTests(unittest.TestCase):
    def test_envelope_selection_survives_delayed_bootstrap_and_hashing(self):
        code = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source=readFileSync('web/app.js','utf8');
const loadSource=source.slice(source.indexOf('async function loadEnvelope(value) {'),source.indexOf('\nfunction validateGate('));
const bootstrapSource=source.slice(source.lastIndexOf("try {\n  const response = await fetch('/deployment.json'"));
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve}};
const update=name=>({version:'attaint/1',registry:'npm',package:name,from_version:'1',to_version:'2',pin:{},facts:{}});
const sample=deferred(), nodes={};
const c={envelopeGeneration:0,envelope:null,TextEncoder,Number,JSON,
  $:id=>nodes[id]??={textContent:'',value:''},json:JSON.stringify,controls:()=>{},notify:()=>{},
  canonical:JSON.stringify,digest:async text=>text==='code'?'a'.repeat(64):text,
  link:()=>'',reader:{getContractCode:async()=>'code'},inspect:async()=>{},
  fetch:async path=>path==='/deployment.json'?{ok:true,json:async()=>({chain_id:4221,contract:'0x'+'b'.repeat(40),policy_id:0,policy_hash:'c'.repeat(64),code_sha256:'a'.repeat(64)})}:sample.promise};
c.$=id=>nodes[id]??={textContent:'',value:'',replaceChildren:()=>{}};
vm.createContext(c);vm.runInContext(loadSource,c);
const boot=vm.runInContext('(async()=>{'+bootstrapSource+'})()',c);
await c.loadEnvelope(update('manual'));
sample.resolve({ok:true,json:async()=>update('automatic-example')});await boot;
assert.equal(c.envelope.body.package,'manual');
assert.match(nodes['live-object'].textContent,/^manual /);
// A late digest for the first selection cannot replace a newer selection.
const first=deferred();c.digest=text=>text.includes('slow')?first.promise:Promise.resolve(text);
const loading=c.loadEnvelope(update('slow'));await c.loadEnvelope(update('newer'));
first.resolve('late-hash');await loading;
assert.equal(c.envelope.body.package,'newer');
assert.match(nodes['live-object'].textContent,/^newer /);
"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code, text=True,
                                capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_receipts_gates_and_wallet_disconnect(self):
        code = r"""
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {createHash} from 'node:crypto';
import {assertFinalizedConsensusReceipt} from './scripts/finalized_receipt.mjs';
const source=readFileSync('web/app.js','utf8');
const recoverySource=source.slice(source.indexOf('async function recoverReceiptRequest(receipt) {'),source.indexOf('\nfunction validateGate('));
const pollSource=source.slice(source.indexOf('async function poll() {'),source.indexOf('\nasync function send() {'));
const sendSource=source.slice(source.indexOf('async function send() {'),source.indexOf("\n$('live-connect')"));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject}};
const address='0x'+'a'.repeat(40), hash=n=>'0x'+n.repeat(64);
const tx=(n,status='SUBMITTED')=>({hash:hash(n),status,deadline:Date.now()+60000});
const receipt=(n,status='FINALIZED')=>({txId:hash(n),recipient:address,status:status==='FINALIZED'?7:6,statusName:status,result:1,lastRound:{result:1},txExecutionResult:1,txDataDecoded:{callData:{method:'request_attestation'}}});
function setup() {
  const nodes={}, notices=[], shown=[];
  const c={pending:tx('1'),pollGeneration:0,pollTimer:null,Date,Number,String,Boolean,Math,Map,JSON,TextEncoder,
    canonical:JSON.stringify,digest:async text=>createHash('sha256').update(text).digest('hex'),
    deployment:{contract:address,policy_id:0},
    reader:{getTransaction:async()=>receipt('1')},read:async()=>0,
    evmReader:{readContract:async()=>[false,0,0]},testnetBradbury:{consensusDataContract:{}},
    $:id=>nodes[id]??=( {textContent:'',hidden:true} ),json:JSON.stringify,
    renderTransaction:()=>{},controls:()=>{},notify:m=>notices.push(m),showGate:g=>shown.push(g),
    validateGate:g=>g,assertFinalizedConsensusReceipt,
    clearTimeout:()=>{},setTimeout:()=>{c.timerCount++;return 1},timerCount:0,
  };
  vm.createContext(c);vm.runInContext(recoverySource,c);vm.runInContext(pollSource,c);
  return{c,nodes,notices,shown};
}
// A's late FINALIZED receipt must never make the new B request terminal.
{
 const {c,nodes}=setup(),rpc=deferred();c.reader.getTransaction=()=>rpc.promise;
 const first=c.poll();const b=tx('2');c.pending=b;rpc.resolve(receipt('1'));await first;
 assert.equal(b.status,'SUBMITTED');assert.equal(b.receipt,undefined);assert.equal(nodes['live-receipt'],undefined);assert.equal(c.timerCount,0);
}
// The same hash can be manually refreshed while an older poll is in flight.
{
 const {c}=setup(),rpc=deferred();let calls=0;
 c.reader.getTransaction=()=>++calls===1?rpc.promise:Promise.resolve(receipt('1'));
 const old=c.poll();await c.poll();rpc.resolve(receipt('1','ACCEPTED'));await old;
 assert.equal(c.pending.status,'FINALIZED');assert.equal(c.timerCount,0);
}
// A correct finalized receipt does not authorize rendering a gate after switching hashes.
{
 const {c,shown}=setup(),gateRead=deferred(),started=deferred();
 c.pending.expected={hash:'e'};c.pending.account=address;c.pending.countBefore=0;
 c.read=async method=>method==='attestation_count'?1:(started.resolve(),gateRead.promise);
 const old=c.poll();await started.promise;c.pending=tx('2');
 gateRead.resolve({att_id:0,envelope_hash:'e',policy_id:0,requester:address,gate:'CLEAN'});await old;
 assert.equal(shown.length,0);assert.equal(c.pending.status,'SUBMITTED');
}
// Identity failure cannot convert an unresolved request into FINALIZED.
{
 const {c,notices}=setup();c.reader.getTransaction=async()=>receipt('2');await c.poll();
 assert.equal(c.pending.status,'SUBMITTED');assert.match(notices[0],/identity mismatch/);assert.equal(c.timerCount,1);
}
// A genuine same-session finalized gate still renders normally.
{
 const {c,shown}=setup();c.pending.expected={hash:'e'};c.pending.account=address;c.pending.countBefore=0;
 c.read=async method=>method==='attestation_count'?1:{att_id:0,envelope_hash:'e',policy_id:0,requester:address,gate:'CLEAN'};
 await c.poll();assert.equal(shown.length,1);assert.equal(c.pending.attestation_id,0);
}
// A hash-only resume recovers the signed envelope, sender and matching gate.
{
 const {c,shown}=setup();
 const body={version:'attaint/1',registry:'npm',package:'chalk',from_version:'1',to_version:'2'};
 const evidence=JSON.stringify(body),envelopeHash=await c.digest(evidence);
 const received={...receipt('1'),sender:address,txDataDecoded:{callData:{method:'request_attestation',args:[0,'chalk','1','2',1,envelopeHash,evidence]}}};
 c.reader.getTransaction=async()=>received;
 c.read=async method=>method==='attestation_count'?1:{att_id:0,envelope_hash:envelopeHash,policy_id:0,requester:address,gate:'CLEAN'};
 await c.poll();assert.equal(shown.length,1);assert.equal(c.pending.attestation_id,0);
 assert.equal(c.pending.expected.body.package,'chalk');assert.equal(c.pending.account,address);
 // Tampered receipt metadata cannot select a gate or be silently trusted.
 const bad=setup();bad.c.reader.getTransaction=async()=>({...received,txDataDecoded:{callData:{method:'request_attestation',args:[0,'other','1','2',1,envelopeHash,evidence]}}});
 await bad.c.poll();assert.equal(bad.shown.length,0);assert.match(bad.nodes['live-result'].textContent,/verification failed/);
}
// A wallet disconnect during asynchronous preflight must stop before signing.
{
 const {c,notices}=setup(),capacity=deferred();let writes=0;
 const estimate=()=>{};const connectedWriter={writeContract:()=>{writes++},estimateTransactionGas:estimate};
 Object.assign(c,{pending:null,busy:false,writer:connectedWriter,account:address,envelope:{hash:'e'},deploymentVerified:true,
   walletEstimate:estimate,walletOperation:'',assertReadCapacity:()=>capacity.promise});
 vm.runInContext(sendSource,c);const sending=c.send();c.writer=null;c.account=null;capacity.resolve();await sending;
 assert.equal(writes,0);assert.match(notices.at(-1),/Wallet account or network changed/);assert.equal(c.busy,false);
 assert.equal(connectedWriter.estimateTransactionGas,estimate);
}

// A missing wallet acknowledgement must not unlock an automatic/manual duplicate.
for (const declined of [false,true]) {
 const {c,nodes}=setup();let writes=0;
 const estimate=()=>{};
 const connectedWriter={estimateTransactionGas:estimate,writeContract:async()=>{
   writes++;c.pending.broadcast_attempted=true;
   const error=Error('wallet response lost');if(declined)error.cause={code:4001};throw error;
 }};
 Object.assign(c,{pending:null,busy:false,writer:connectedWriter,account:address,
   envelope:{hash:'e',body:{package:'sample',from_version:'1',to_version:'2'},evidence:'{}'},deploymentVerified:true,
   walletEstimate:estimate,walletOperation:'',assertReadCapacity:async()=>{},FOLLOW_WINDOW_MS:21600000,
   read:async method=>method==='get_policy'?{}:0,awaitRequestGate:()=>{},
   createSubmissionTTL:()=>({}),createGasGuard:()=>({estimate}),decodeFunctionData:()=>{},encodeFunctionData:()=>{}});
 vm.runInContext(sendSource,c);await c.send();
 if(declined){assert.equal(c.pending,null);assert.match(nodes['live-result'].textContent,/NOT SUBMITTED/);}
 else {assert.equal(c.pending.status,'SUBMISSION_UNCONFIRMED');await c.send();assert.equal(writes,1);}
}

"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code, text=True,
                                capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
