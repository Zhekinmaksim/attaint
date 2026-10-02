// Official raw TransactionManager state, not timestamp-projected ConsensusData status.
import {readFileSync} from 'node:fs';
const managerAbi=JSON.parse(readFileSync(new URL('./transaction_manager_abi.json',import.meta.url),'utf8'));
const queueAbi=JSON.parse(readFileSync(new URL('./queue_head_abi.json',import.meta.url),'utf8'));
const addressManager='0x8aCE036C8C3C5D603dB546b031302FCf149648E8';
const addressAbi=[{type:'function',name:'getAllContractAddresses',stateMutability:'view',inputs:[],outputs:[{type:'tuple[]',components:[{name:'key',type:'string'},{name:'addr',type:'address'}]}]}];
export const cancelAbi=[{type:'function',name:'cancelTransaction',stateMutability:'nonpayable',inputs:[{name:'txId',type:'bytes32'}],outputs:[]}];
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
export function assertExpiredOwnHead({hash,head,raw,sender,recipient,timestamp}) {
  if(!same(hash,head)||!same(raw.id,hash))throw Error('transaction is not the exact current pending queue head');
  if(Number(raw.status)!==1)throw Error('raw transaction is not PENDING');
  if(!same(raw.sender,sender)||!same(raw.txOrigin,sender)||!same(raw.recipient,recipient))throw Error('expired-head sender/recipient identity mismatch');
  if(BigInt(raw.validUntil)<=0n||BigInt(raw.validUntil)>=BigInt(timestamp))throw Error('pending queue head is not strictly expired at the observed block');
}
export async function inspectExpiredHead({publicClient,hash,sender,recipient}) {
  const block=await publicClient.getBlock();
  const entries=await publicClient.readContract({address:addressManager,abi:addressAbi,functionName:'getAllContractAddresses',blockNumber:block.number});
  const resolve=name=>{const found=entries.filter(e=>e.key===name);if(found.length!==1)throw Error('cannot resolve '+name);return found[0].addr;};
  const manager=resolve('TransactionManager'),queue=resolve('Queues');
  const [head,pending,raw]=await Promise.all([
    publicClient.readContract({address:queue,abi:queueAbi,functionName:'getPendingHeadTxId',args:[recipient],blockNumber:block.number}),
    publicClient.readContract({address:queue,abi:queueAbi,functionName:'getPendingTxCount',args:[recipient],blockNumber:block.number}),
    publicClient.readContract({address:manager,abi:managerAbi,functionName:'getTransaction',args:[hash],blockNumber:block.number}),
  ]);
  assertExpiredOwnHead({hash,head,raw,sender,recipient,timestamp:block.timestamp});
  return{hash,head,recipient,sender,manager,queue,block:block.number,block_timestamp:block.timestamp,
    raw_status:Number(raw.status),valid_until:raw.validUntil,pending:Number(pending),tx_slot:raw.txSlot};
}

export async function createRawStatusReader(publicClient) {
  const block=await publicClient.getBlock();
  const entries=await publicClient.readContract({address:addressManager,abi:addressAbi,functionName:'getAllContractAddresses',blockNumber:block.number});
  const managers=entries.filter(e=>e.key==='TransactionManager');
  if(managers.length!==1)throw Error('cannot resolve raw TransactionManager');
  return async hash=>{
    const raw=await publicClient.readContract({address:managers[0].addr,abi:managerAbi,functionName:'getTransaction',args:[hash],blockNumber:block.number});
    if(!same(raw.id,hash))throw Error('raw transaction identity mismatch');
    return{hash:raw.id,status:Number(raw.status),sender:raw.sender,recipient:raw.recipient,
      valid_until:raw.validUntil,block:block.number,block_timestamp:block.timestamp};
  };
}
export async function readQueueHead({publicClient,recipient}) {
  const block=await publicClient.getBlock();
  const entries=await publicClient.readContract({address:addressManager,abi:addressAbi,functionName:'getAllContractAddresses',blockNumber:block.number});
  const queues=entries.filter(e=>e.key==='Queues');
  if(queues.length!==1)throw Error('cannot resolve Queues');
  const head=await publicClient.readContract({address:queues[0].addr,abi:queueAbi,functionName:'getPendingHeadTxId',args:[recipient],blockNumber:block.number});
  return{head,recipient,block:block.number};
}
async function readTerminalProof({publicClient,hash,sender,recipient,expectedCalldata},status) {
  const block=await publicClient.getBlock();
  const entries=await publicClient.readContract({address:addressManager,abi:addressAbi,functionName:'getAllContractAddresses',blockNumber:block.number});
  const resolve=name=>{const found=entries.filter(e=>e.key===name);if(found.length!==1)throw Error('cannot resolve '+name);return found[0].addr;};
  const manager=resolve('TransactionManager'),queue=resolve('Queues');
  const abi=JSON.parse(readFileSync(new URL('./queue_head_abi.json',import.meta.url),'utf8'));
  const [raw,head,tail]=await Promise.all([
    publicClient.readContract({address:manager,abi:managerAbi,functionName:'getTransaction',args:[hash],blockNumber:block.number}),
    publicClient.readContract({address:queue,abi,functionName:'getPendingHead',args:[recipient],blockNumber:block.number}),
    publicClient.readContract({address:queue,abi,functionName:'getPendingTail',args:[recipient],blockNumber:block.number}),
  ]);
  if(!same(raw.id,hash)||Number(raw.status)!==status||!same(raw.sender,sender)||!same(raw.recipient,recipient)||!same(raw.txOrigin,sender)||BigInt(raw.value)!==0n||!same(raw.txCalldata,expectedCalldata))throw Error('no exact raw terminal transaction identity/calldata proof');
  if(tail<head||tail-head>20n)throw Error('pending queue is outside bounded audit range');
  const pending=[];
  for(let slot=head;slot<tail;slot++)pending.push(await publicClient.readContract({address:queue,abi,functionName:'getPendingTxId',args:[recipient,slot],blockNumber:block.number}));
  if(pending.some(id=>same(id,hash)))throw Error('raw terminal transaction still belongs to pending queue');
  return{hash,sender,recipient,raw_status:status,valid_until:raw.validUntil,calldata_matches:true,value_wei:'0',
    block:block.number,block_timestamp:block.timestamp,queue:{address:queue,head,tail,pending_hashes:pending},outside_pending_queue:true};
}

// Separate fixed-status entry points keep canceled proof semantics unchanged.
export const readCanceledProof = args => readTerminalProof(args,8);
export const readFinalizedFailureProof = args => readTerminalProof(args,7);
