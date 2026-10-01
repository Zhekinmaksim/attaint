import managerAbi from './transaction_manager_abi.json' with {type:'json'};

const addressManager='0x8aCE036C8C3C5D603dB546b031302FCf149648E8';
const addressAbi=[{type:'function',name:'getAllContractAddresses',stateMutability:'view',inputs:[],outputs:[{type:'tuple[]',components:[{name:'key',type:'string'},{name:'addr',type:'address'}]}]}];
const same=(a,b)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();

// A timestamp-projected cancellation does not release a still-live request.
export async function confirmProjectedCancellation({publicClient,hash,recipient}) {
  const block=await publicClient.getBlock();
  const entries=await publicClient.readContract({address:addressManager,abi:addressAbi,functionName:'getAllContractAddresses',blockNumber:block.number});
  const managers=entries.filter(entry=>entry.key==='TransactionManager');
  if(managers.length!==1)throw Error('Cannot resolve raw TransactionManager; cancellation remains unconfirmed.');
  const raw=await publicClient.readContract({address:managers[0].addr,abi:managerAbi,functionName:'getTransaction',args:[hash],blockNumber:block.number});
  if(!same(raw.id,hash)||!same(raw.recipient,recipient))throw Error('Raw cancellation identity mismatch; preserve the original hash.');
  return {status:Number(raw.status)===8?'CANCELED':'CANCELLATION_UNCONFIRMED',
    raw_observation:{hash:raw.id,recipient:raw.recipient,status:Number(raw.status),valid_until:raw.validUntil,block:block.number,block_timestamp:block.timestamp}};
}
