// Bradbury currently retrieves a recipient's accepted history in one EVM call.
// The benchmark's 30-record read reverted at 16,777,216 gas and succeeded at
// 95,000,000. Eight million gas is a conservative application admission limit,
// not a protocol limit or a guarantee about the cost of a future attestation.
export const MAX_SAFE_HISTORY_GAS = 8_000_000n;
export const MAX_HISTORY_RECORDS = 100n;
const MAX_ESTIMATE_GAS = 95_000_000n;
const ADDRESS_MANAGER = '0x8aCE036C8C3C5D603dB546b031302FCf149648E8';
const addressPattern = /^0x[0-9a-fA-F]{40}$/;
const addressAbi = [{type:'function',name:'getAllContractAddresses',stateMutability:'view',inputs:[],outputs:[{type:'tuple[]',components:[{name:'key',type:'string'},{name:'addr',type:'address'}]}]}];
const countAbi = [{type:'function',name:'getLatestAcceptedTxCount',stateMutability:'view',inputs:[{name:'recipient',type:'address'}],outputs:[{type:'uint256'}]}];
// Estimation needs only the input signature; the potentially large tuple[]
// response is neither requested by a separate read nor decoded here.
const historyAbi = [{type:'function',name:'getLatestAcceptedTransactions',stateMutability:'view',inputs:[{name:'recipient',type:'address'},{name:'startIndex',type:'uint256'},{name:'pageSize',type:'uint256'}],outputs:[]}];

function natural(value, name) {
  if(typeof value !== 'bigint' || value < 0n) throw Error(`Invalid ${name}.`);
  return value;
}

/** Read-only, bounded preflight. The caller must also verify live code and gate.
 * Results describe one current block and must not be cached as write authority.
 * No failed observation authorizes a write, retry, or replacement deployment.
 */
export async function checkReadCapacity({publicClient, recipient, timeoutMs=30_000}) {
  const result = {ok:false,status:'UNAVAILABLE',recipient,accepted_count:null,
    block_number:null,estimated_gas:null,max_safe_gas:MAX_SAFE_HISTORY_GAS.toString()};
  const deadline = Date.now() + Math.min(Math.max(timeoutMs, 1), 30_000);
  async function bounded(read) {
    const remaining = deadline - Date.now();
    if(remaining <= 0) throw Error('History capacity check timed out.');
    let timer;
    try {
      return await Promise.race([Promise.resolve().then(read),new Promise((_,reject)=>{
        timer=setTimeout(()=>reject(Error('History capacity check timed out.')),remaining);
      })]);
    } finally { clearTimeout(timer); }
  }
  try {
    if(!addressPattern.test(recipient) || /^0x0{40}$/i.test(recipient)) throw Error('Invalid recipient.');
    if(!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw Error('Invalid timeout.');
    const chainId = await bounded(()=>publicClient.getChainId());
    if(chainId !== 4221) throw Error('History capacity check requires Bradbury chain 4221.');
    const block = await bounded(()=>publicClient.getBlock({blockTag:'latest'}));
    const blockNumber = natural(block.number,'block number');
    const blockGasLimit = natural(block.gasLimit,'block gas limit');
    if(blockGasLimit === 0n) throw Error('Invalid block gas limit.');
    result.block_number=blockNumber.toString();
    const entries=await bounded(()=>publicClient.readContract({address:ADDRESS_MANAGER,
      abi:addressAbi,functionName:'getAllContractAddresses',blockNumber}));
    if(!Array.isArray(entries)) throw Error('Invalid AddressManager response.');
    const matches=entries.filter(entry=>entry.key==='ConsensusData');
    if(matches.length!==1 || !addressPattern.test(matches[0].addr) || /^0x0{40}$/i.test(matches[0].addr)) {
      throw Error('Cannot resolve ConsensusData.');
    }
    const address=matches[0].addr;
    result.consensus_data=address;
    const count=natural(await bounded(()=>publicClient.readContract({address,abi:countAbi,
      functionName:'getLatestAcceptedTxCount',args:[recipient],blockNumber})),'accepted count');
    result.accepted_count=count.toString();
    if(count>MAX_HISTORY_RECORDS) return {...result,status:'CAPACITY_LIMIT',reason:'Accepted history exceeds the bounded inspection limit.'};
    if(count===0n) return {...result,ok:true,status:'AVAILABLE',estimated_gas:'0',reason:'No accepted history; live code verification is still required.'};
    const estimated=natural(await bounded(()=>publicClient.estimateContractGas({address,abi:historyAbi,
      functionName:'getLatestAcceptedTransactions',args:[recipient,0n,count],blockNumber,
      gas:blockGasLimit<MAX_ESTIMATE_GAS?blockGasLimit:MAX_ESTIMATE_GAS})),'history gas estimate');
    if(estimated===0n) throw Error('Invalid zero history gas estimate.');
    result.estimated_gas=estimated.toString();
    if(estimated>MAX_SAFE_HISTORY_GAS || estimated>blockGasLimit) {
      return {...result,status:'CAPACITY_LIMIT',reason:'Accepted history is too expensive for reliable public-node reads.'};
    }
    return {...result,ok:true,status:'AVAILABLE',reason:'Current accepted history is below the conservative read limit.'};
  } catch(error) {
    return {...result,reason:`History capacity could not be verified: ${String(error?.shortMessage || error?.message || error).slice(0,240)}`};
  }
}

export async function assertReadCapacity(options) {
  const result=await checkReadCapacity(options);
  if(!result.ok) {
    const error=Error(result.reason);
    error.capacity=result;
    throw error;
  }
  return result;
}
