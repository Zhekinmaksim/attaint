// A read failure cannot certify a receipt or allocate a replacement request.
export async function observeReceiptStates({hashes,getTransaction,finalizationCapability,getMinimalTransaction,getRawTransaction}) {
  const addRawExpiry=async state=>{
    if(state.status!=='CANCELED'||!getRawTransaction)return state;
    const raw=await getRawTransaction(state.hash);
    if(String(raw.hash).toLowerCase()!==state.hash.toLowerCase()||String(raw.recipient).toLowerCase()!==String(state.recipient).toLowerCase())throw Error('raw/projection transaction identity mismatch');
    if(raw.status===1&&BigInt(raw.valid_until)>0n&&BigInt(raw.valid_until)<BigInt(raw.block_timestamp))
      return{...state,status:'EXPIRED_PENDING_CLEANUP',projected_status:'CANCELED',raw_observation:raw,capability:null};
    return{...state,raw_observation:raw};
  };
  const states=[];
  for(let index=0;index<hashes.length;index+=4) {
    const batch=await Promise.all(hashes.slice(index,index+4).map(async hash=>{
      try {
        const receipt=await getTransaction(hash);
        const statusCode=Number(receipt.status);
        if(!Number.isSafeInteger(statusCode)||statusCode<0) throw new Error('consensus receipt has no valid numeric status');
        // SDK 1.1.8 omits this additive processing phase; current official
        // genlayer-js/src/types/transactions.ts names status 14 LEADER_REVEALING.
        // Keep all existing status names/numbers and terminal criteria unchanged.
        const status=receipt.statusName||(statusCode===14?'LEADER_REVEALING':`UNKNOWN_STATUS_${statusCode}`);
        const capability=['ACCEPTED','READY_TO_FINALIZE','UNDETERMINED'].includes(status)?await finalizationCapability(hash):null;
        return await addRawExpiry({hash,status,status_code:statusCode,recipient:receipt.recipient,
          execution:receipt.txExecutionResultName,result:Number(receipt.result),round:receipt.numOfRounds,capability});
      } catch(error) {
        const message=String(error.shortMessage||error.message||'receipt read failed')
          .replace(/https?:\/\/\S+/g,'[RPC endpoint]').slice(0,600);
        if(getMinimalTransaction && /getTransactionAllData/.test(message) && /0x1f90236d/i.test(message)) {
          try {
            const minimal=await getMinimalTransaction(hash);
            if(String(minimal.txId).toLowerCase()!==hash.toLowerCase() || Number(minimal.status)!==8)
              throw new Error('minimal view cannot certify a canceled observation');
            return await addRawExpiry({hash,status:'CANCELED',status_code:8,recipient:minimal.recipient,
              result:Number(minimal.result),round:minimal.numOfRounds,capability:null,
              execution:'UNAVAILABLE',receipt_source:'consensusData.getTransactionData',
              partial_receipt:true,error:message});
          } catch {}
        }
        return {hash,status:'READ_ERROR',capability:null,error:message};
      }
    }));
    states.push(...batch);
  }
  return states;
}
