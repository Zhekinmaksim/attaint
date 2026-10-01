// Capability checks use the deployed protocol, without inferring readiness from status.
export function createFinalizationChecker({client, publicClient, chain}) {
  let lifecycleAvailable = true;
  return async (hash) => {
    if (lifecycleAvailable) {
      try {
        const lifecycle = await client.request({method:'gen_getTransactionLifecycle',params:[{txId:hash}]});
        if (!lifecycle || typeof lifecycle.resolutionAction !== 'string') throw new Error('invalid lifecycle response');
        return {source:'gen_getTransactionLifecycle',eligible:lifecycle.resolutionAction === 'Finalize' && lifecycle.decisionActive === true && lifecycle.decisionId != null,lifecycle};
      } catch (error) {
        let missing = false;
        for (let current = error, depth = 0; current && depth < 6; current = current.cause, depth++) {
          if (current.code === -32601 || /method not found.*gen_getTransactionLifecycle/i.test(String(current.message))) missing = true;
        }
        if (!missing) throw error;
        lifecycleAvailable = false;
      }
    }
    const block = await publicClient.getBlock();
    // This is the same projection time convention as GenLayerJS getTransaction.
    const evaluatedAt = BigInt(Math.floor(Date.now()/1000));
    const result = await publicClient.readContract({address:chain.consensusDataContract.address,
      abi:chain.consensusDataContract.abi,functionName:'canFinalize',args:[hash,evaluatedAt],blockNumber:block.number});
    if (!Array.isArray(result) || typeof result[0] !== 'boolean') throw new Error('invalid canFinalize response');
    return {source:'consensusData.canFinalize',eligible:result[0],block:block.number,
      block_timestamp:block.timestamp,evaluated_at:evaluatedAt,raw:result};
  };
}
