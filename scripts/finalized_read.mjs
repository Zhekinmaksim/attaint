const ADDRESS_MANAGER = '0x8aCE036C8C3C5D603dB546b031302FCf149648E8';
const addressAbi = [{type:'function',name:'getAllContractAddresses',stateMutability:'view',inputs:[],outputs:[{type:'tuple[]',components:[{name:'key',type:'string'},{name:'addr',type:'address'}]}]}];
const validAddress = value => typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value) && !/^0x0{40}$/i.test(value);
const validHash = value => typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value) && !/^0x0{64}$/i.test(value);
const same = (a,b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
function unconfirmed(reason) {
  const error = Error(`Finalized state could not be verified: ${reason}`);
  error.code = 'FINALITY_UNCONFIRMED';
  return error;
}
function natural(value) {
  return typeof value === 'bigint' && value >= 0n;
}

// Some public-node versions expose ACCEPTED state even when gen_call asks for
// latest-final. Never interpret that response as a finalized CI decision.
// Check every accepted record, since a finalized newest record alone does not
// prove that earlier accepted state is final. Bound work to 100 records and
// five records per call; unknown, incomplete, or changing history fails closed.
export async function readFinalizedContract({client,publicClient,address,functionName,args=[],consensusDataAbi=client?.chain?.consensusDataContract?.abi}) {
  if (!validAddress(address) || !Array.isArray(args) || typeof functionName !== 'string' || !functionName)
    throw unconfirmed('invalid contract read arguments.');
  const methods = ['getLatestAcceptedTxCount','getLatestAcceptedTransactions'];
  const historyAbi = consensusDataAbi?.filter(entry => entry.type === 'function' && methods.includes(entry.name));
  if (historyAbi?.length !== 2 || methods.some(name => historyAbi.filter(entry => entry.name === name).length !== 1))
    throw unconfirmed('ConsensusData ABI is unavailable.');
  if (await publicClient.getChainId() !== 4221 || client?.chain?.id !== 4221)
    throw unconfirmed('Bradbury chain 4221 is required.');

  async function observe() {
    const block = await publicClient.getBlock({blockTag:'latest'});
    if (!natural(block.number) || !validHash(block.hash)) throw unconfirmed('invalid EVM block.');
    const entries = await publicClient.readContract({address:ADDRESS_MANAGER,abi:addressAbi,
      functionName:'getAllContractAddresses',blockNumber:block.number});
    const matches = Array.isArray(entries) ? entries.filter(entry => entry.key === 'ConsensusData') : [];
    if (matches.length !== 1 || !validAddress(matches[0].addr)) throw unconfirmed('cannot resolve ConsensusData.');
    const manager = matches[0].addr;
    const count = await publicClient.readContract({address:manager,abi:historyAbi,
      functionName:'getLatestAcceptedTxCount',args:[address],blockNumber:block.number});
    if (!natural(count) || count === 0n || count > 100n) throw unconfirmed('accepted history is empty or exceeds the 100-record verification bound.');
    const ids = new Set(), vector = [];
    for (let offset = 0n; offset < count; offset += 5n) {
      const size = count - offset < 5n ? count - offset : 5n;
      const page = await publicClient.readContract({address:manager,abi:historyAbi,
        functionName:'getLatestAcceptedTransactions',args:[address,offset,size],blockNumber:block.number});
      if (!Array.isArray(page) || page.length !== Number(size)) throw unconfirmed('accepted history page is incomplete.');
      for (const record of page) {
        if (!validHash(record?.txId) || !same(record?.recipient,address)) throw unconfirmed('accepted history identity mismatch.');
        const id = record.txId.toLowerCase();
        if (ids.has(id)) throw unconfirmed('accepted history contains duplicate transactions.');
        ids.add(id);
        if (Number(record.status) !== 7 || Number(record.result) !== 1 || Number(record.lastRound?.result) !== 1)
          throw unconfirmed('accepted history contains a transaction that is not finalized with consensus agreement.');
        // Deterministic deployment/policy calls legitimately use round zero.
        if (!natural(record.numOfRounds) || !validHash(record.txExecutionHash))
          throw unconfirmed('invalid consensus round count or execution hash.');
        // Execution errors agreed on by consensus do not alter contract state;
        // requiring a successful execution here would reject valid old state.
        vector.push(`${id}:${record.numOfRounds}:${record.txExecutionHash.toLowerCase()}`);
      }
    }
    if (ids.size !== Number(count)) throw unconfirmed('accepted history count mismatch.');
    return {block,manager,vector};
  }

  const before = await observe();
  const value = await client.readContract({address,functionName,args,transactionHashVariant:'latest-final'});
  const after = await observe();
  if (after.block.number < before.block.number || !same(before.manager,after.manager) ||
      before.vector.length !== after.vector.length || before.vector.some((entry,index) => entry !== after.vector[index]))
    throw unconfirmed('accepted history changed during the read; try again after finalization.');
  // Re-reading the original height also detects a reorg when the new head has
  // advanced. A stable transaction id alone does not establish canonicality.
  const canonical = await publicClient.getBlock({blockNumber:before.block.number});
  if (!same(canonical?.hash,before.block.hash) ||
      (after.block.number === before.block.number && !same(after.block.hash,before.block.hash)))
    throw unconfirmed('EVM block changed during the read.');
  return value;
}
