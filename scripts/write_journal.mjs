// Persist only public transaction identity before broadcast, never signature bytes.
export function recordSigningIntent(journal, kind, evmHash, transaction, {retryPlan,operationHash} = {}) {
  if (!journal || !kind) throw new Error('missing write journal context; refusing to sign');
  if (!/^0x[0-9a-f]{64}$/i.test(evmHash)) throw new Error('invalid signed EVM transaction hash');
  const previous = journal[`${kind}_intent`];
  if (previous) {
    if (kind !== 'submission' || !retryPlan || retryPlan.evm_hash !== previous.evm_hash || retryPlan.nonce !== Number(transaction.nonce)) throw new Error(`existing ${kind} signing intent; refusing automatic resend`);
    journal.prior_submission_intents ||= [];
    journal.prior_submission_intents.push(previous);
  }
  journal[`${kind}_intent`] = {evm_hash:evmHash,state:'SIGNED',
    nonce:String(transaction.nonce),to:transaction.to,chainId:Number(transaction.chainId),
    from:transaction.account?.address,value_wei:String(transaction.value || 0),
    ...(operationHash ? {operation_sha256:operationHash} : {}),
    ...(retryPlan ? {manual_same_nonce_retry:true,legacy_sender_assertion:retryPlan.legacy_sender_assertion} : {})};
}

export async function recoverSigningIntent({journal,kind,publicClient,consensusAddress,abi,parseEventLogs,save}) {
  const intent = journal[`${kind}_intent`];
  if (!intent) throw new Error(`no ${kind} signing intent`);
  let receipt;
  try {receipt = await publicClient.getTransactionReceipt({hash:intent.evm_hash});}
  catch (error) {
    if (error.name === 'TransactionReceiptNotFoundError') throw new Error(`unresolved ${kind} EVM hash ${intent.evm_hash}; refusing automatic resend`);
    throw error;
  }
  intent.evm_receipt = receipt;
  intent.state = receipt.status === 'success' ? 'CONFIRMED' : 'REVERTED';
  save(journal);
  if (receipt.status !== 'success') throw new Error(`${kind} EVM transaction reverted; refusing automatic resend`);
  if (kind === 'submission') {
    const logs = receipt.logs.filter(log => log.address.toLowerCase() === consensusAddress.toLowerCase());
    const events = parseEventLogs({abi,eventName:['NewTransaction','CreatedTransaction'],logs,strict:false});
    const hashes = [...new Set(events.map(event => event.args.txId))];
    if (hashes.length !== 1 || !/^0x[0-9a-f]{64}$/i.test(hashes[0])) throw new Error('successful EVM receipt has no unique consensus transaction ID; refusing resend');
    journal.hash = hashes[0];
  } else {
    journal[`${kind}_hash`] = intent.evm_hash;
    if (kind === 'recovery') journal.recovery_receipt = receipt;
  }
  save(journal);
  return journal;
}
