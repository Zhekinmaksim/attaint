// A successful leader execution alone does not mean consensus accepted it.
export function assertFinalizedConsensusReceipt(receipt, {hash, recipient, method}) {
  if (Number(receipt.status) !== 7 || receipt.statusName !== 'FINALIZED')
    throw new Error('Consensus transaction is not finalized.');
  if (String(receipt.txId).toLowerCase() !== hash.toLowerCase() ||
      String(receipt.recipient).toLowerCase() !== recipient.toLowerCase())
    throw new Error('Consensus receipt belongs to another transaction or contract.');
  const callData = receipt.txDataDecoded?.callData;
  const actualMethod = callData instanceof Map ? callData.get('method') : callData?.method;
  if (method && actualMethod !== method)
    throw new Error('Consensus receipt belongs to another contract method.');
  if (Number(receipt.result) !== 1 || Number(receipt.lastRound?.result) !== 1)
    throw new Error('Finalized transaction has no accepted consensus decision; no successful attestation is claimed.');
  if (Number(receipt.txExecutionResult) !== 1)
    throw new Error('Finalized transaction did not execute successfully.');
}
