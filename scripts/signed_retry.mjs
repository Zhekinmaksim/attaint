// Explicit same-nonce recovery for an ambiguous submission. Never auto-retry.
import {createHash} from 'node:crypto';

const same = (a,b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const address = (v) => /^0x[0-9a-f]{40}$/i.test(v || '');
const abi = [5,6].map(count => ({type:'function',name:'addTransaction',stateMutability:'nonpayable',
  inputs:[{name:'sender',type:'address'},{name:'recipient',type:'address'},
    {name:'validators',type:'uint256'},{name:'rotations',type:'uint256'},
    {name:'data',type:'bytes'},...(count === 6 ? [{name:'validUntil',type:'uint256'}] : [])],outputs:[]}));

export function submissionOperationHash(data, decodeFunctionData) {
  const decoded = decodeFunctionData({abi,data});
  if (decoded.functionName !== 'addTransaction' || ![5,6].includes(decoded.args?.length)) throw new Error('retry is not an addTransaction submission');
  // V6 validUntil and gas price may change; sender/recipient/consensus/input may not.
  return submissionFieldsHash(decoded.args.slice(0,5));
}

export function submissionFieldsHash(values) {
  const fields = values.map(value => typeof value === 'bigint' ? value.toString() : String(value).toLowerCase());
  return createHash('sha256').update(JSON.stringify(fields)).digest('hex');
}

export async function assertUnusedIntentNonce({journal,intent,publicClient,sender}) {
  const intents = [...(journal.prior_submission_intents || []),intent];
  for (const previous of intents) {
    try {await publicClient.getTransactionReceipt({hash:previous.evm_hash});}
    catch (error) {
      if (error.name !== 'TransactionReceiptNotFoundError') throw error;
      try {await publicClient.getTransaction({hash:previous.evm_hash});}
      catch (transactionError) {
        if (transactionError.name !== 'TransactionNotFoundError') throw transactionError;
        continue;
      }
      throw new Error('signed-intent transaction is present; refusing replacement');
    }
    throw new Error('signed-intent receipt is present; resume its original hash');
  }
  const [latest,pending] = await Promise.all(['latest','pending'].map(blockTag =>
    publicClient.getTransactionCount({address:sender,blockTag})));
  if (BigInt(latest) !== BigInt(intent.nonce) || BigInt(pending) !== BigInt(intent.nonce)) throw new Error('signed-intent nonce is spent or pending; refusing replacement');
}

export async function prepareSignedIntentRetry({journal,publicClient,sender,expectedSender,consensusAddress}) {
  const intent = journal.submission_intent;
  if (!['deploy','write'].includes(journal.command) || journal.hash || !intent || intent.state !== 'SIGNED') throw new Error('retry requires an unresolved deploy/write signing intent');
  if (!/^(0|[1-9]\d*)$/.test(String(journal.value_wei)) || (journal.command === 'deploy' && !/^[0-9a-f]{64}$/.test(journal.source_sha256 || ''))) throw new Error('retry requires the original journal value and deployment source hash');
  if (!address(expectedSender) || !same(sender,expectedSender)) throw new Error('--retry-sender must pin the original signer wallet');
  if (intent.from && !same(intent.from,sender)) throw new Error('signed-intent signer mismatch');
  if (intent.chainId !== 4221 || !same(intent.to,consensusAddress) || !/^(0|[1-9]\d*)$/.test(intent.nonce)) throw new Error('signed-intent chain/destination/nonce mismatch');
  if (!Number.isSafeInteger(Number(intent.nonce))) throw new Error('signed-intent nonce is too large');
  await assertUnusedIntentNonce({journal,intent,publicClient,sender});
  return {evm_hash:intent.evm_hash,nonce:Number(intent.nonce),sender,legacy_sender_assertion:!intent.from};
}

export function validateRetryTransaction({journal,plan,transaction,operationHash,expectedOperationHash}) {
  const intent = journal.submission_intent;
  if (!plan || plan.evm_hash !== intent?.evm_hash || plan.nonce !== Number(intent.nonce)) throw new Error('signed-intent retry plan mismatch');
  if (!same(transaction.to,intent.to) || Number(transaction.chainId) !== 4221
      || !same(transaction.account?.address,plan.sender)
      || BigInt(transaction.value || 0) !== BigInt(journal.value_wei || 0)) throw new Error('retry changed sender/destination/chain/value');
  if (operationHash !== expectedOperationHash || (intent.operation_sha256 && operationHash !== intent.operation_sha256)) throw new Error('retry changed submission semantics');
  return {...transaction,nonce:plan.nonce};
}
