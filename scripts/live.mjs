#!/usr/bin/env node
// Bradbury SDK bridge. Credentials are loaded from the CLI keychain, never saved.
import {execFileSync} from 'node:child_process';
import {dirname, join, resolve} from 'node:path';
import {realpathSync, readFileSync, writeFileSync, renameSync, mkdirSync, existsSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {retryRpcRead} from './rpc_retry.mjs';
import {createFinalizationChecker} from './finalization.mjs';
import {recordSigningIntent,recoverSigningIntent} from './write_journal.mjs';
import {selectFinalizedRound,decodeFinalizedTrace} from './settled_trace.mjs';
import {prepareSignedIntentRetry,assertUnusedIntentNonce,submissionOperationHash,submissionFieldsHash,validateRetryTransaction} from './signed_retry.mjs';

const options = process.argv.slice(3);
const option = (name, fallback = '') => {
  const i = options.indexOf(name);
  if (i < 0) return fallback;
  if (!options[i + 1] || options[i + 1].startsWith('--')) throw new Error(`missing value for ${name}`);
  return options[i + 1];
};
const required = (name) => {const v = option(name); if (!v) throw new Error(`missing ${name}`); return v;};
const stringify = (v) => JSON.stringify(v, (_, x) => typeof x === 'bigint' ? x.toString() : x instanceof Map ? Object.fromEntries(x) : x, 2);
const save = (v) => {
  const out = option('--out');
  if (out) {mkdirSync(dirname(resolve(out)), {recursive:true}); writeFileSync(out + '.tmp', stringify(v) + '\n'); renameSync(out + '.tmp', out);}
};

const readRpc = (operation) => retryRpcRead(operation, {
  onRetry: (attempt, attempts) => console.error(`Transient RPC read failure; retry ${attempt}/${attempts}`),
});

try {
  const cliEntry = realpathSync(execFileSync('which', ['genlayer'], {encoding:'utf8'}).trim());
  const cliRoot = resolve(dirname(cliEntry), '..');
  let sdk, chains;
  try {sdk = await import('genlayer-js'); chains = await import('genlayer-js/chains');}
  catch {sdk = await import(pathToFileURL(join(cliRoot,'node_modules/genlayer-js/dist/index.js'))); chains = await import(pathToFileURL(join(cliRoot,'node_modules/genlayer-js/dist/chains/index.js')));}
  const command = process.argv[2];
  if (options.includes('--retry-signed-intent') && !['deploy','write'].includes(command)) throw new Error('--retry-signed-intent is limited to unresolved deploy/write submissions');
  const writes = ['deploy','write','settle','recover'].includes(command);
  let account;
  if (writes) {
    const configPath = process.env.GENLAYER_CONFIG || join(process.env.HOME,'.genlayer/genlayer-config.json');
    let config = {}; try {config = JSON.parse(readFileSync(configPath,'utf8'));} catch {}
    const name = option('--account',process.env.GENLAYER_ACCOUNT || config.activeAccount || '');
    let secret = process.env.GENLAYER_PRIVATE_KEY;
    if (!secret && name) {
      const keytarModule = await import(pathToFileURL(join(cliRoot,'node_modules/keytar/lib/keytar.js')));
      secret = await (keytarModule.default || keytarModule).getPassword('genlayer-cli','account:'+name);
    }
    if (!secret) throw new Error('No unlocked account. Unlock the GenLayer CLI account first.');
    try {account = sdk.createAccount(secret);} catch {throw new Error("Invalid unlocked account credential");}
  }
  const rpc = option('--rpc','https://rpc-bradbury.genlayer.com');
  const client = sdk.createClient({chain:chains.testnetBradbury,endpoint:rpc,account});
  let viem;
  try {viem = await import('viem');}
  catch {viem = await import(pathToFileURL(join(cliRoot,'node_modules/viem/_esm/index.js')));}
  const publicClient = viem.createPublicClient({chain:chains.testnetBradbury,transport:viem.http(rpc)});
  const finalizationCapability = createFinalizationChecker({client,publicClient,chain:chains.testnetBradbury});
  const actualChain = Number(BigInt(await readRpc(() => client.request({method:'eth_chainId'}))));
  if (actualChain !== 4221) throw new Error(`wrong chain: expected 4221, received ${actualChain}`);
  const meta = {network:'bradbury',chainId:actualChain,rpc};
  let result;
  let signingKind = null;
  let retryPlan = null;
  let expectedOperationHash = null;
  let retryConsumed = false;
  if (writes) {
    const block = await readRpc(() => client.request({method:'eth_getBlockByNumber',params:['latest',false]}));
    const blockCap = BigInt(block.gasLimit) * 95n / 100n;
    const requestedCap = BigInt(option('--gas-limit','16777216'));
    if (requestedCap <= 0n || requestedCap > blockCap) throw new Error('--gas-limit exceeds available block gas');
    const sign = account.signTransaction.bind(account);
    account.signTransaction = async (transaction, signingOptions) => {
      let operationHash;
      if (signingKind === 'submission') operationHash = submissionOperationHash(transaction.data,viem.decodeFunctionData);
      if (retryPlan && signingKind === 'submission') {
        if (retryConsumed) throw new Error('manual signed-intent retry already used; refusing a second broadcast');
        transaction = validateRetryTransaction({journal:result,plan:retryPlan,transaction,operationHash,expectedOperationHash});
        await readRpc(() => assertUnusedIntentNonce({journal:result,intent:result.submission_intent,publicClient,sender:account.address}));
      }
      const estimate = BigInt(transaction.gas || 200000n);
      if (estimate > requestedCap) throw new Error(`estimated gas ${estimate} exceeds transaction cap ${requestedCap}; compact the deployment source`);
      const withHeadroom = estimate + estimate / 10n;
      const gas = withHeadroom < requestedCap ? withHeadroom : requestedCap;
      console.error(`Gas: estimate=${estimate} limit=${gas} block=${block.gasLimit}`);
      required('--out');
      const serialized = await sign({...transaction,gas}, signingOptions);
      recordSigningIntent(result,signingKind,viem.keccak256(serialized),transaction,{retryPlan:signingKind === 'submission' ? retryPlan : null,operationHash});
      save(result); // A save failure prevents returning signed bytes to the sender.
      if (retryPlan && signingKind === 'submission') retryConsumed = true;
      return serialized;
    };
  }

  const address = option('--address');
  if (address && !/^0x[0-9a-f]{40}$/i.test(address)) throw new Error('invalid contract address');
  const argsFile = option('--args-file');
  const args = argsFile ? JSON.parse(readFileSync(argsFile,'utf8')) : [];
  const valueWei = BigInt(option('--value','0')).toString();
  const deploymentCode = command === 'deploy' ? readFileSync(required('--file'),'utf8') : null;
  const sourceHash = deploymentCode === null ? null : createHash('sha256').update(deploymentCode).digest('hex');
  if (!Array.isArray(args)) throw new Error('--args-file must contain a JSON array');
  const recoverIntent = (kind) => readRpc(() => recoverSigningIntent({journal:result,kind,publicClient,
    consensusAddress:chains.testnetBradbury.consensusMainContract.address,
    abi:chains.testnetBradbury.consensusMainContract.abi,parseEventLogs:viem.parseEventLogs,save}));
  if (command === 'read') {
    result = {...meta,address,method:required('--method'),result:await readRpc(() => client.readContract({address:required('--address'),functionName:required('--method'),args,transactionHashVariant:option('--variant','latest-final')}))};
  } else if (command === 'code') {
    const code = await readRpc(() => client.getContractCode(required('--address')));
    if (!code) throw new Error('empty contract code');
    result = {...meta,address,code_sha256:createHash('sha256').update(code).digest('hex'),code};
  } else if (command === 'receipt') {
    result = {...meta,hash:required('--hash'),receipt:await readRpc(() => client.getTransaction({hash:required('--hash')}))};
  } else if (command === 'recover') {
    const hash = required('--hash');
    const out = required('--out');
    result = {...meta,command,hash};
    if (existsSync(out)) {
      const previous = JSON.parse(readFileSync(out,'utf8'));
      if (previous.hash !== hash || previous.chainId !== 4221 || previous.command !== command) throw new Error('recovery journal mismatch');
      result = {...previous,...result};
    }
    if (!result.recovery_hash && result.recovery_intent) await recoverIntent('recovery');
    if (!result.recovery_hash) {
      const simulation = await readRpc(() => publicClient.simulateContract({address:chains.testnetBradbury.consensusMainContract.address,
        abi:chains.testnetBradbury.consensusMainContract.abi,functionName:'processIdleness',args:[hash],account:account.address,blockTag:'pending'}));
      const walletClient = viem.createWalletClient({chain:chains.testnetBradbury,transport:viem.http(rpc),account});
      signingKind = 'recovery';
      result.recovery_hash = await walletClient.writeContract({...simulation.request,account});
      signingKind = null; save(result);
      console.error(`Recovery EVM Hash: ${result.recovery_hash}`);
    }
    result.recovery_receipt = await readRpc(() => publicClient.waitForTransactionReceipt({hash:result.recovery_hash})); save(result);
    if (result.recovery_receipt.status !== 'success') throw new Error('recovery EVM transaction reverted');
    result.receipt = await readRpc(() => client.getTransaction({hash})); save(result);
  } else if (writes) {
    let hash = option('--hash');
    const out = option('--out');
    let previous = {};
    // Reusing the journal resumes the original transaction rather than broadcasting twice.
    if (out && existsSync(out)) {
      previous = JSON.parse(readFileSync(out,'utf8'));
      if (previous.chainId !== 4221 || previous.command !== command || previous.address !== address || previous.method !== option('--method')) throw new Error('journal identity mismatch');
      if (stringify(previous.args) !== stringify(args)) throw new Error('journal arguments mismatch');
      if (previous.value_wei !== undefined && previous.value_wei !== valueWei) throw new Error('journal native value mismatch');
      if (previous.source_sha256 && previous.source_sha256 !== sourceHash) throw new Error('journal deployment source mismatch');
      if (hash && hash !== previous.hash) throw new Error('journal transaction hash mismatch');
      hash = previous.hash;
      if (!hash && !previous.submission_intent) throw new Error('existing journal has no transaction identity; refusing duplicate submission');
    }
    result = {...previous,...meta,command,address,method:option('--method'),args,hash};
    if (!hash) {result.value_wei = valueWei; if (sourceHash) result.source_sha256 = sourceHash;}
    if (options.includes('--retry-signed-intent')) {
      if (hash) throw new Error('signed-intent retry cannot replace an existing consensus transaction');
      retryPlan = await readRpc(() => prepareSignedIntentRetry({journal:result,publicClient,sender:account.address,
        expectedSender:required('--retry-sender'),consensusAddress:chains.testnetBradbury.consensusMainContract.address}));
      const calldata = sdk.abi.calldata.encode(sdk.abi.calldata.makeCalldataObject(command === 'deploy' ? undefined : required('--method'),args));
      const input = sdk.abi.transactions.serialize(command === 'deploy' ? [deploymentCode,calldata,false] : [calldata,false]);
      expectedOperationHash = submissionFieldsHash([account.address,command === 'deploy' ? viem.zeroAddress : required('--address'),
        chains.testnetBradbury.defaultNumberOfInitialValidators,chains.testnetBradbury.defaultConsensusMaxRotations,input]);
    } else if (!hash && result.submission_intent) {await recoverIntent('submission'); hash = result.hash;}
    if (!hash) {
      required('--out');
      signingKind = 'submission';
      if (command === 'deploy') hash = await client.deployContract({code:deploymentCode,args});
      else if (command === 'write') hash = await client.writeContract({address:required('--address'),functionName:required('--method'),args,value:BigInt(valueWei)});
      else throw new Error('settle requires --hash');
      signingKind = null;
    }
    result.hash = hash;
    save(result);
    console.error(`Transaction Hash: ${hash}`);
    if (command === 'settle' || options.includes('--wait')) {
      // A prior run's return value must never survive a failed live recheck.
      result.trace_verified = false;
      delete result.return_value;
      delete result.trace_identity;
      save(result);
      const deadline = Date.now() + Number(option('--timeout','3600')) * 1000;
      const retryRead = (operation) => retryRpcRead(operation, {
        onRetry: (attempt, attempts) => console.error(`Transient RPC read failure; retry ${attempt}/${attempts}`),
      });
      let last = '';
      while (Date.now() < deadline) {
        const receipt = await retryRead(() => client.getTransaction({hash}));
        const status = String(receipt.statusName || receipt.status).toUpperCase();
        result.receipt = receipt; save(result);
        if (status !== last) {console.error(`Status: ${status}`); last = status;}
        if (status === 'FINALIZED') break;
        if (['CANCELED','UNDETERMINED','VALIDATORS_TIMEOUT','LEADER_TIMEOUT'].includes(status)) throw new Error(`transaction ${status}`);
        if (['ACCEPTED', 'READY_TO_FINALIZE'].includes(status)) {
          result.finalization_capability = await retryRead(() => finalizationCapability(hash)); save(result);
          if (!result.finalize_hash && result.finalize_intent) await recoverIntent('finalize');
          if (result.finalization_capability.eligible && !result.finalize_hash) {
            // A fresh EVM simulation prevents submitting an ineligible finalization.
            await retryRead(() => publicClient.simulateContract({address:chains.testnetBradbury.consensusMainContract.address,
              abi:chains.testnetBradbury.consensusMainContract.abi,functionName:'finalizeTransaction',args:[hash],account:account.address,blockTag:'pending'}));
            signingKind = 'finalize';
            result.finalize_hash = await client.finalizeTransaction({txId:hash});
            signingKind = null; save(result);
          }
        }
        await new Promise(r=>setTimeout(r,5000));
      }
      if (String(result.receipt?.statusName || result.receipt?.status).toUpperCase() !== 'FINALIZED') throw new Error('finalization timeout; rerun with the same journal to resume');
      const [roundNumber,lastRoundData] = await Promise.all([
        retryRead(() => client.getRoundNumber({txId:hash})),
        retryRead(() => client.getLastRoundData({txId:hash})),
      ]);
      result.trace_identity = selectFinalizedRound({hash,receipt:result.receipt,roundNumber,lastRoundData});
      result.trace = await retryRead(() => client.debugTraceTransaction({hash,round:result.trace_identity.round})); save(result);
      result.return_value = decodeFinalizedTrace({hash,trace:result.trace,identity:result.trace_identity,decode:sdk.abi.calldata.decode});
      result.trace_verified = true;
      save(result);
    }
  } else throw new Error('command must be deploy, write, settle, read, code or receipt');
  save(result); console.log(stringify(result));
} catch (error) {console.error('live: '+(error.shortMessage || error.message)); process.exitCode=2;}
