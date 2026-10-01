#!/usr/bin/env node
// Bradbury SDK bridge. Credentials are loaded from the CLI keychain, never saved.
import {execFileSync} from 'node:child_process';
import {dirname, join, resolve} from 'node:path';
import {realpathSync, readFileSync, writeFileSync, renameSync, mkdirSync, existsSync} from 'node:fs';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {retryRpcRead} from './rpc_retry.mjs';
import {createFinalizationChecker} from './finalization.mjs';
import {recordSigningIntent,recoverSigningIntent} from './write_journal.mjs';
import {selectFinalizedRound,decodeFinalizedTrace,validateNonagreementReceipt} from './settled_trace.mjs';
import {prepareSignedIntentRetry,assertUnusedIntentNonce,submissionOperationHash,submissionFieldsHash,validateRetryTransaction} from './signed_retry.mjs';
import {createGasGuard} from './gas_guard.mjs';
import {readPendingQueue} from './queues.mjs';
import {acquireWriterLock} from './writer_lock.mjs';
import {observeReceiptStates} from './receipt_observer.mjs';
import {createSubmissionTTL} from './submission_ttl.mjs';
import {inspectExpiredHead,cancelAbi,createRawStatusReader,readQueueHead,readCanceledProof} from './expired_head.mjs';

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
  const finalizeNonagreement = options.includes('--finalize-nonagreement');
  if (finalizeNonagreement && command !== 'settle') throw new Error('--finalize-nonagreement is limited to settlement of an existing transaction');
  if (options.includes('--retry-signed-intent') && !['deploy','write'].includes(command)) throw new Error('--retry-signed-intent is limited to unresolved deploy/write submissions');
  const writes = ['deploy','write','settle','recover','cancel-expired'].includes(command);
  const ttlSeconds=option('--submission-ttl');
  if(ttlSeconds&&!['deploy','write'].includes(command))throw Error('--submission-ttl applies only to new deploy/write submissions');
  if (writes) {
    const release = acquireWriterLock(fileURLToPath(new URL('../.attaint-writer.lock',import.meta.url)));
    process.once('exit',release);
    process.once('SIGINT',() => {release();process.exit(130);});
    process.once('SIGTERM',() => {release();process.exit(143);});
  }
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
    if(option('--expected-sender')&&account.address.toLowerCase()!==option('--expected-sender').toLowerCase())throw Error('unlocked account differs from pinned expected sender');
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
  const ttl=ttlSeconds?createSubmissionTTL({seconds:Number(ttlSeconds),decodeFunctionData:viem.decodeFunctionData,encodeFunctionData:viem.encodeFunctionData}):null;
  if (writes) {
    const originalEstimate=client.estimateTransactionGas.bind(client);
    const gasGuard = createGasGuard({estimate:async request=>{
      if(ttl&&signingKind==='submission') {
        request={...request,data:ttl.rewrite(request.data)};
        // Protocol deadline range and exact calldata must pass before SDK signing.
        await publicClient.call({account:request.from,to:request.to,data:request.data,value:request.value,blockTag:'pending'});
      }
      return originalEstimate(request);
    },readRpc});
    client.estimateTransactionGas = gasGuard.estimate;
    const block = await readRpc(() => client.request({method:'eth_getBlockByNumber',params:['latest',false]}));
    const blockCap = BigInt(block.gasLimit) * 95n / 100n;
    const requestedCap = BigInt(option('--gas-limit','16777216'));
    if (requestedCap <= 0n || requestedCap > blockCap) throw new Error('--gas-limit exceeds available block gas');
    const sign = account.signTransaction.bind(account);
    account.signTransaction = async (transaction, signingOptions) => {
      gasGuard.assertCanSign();
      if(ttl&&signingKind==='submission') {
        transaction={...transaction,data:ttl.rewrite(transaction.data)};
        await readRpc(()=>publicClient.call({account:account.address,to:transaction.to,data:transaction.data,value:transaction.value,blockTag:'pending'}));
        result.submission_ttl=ttl.metadata();
      }
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
      if(signingKind==='cleanup') {
        const feeCap=BigInt(required('--max-cleanup-fee'));
        const feeRate=BigInt(transaction.maxFeePerGas||transaction.gasPrice||0);
        if(feeRate<=0n||gas*feeRate>feeCap)throw Error('cleanup maximum signed fee exceeds remaining approved budget');
        result.maximum_signed_fee_wei=(gas*feeRate).toString();
      }
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
  if(command==='canceled-proof') {
    const calldata=sdk.abi.calldata.encode(sdk.abi.calldata.makeCalldataObject(required('--method'),args));
    const expectedCalldata=sdk.abi.transactions.serialize([calldata,false]);
    result={...meta,...await readRpc(()=>readCanceledProof({publicClient,hash:required('--hash'),sender:required('--sender'),recipient:required('--address'),expectedCalldata}))};
  } else if(command==='pending-head') {
    result={...meta,...await readRpc(()=>readQueueHead({publicClient,recipient:required('--address')}))};
  } else if(command==='expired-head'||command==='cancel-expired') {
    const hash=required('--hash'),recipient=required('--address');
    const sender=command==='cancel-expired'?account.address:required('--sender');
    const out=option('--out');
    result={...meta,command,hash,address:recipient,sender};
    if(out&&existsSync(out)) {
      const previous=JSON.parse(readFileSync(out,'utf8'));
      if(previous.command!==command||previous.hash!==hash||previous.address!==recipient||previous.sender.toLowerCase()!==sender.toLowerCase()||previous.chainId!==4221)throw Error('expired cleanup journal identity mismatch');
      result={...previous,...result};
    }
    if(command==='cancel-expired'&&!result.cleanup_hash&&result.cleanup_intent)await recoverIntent('cleanup');
    if(!result.cleanup_hash) {
      result.proof=await readRpc(()=>inspectExpiredHead({publicClient,hash,sender,recipient}));
      const simulation=await readRpc(()=>publicClient.simulateContract({address:chains.testnetBradbury.consensusMainContract.address,abi:cancelAbi,functionName:'cancelTransaction',args:[hash],account:sender,blockTag:'pending'}));
      const estimate=await readRpc(()=>publicClient.estimateContractGas({...simulation.request,account:sender}));
      result.gas_estimate=estimate;
      result.gas_price=await readRpc(()=>publicClient.getGasPrice());
      result.estimated_fee_wei=estimate*result.gas_price;
      if(command==='cancel-expired') {
        required('--out');
        // Reread authoritative head/expiry, then simulate again immediately before signing.
        result.proof=await readRpc(()=>inspectExpiredHead({publicClient,hash,sender,recipient}));
        const fresh=await readRpc(()=>publicClient.simulateContract({address:chains.testnetBradbury.consensusMainContract.address,abi:cancelAbi,functionName:'cancelTransaction',args:[hash],account:sender,blockTag:'pending'}));
        const wallet=viem.createWalletClient({chain:chains.testnetBradbury,transport:viem.http(rpc),account});
        signingKind='cleanup';
        result.cleanup_hash=await wallet.writeContract({...fresh.request,account,gas:estimate,gasPrice:result.gas_price,type:'legacy'});
        signingKind=null;save(result);
      }
    }
    if(result.cleanup_hash) {
      result.cleanup_receipt=await readRpc(()=>publicClient.waitForTransactionReceipt({hash:result.cleanup_hash}));save(result);
      if(result.cleanup_receipt.status!=='success')throw Error('expired-head cancellation reverted; refusing retry');
      result.queue_after=await readRpc(()=>readPendingQueue({publicClient,recipient}));
    }
  } else if (command === 'read') {
    result = {...meta,address,method:required('--method'),result:await readRpc(() => client.readContract({address:required('--address'),functionName:required('--method'),args,transactionHashVariant:option('--variant','latest-final')}))};
  } else if (command === 'code') {
    const code = await readRpc(() => client.getContractCode(required('--address')));
    if (!code) throw new Error('empty contract code');
    result = {...meta,address,code_sha256:createHash('sha256').update(code).digest('hex'),code};
  } else if (command === 'receipt') {
    result = {...meta,hash:required('--hash'),receipt:await readRpc(() => client.getTransaction({hash:required('--hash')}))};
  } else if (command === 'evm-receipt') {
    const hash = required('--hash');
    const [receipt,transaction] = await Promise.all([
      readRpc(() => publicClient.getTransactionReceipt({hash})),
      readRpc(() => publicClient.getTransaction({hash})),
    ]);
    result = {...meta,hash,receipt,transaction};
  } else if (command === 'poll') {
    if (!args.every(hash => /^0x[0-9a-f]{64}$/i.test(hash))) throw new Error('poll requires an array of transaction hashes');
    const queue = await readRpc(() => readPendingQueue({publicClient,recipient:required('--address')}));
    let rawReader;
    const states = await observeReceiptStates({hashes:args,
      getTransaction:hash=>readRpc(()=>client.getTransaction({hash})),
      getRawTransaction:async hash=>{rawReader ||=readRpc(()=>createRawStatusReader(publicClient));return readRpc(async()=> (await rawReader)(hash));},
      finalizationCapability:hash=>readRpc(()=>finalizationCapability(hash)),
      getMinimalTransaction:hash=>readRpc(()=>publicClient.readContract({
        address:chains.testnetBradbury.consensusDataContract.address,
        abi:chains.testnetBradbury.consensusDataContract.abi,functionName:'getTransactionData',
        args:[hash,BigInt(Math.round(Date.now()/1000))]}))});
    result = {...meta,observed_at:new Date().toISOString(),queue,states};
  } else if (command === 'gates') {
    const variant=option('--variant','latest-nonfinal');
    if(!['latest-final','latest-nonfinal'].includes(variant))throw Error('gates audit requires a final/current state view');
    const getCount = () => client.readContract({address:required('--address'),functionName:'attestation_count',args:[],transactionHashVariant:variant});
    const before = Number(await readRpc(getCount));
    if (!Number.isSafeInteger(before) || before < 0 || before > 2000) throw new Error('attestation count is outside bounded audit range');
    const gates = [];
    for (let index=0;index<before;index+=4) gates.push(...await Promise.all(Array.from({length:Math.min(4,before-index)},(_,offset)=>
      readRpc(() => client.readContract({address:required('--address'),functionName:'gate',args:[index+offset],transactionHashVariant:variant})))));
    const after = Number(await readRpc(getCount));
    if (before !== after || gates.some((gate,index)=>Number(gate.att_id) !== index)) throw new Error('attestation set changed during audit; retry read-only proof');
    result = {...meta,address:required('--address'),variant,observed_at:new Date().toISOString(),count:before,gates};
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
    if(option('--canceled-retry-anchor')) {
      const anchor=option('--canceled-retry-anchor');
      if(command!=='write'||!/^0x[0-9a-f]{64}$/i.test(anchor))throw Error('invalid canceled replacement anchor');
      if(previous.canceled_retry_anchor&&previous.canceled_retry_anchor!==anchor)throw Error('canceled replacement journal anchor mismatch');
      result.canceled_retry_anchor=anchor;
    }
    if(result.canceled_retry_anchor&&options.includes('--retry-signed-intent'))throw Error('a canceled replacement signing intent has consumed its one authorized attempt; manual resend is forbidden');
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
        if (finalizeNonagreement) validateNonagreementReceipt({hash,receipt});
        if (status === 'FINALIZED') break;
        if (['CANCELED','VALIDATORS_TIMEOUT','LEADER_TIMEOUT'].includes(status) || (status === 'UNDETERMINED' && !finalizeNonagreement)) throw new Error(`transaction ${status}`);
        if (['ACCEPTED', 'READY_TO_FINALIZE'].includes(status) || (status === 'UNDETERMINED' && finalizeNonagreement)) {
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
      if (finalizeNonagreement) {
        validateNonagreementReceipt({hash,receipt:result.receipt});
        result.failure_finalized = true;
        delete result.trace;
        save(result); console.log(stringify(result)); process.exit(0);
      }
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
  } else throw new Error('command must be deploy, write, settle, read, code, receipt or evm-receipt');
  save(result); console.log(stringify(result));
} catch (error) {console.error('live: '+(error.shortMessage || error.message)); process.exitCode=2;}
