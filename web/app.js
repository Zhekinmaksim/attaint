import { createClient } from 'genlayer-js';
import { testnetBradbury } from 'genlayer-js/chains';
import { parseEventLogs, createPublicClient, http, decodeFunctionData, encodeFunctionData } from 'viem';
import { createGasGuard } from '../scripts/gas_guard.mjs';
import { assertFinalizedConsensusReceipt } from '../scripts/finalized_receipt.mjs';
import { createSubmissionTTL } from '../scripts/submission_ttl.mjs';
import { confirmProjectedCancellation } from '../scripts/raw_cancellation.mjs';
import { assertReadCapacity } from '../scripts/read_capacity.mjs';
import { readFinalizedContract } from '../scripts/finalized_read.mjs';

const EXPLORER = 'https://explorer-bradbury.genlayer.com';
const reader = createClient({ chain: testnetBradbury });
const evmReader = createPublicClient({ chain: testnetBradbury, transport: http(testnetBradbury.rpcUrls.default.http[0]) });
const $ = id => document.getElementById(id);
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v instanceof Map ? Object.fromEntries(v) : v, 2);
const link = (label, path) => { const a = document.createElement('a'); a.textContent = label; a.href = `${EXPLORER}/${path}`; a.target = '_blank'; a.rel = 'noopener'; return a; };
let deployment, account, writer, envelope, pending, busy = false, pollTimer, generation = 0, walletOperation = '', deploymentVerified = false;
let walletEstimate, submissionGasGuard, submissionTTL, pollGeneration = 0;
const FOLLOW_WINDOW_MS = 6 * 60 * 60 * 1000;
const read = (method, args = []) => readFinalizedContract({ client: reader, publicClient: evmReader, address: deployment.contract, functionName: method, args });
const notify = message => { $('live-notice').textContent = message; };
function awaitRequestGate() {
  generation++;
  $('live-result').textContent = 'PENDING · no finalized gate for this request';
  $('live-result').className = 'live-result';
  $('live-gate').textContent = '';
}
function controls() {
  $('live-send').disabled = busy || !account || !envelope || !deploymentVerified;
  $('live-connect').disabled = busy || !deploymentVerified;
  $('live-envelope').disabled = busy;
  $('live-example').disabled = busy;
  $('live-connect').textContent = account ? `${account.slice(0, 6)}…${account.slice(-4)} · Bradbury` : 'Connect wallet';
  $('live-finalize').disabled = busy || !writer;
  $('live-check').disabled = busy || !deploymentVerified;
  $('live-refresh').disabled = busy || !deploymentVerified;
  $('live-hash').disabled = busy;
}
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
async function digest(text) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function loadEnvelope(value) {
  const keys = ['version', 'registry', 'package', 'from_version', 'to_version', 'pin', 'facts', 'fetched_from', 'author_note'];
  const body = {};
  for (const k of keys) if (value[k] !== undefined && value[k] !== null && value[k] !== '' && (!Array.isArray(value[k]) || value[k].length)) body[k] = value[k];
  if (body.version !== 'attaint/1' || body.registry !== 'npm' || !body.package || !body.from_version || !body.to_version || !body.pin || !body.facts) throw new Error('Use a registry envelope produced by cli/envelope.py.');
  const evidence = canonical(body);
  if (new TextEncoder().encode(evidence).length > 12288) throw new Error('Envelope exceeds the 12,288-byte contract limit.');
  const hash = await digest(evidence);
  if (value.envelope_hash && value.envelope_hash !== hash) throw new Error('Envelope hash does not match its contents.');
  envelope = { body, evidence, hash };
  $('live-object').textContent = `${body.package} ${body.from_version} → ${body.to_version} · level 1 · ${new TextEncoder().encode(evidence).length} bytes`;
  $('live-evidence').textContent = json(body);
  notify('Envelope loaded. File excerpts come from the local builder; registry metadata is checked by the contract.');
  controls();
}
function validateGate(gate, expected) {
  if (Number(gate.policy_id) !== deployment.policy_id || gate.policy_hash !== deployment.policy_hash) throw new Error('Gate does not match the published immutable policy.');
  if (expected && (gate.envelope_hash !== expected.hash || gate.package !== expected.body.package || gate.from_version !== expected.body.from_version || gate.to_version !== expected.body.to_version)) throw new Error('Gate belongs to another update.');
  if (!['CLEAN', 'RISK', 'INCONCLUSIVE'].includes(gate.gate)) throw new Error('Unrecognized gate result.');
  return gate;
}
function showGate(gate) {
  $('live-result').textContent = `${gate.gate} · ${gate.verdict} · exit ${{ CLEAN: 0, RISK: 1, INCONCLUSIVE: 2 }[gate.gate]}`;
  $('live-result').className = 'live-result ' + gate.gate;
  $('live-gate').textContent = json(gate);
}
async function inspect() {
  const epoch = ++generation;
  $('live-result').textContent = 'PENDING · reading current gate';
  $('live-result').className = 'live-result';
  $('live-gate').textContent = '';
  try {
    notify('Reading finalized state from Bradbury…');
    const policy = await read('get_policy', [deployment.policy_id]);
    if (policy.policy_hash !== deployment.policy_hash) throw new Error('Published policy hash differs from chain state.');
    $('live-policy').textContent = `${policy.blocking.join(', ')} · minimum evidence level ${policy.min_level} · ${policy.min_rounds} class rounds`;
    const id = Number($('live-attestation').value);
    if (!Number.isSafeInteger(id) || id < 0) throw new Error('Enter a nonnegative attestation ID.');
    const gate = validateGate(await read('gate', [id]));
    if (Number(gate.att_id) !== id) throw new Error('Gate attestation ID does not match the requested record.');
    if (id === deployment.first_attestation_id) {
      if (gate.envelope_hash !== deployment.first_envelope_hash) throw new Error('Published example evidence does not match the chain gate.');
      const hash = deployment.transactions['first-attestation'];
      const receipt = await reader.getTransaction({hash});
      assertFinalizedConsensusReceipt(receipt, {hash, recipient:deployment.contract, method:'request_attestation'});
      if (epoch !== generation) return;
      $('live-receipt').textContent = json(receipt);
      $('live-hash').value = hash;
    }
    if (epoch !== generation) return;
    showGate(gate);
    notify(`Finalized chain record #${id}: ${gate.package} ${gate.from_version} → ${gate.to_version}. This is a bounded evidence verdict, not a whole-package safety guarantee.`);
  } catch (error) { if (epoch === generation) { $('live-result').textContent = 'INCONCLUSIVE · chain read failed · exit 2'; $('live-result').className = 'live-result INCONCLUSIVE'; $('live-gate').textContent = ''; notify(error.shortMessage || error.message); } }
}
async function connect() {
  if (busy) return;
  busy = true; controls();
  try {
    if (!window.ethereum) throw new Error('Open in a browser with an EIP-1193 wallet, such as Rabby or MetaMask.');
    const provider = window.ethereum, chainId = '0x107d';
    const accounts = await provider.request({ method: 'eth_requestAccounts' });
    try { await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] }); }
    catch (error) {
      if (Number(error.code) !== 4902) throw error;
      await provider.request({ method: 'wallet_addEthereumChain', params: [{ chainId, chainName: testnetBradbury.name, nativeCurrency: testnetBradbury.nativeCurrency, rpcUrls: [...testnetBradbury.rpcUrls.default.http], blockExplorerUrls: [EXPLORER] }] });
      await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId }] });
    }
    if (Number(await provider.request({ method: 'eth_chainId' })) !== 4221 || !accounts[0]) throw new Error('Select an account on Bradbury chain 4221.');
    account = accounts[0];
    const tracked = { request: async request => {
      if (request.method === 'eth_sendTransaction' && walletOperation === 'attest') {
        if (!account || !writer || Number(await provider.request({ method: 'eth_chainId' })) !== 4221) throw new Error('Wallet account or network changed; no transaction was sent.');
        submissionGasGuard?.assertCanSign();
        if (!submissionTTL || !request.params?.[0]?.data) throw new Error('Missing estimated submission deadline; no transaction was sent.');
        const tx = request.params[0], data = submissionTTL.rewrite(tx.data);
        await evmReader.call({ account, to: tx.to, data, value: BigInt(tx.value || 0), gas: 16777216n, blockTag: 'pending' });
        const [selected, selectedChain] = await Promise.all([provider.request({method:'eth_accounts'}),provider.request({method:'eth_chainId'})]);
        if (!account || !writer || selected[0]?.toLowerCase() !== pending.account.toLowerCase() || account.toLowerCase() !== pending.account.toLowerCase() || tx.from?.toLowerCase() !== pending.account.toLowerCase() || Number(selectedChain) !== 4221) throw new Error('Wallet account or network changed; no transaction was sent.');
        pending.submission_ttl = submissionTTL.metadata();
        request = { ...request, params: [{ ...tx, data }, ...request.params.slice(1)] };
      }
      if (request.method === 'eth_sendTransaction' && request.params?.[0]?.gas) {
        const tx = request.params[0], cap = 16777216n, estimate = BigInt(tx.gas);
        if (estimate > cap) throw new Error('Transaction exceeds the Bradbury gas cap. No transaction was sent.');
        const headroom = (estimate * 3n + 1n) / 2n;
        request = { ...request, params: [{ ...tx, gas: '0x' + (headroom < cap ? headroom : cap).toString(16) }, ...request.params.slice(1)] };
      }
      if (request.method === 'eth_sendTransaction' && pending && walletOperation === 'attest') pending.broadcast_attempted = true;
      const result = await provider.request(request);
      if (request.method === 'eth_sendTransaction' && pending && walletOperation === 'attest') { pending.evmHash = result; pending.hash = result; pending.status = 'EVM_PENDING'; renderTransaction(); }
      if (request.method === 'eth_sendTransaction' && pending && walletOperation === 'finalize') pending.finalize_hash = result;
      return result;
    } };
    writer = createClient({ chain: testnetBradbury, account, provider: tracked });
    walletEstimate = writer.estimateTransactionGas.bind(writer);
    notify('Wallet connected. An attestation spends Bradbury testnet fees; review the transaction in your wallet.');
  } catch (error) { notify(error.shortMessage || error.message); }
  finally { busy = false; controls(); }
}
function renderTransaction() {
  const box = $('live-transaction'); box.replaceChildren();
  if (!pending) return;
  $('live-download').hidden = false;
  if (!pending.hash) { box.textContent = 'Submission unconfirmed. Check wallet activity for a transaction hash before trying again.'; return; }
  box.append(link(`${pending.status} · ${pending.hash}`, `tx/${pending.hash}`));
  box.append(document.createElement('br'), document.createTextNode('Copy or download this record before closing. No browser storage is used.'));
  $('live-download').hidden = false;
}
async function poll() {
  if (!pending || !pending.hash) return;
  const request = pending, ticket = ++pollGeneration;
  const current = () => pending === request && ticket === pollGeneration;
  clearTimeout(pollTimer);
  try {
    if (request.status === 'EVM_PENDING') {
      const receipt = await reader.getTransactionReceipt({ hash: request.evmHash });
      if (!current()) return;
      if (receipt.status === 'reverted') { request.status = 'EVM_REVERTED'; throw new Error('Wallet transaction reverted.'); }
      const events = parseEventLogs({ abi: testnetBradbury.consensusMainContract.abi, eventName: 'NewTransaction', logs: receipt.logs });
      const hash = events[0]?.args?.txId;
      if (!hash) throw new Error('Waiting for the consensus transaction ID. Do not resubmit.');
      request.hash = hash; request.status = 'SUBMITTED';
    }
    const receipt = await reader.getTransaction({ hash: request.hash });
    if (!current()) return;
    if (receipt.txId?.toLowerCase() !== request.hash.toLowerCase() || receipt.recipient?.toLowerCase() !== deployment.contract.toLowerCase()) throw new Error('Consensus receipt identity mismatch; keep the original request hash.');
    request.receipt = receipt; request.status = receipt.statusName || (Number(receipt.status) === 14 ? 'LEADER_REVEALING' : receipt.status);
    if (request.status === 'CANCELED') {
      request.status = 'CANCELLATION_UNCONFIRMED';
      renderTransaction();
      const cancellation = await confirmProjectedCancellation({publicClient:evmReader,hash:request.hash,recipient:deployment.contract});
      if (!current()) return;
      Object.assign(request, cancellation);
    }
    renderTransaction();
    $('live-receipt').textContent = json(receipt);
    $('live-finalize').hidden = true;
    if (['ACCEPTED', 'READY_TO_FINALIZE'].includes(request.status)) {
      const [eligible, , eligibleAt] = await evmReader.readContract({ address: testnetBradbury.consensusDataContract.address, abi: testnetBradbury.consensusDataContract.abi, functionName: 'canFinalize', args: [request.hash, BigInt(Math.floor(Date.now() / 1000))] });
      if (!current()) return;
      request.finalization_eligible_at = String(eligibleAt);
      $('live-finalize').hidden = !eligible || Boolean(request.finalize_hash);
      controls();
    }
    if (request.status === 'FINALIZED') {
      assertFinalizedConsensusReceipt(receipt, {hash: request.hash, recipient: deployment.contract, method: 'request_attestation'});
      if (!request.expected) { notify('Consensus transaction finalized successfully. Enter its attestation ID and use Read chain gate to inspect the update.'); return; }
      // Match the update and sender, rather than guessing the ID from a global counter.
      const count = Number(await read('attestation_count'));
      if (!current()) return;
      if (!Number.isSafeInteger(count) || count < 0 || count > 100) throw new Error('Attestation history exceeds the bounded public-instance limit.');
      const floor = request.countBefore ?? Math.max(0, count - 100);
      for (let id = count - 1; id >= floor; id--) {
        const gate = await read('gate', [id]);
        if (!current()) return;
        if (Number(gate.att_id) !== id) throw new Error('Gate attestation ID does not match the requested record.');
        if (gate.envelope_hash === request.expected.hash && Number(gate.policy_id) === deployment.policy_id && gate.requester?.toLowerCase() === request.account.toLowerCase()) {
          validateGate(gate, request.expected); request.attestation_id = id; request.gate = gate;
          $('live-attestation').value = id; showGate(gate); notify(`Finalized successfully. Verified on-chain attestation #${id}.`); return;
        }
      }
      throw new Error('Execution succeeded, but the matching attestation could not be read. Inspect the receipt before retrying.');
    }
    if (['CANCELED', 'EVM_REVERTED'].includes(request.status)) throw new Error(`Transaction ended with ${request.status}; no successful attestation is claimed.`);
    const finalityTime = request.finalization_eligible_at ? ` Finalization opens at ${new Date(Number(request.finalization_eligible_at) * 1000).toLocaleTimeString()}.` : '';
    notify(`${request.status}: waiting for finalized consensus.${finalityTime} An accepted decision is provisional; keep this transaction hash.`);
  } catch (error) {
    if (!current()) return;
    notify(error.shortMessage || error.message);
    if (request.status === 'FINALIZED' || ['CANCELED', 'EVM_REVERTED'].includes(request.status)) {
      $('live-result').textContent = 'INCONCLUSIVE · transaction verification failed · exit 2';
      $('live-result').className = 'live-result INCONCLUSIVE';
      $('live-gate').textContent = '';
      return;
    }
  }
  if (!current()) return;
  if (Date.now() < request.deadline) pollTimer = setTimeout(poll, 12000);
  else notify('Automatic checks paused after six hours. Keep the hash and use Check transaction to resume.');
}
async function send() {
  if (busy || !writer || !envelope || !deploymentVerified) return;
  if (pending && !['FINALIZED', 'CANCELED', 'EVM_REVERTED'].includes(pending.status)) { notify('A transaction is still pending. Inspect it before starting another.'); return; }
  const sendWriter = writer, sendAccount = account, sendEnvelope = envelope, originalEstimate = walletEstimate;
  const assertSession = () => {
    if (writer !== sendWriter || account !== sendAccount) throw new Error('Wallet account or network changed; reconnect before sending.');
  };
  busy = true; controls();
  try {
    notify('Checking public-node read capacity before requesting a signature…');
    await assertReadCapacity({publicClient:evmReader,recipient:deployment.contract});
    assertSession();
    const policy = await read('get_policy', [deployment.policy_id]);
    assertSession();
    if (policy.policy_hash !== deployment.policy_hash) throw new Error('Immutable policy mismatch.');
    const countBefore = Number(await read('attestation_count'));
    assertSession();
    if (!Number.isSafeInteger(countBefore) || countBefore < 0 || countBefore > 100) throw new Error('Attestation history exceeds the bounded public-instance limit.');
    for (let id = countBefore - 1; id >= 0; id--) {
      const existing = await read('gate', [id]);
      assertSession();
      if (Number(existing.policy_id) === deployment.policy_id && existing.requester?.toLowerCase() === sendAccount.toLowerCase() && existing.envelope_hash === sendEnvelope.hash) {
        validateGate(existing, sendEnvelope);
        $('live-attestation').value = id;
        showGate(existing);
        notify(`Your finalized attestation #${id} already covers this evidence. Reused its live gate; no transaction was sent.`);
        return;
      }
    }
    pending = { expected: sendEnvelope, account:sendAccount, countBefore, status: 'AWAITING_WALLET', deadline: Date.now() + FOLLOW_WINDOW_MS };
    awaitRequestGate();
    walletOperation = 'attest';
    submissionTTL = createSubmissionTTL({ seconds: 21600, decodeFunctionData, encodeFunctionData });
    submissionGasGuard = createGasGuard({estimate: async request => {
      assertSession();
      const data = submissionTTL.rewrite(request.data);
      await evmReader.call({ account:sendAccount, to: request.to, data, value: BigInt(request.value || 0), gas: 16777216n, blockTag: 'pending' });
      assertSession();
      return originalEstimate({ ...request, data });
    }, readRpc: operation => operation()});
    sendWriter.estimateTransactionGas = submissionGasGuard.estimate;
    notify('Confirm the attestation in your wallet. Keep this page open until you copy the transaction hash.');
    assertSession();
    const hash = await sendWriter.writeContract({ address: deployment.contract, functionName: 'request_attestation', args: [deployment.policy_id, sendEnvelope.body.package, sendEnvelope.body.from_version, sendEnvelope.body.to_version, 1, sendEnvelope.hash, sendEnvelope.evidence], value: 0n });
    pending.hash = hash; pending.status = 'SUBMITTED'; renderTransaction();
    clearTimeout(pollTimer); await poll();
  } catch (error) {
    notify(`${error.shortMessage || error.message}. No automatic retry was sent.`);
    if (pending?.hash) { clearTimeout(pollTimer); pollTimer = setTimeout(poll, 12000); }
    else {
      let cause = error, declined = false;
      for (let depth = 0; cause && depth < 8; depth++, cause = cause.cause) if (Number(cause.code) === 4001) declined = true;
      if (pending?.broadcast_attempted && !declined) {
        pending.status = 'SUBMISSION_UNCONFIRMED';
        renderTransaction();
        notify('The wallet send was attempted, but no hash was returned. Check wallet activity and resume its hash before another request.');
      } else pending = null;
      $('live-result').textContent = declined ? 'NOT SUBMITTED · wallet request declined' : 'INCONCLUSIVE · submission not confirmed · exit 2';
      $('live-result').className = 'live-result INCONCLUSIVE';
      $('live-gate').textContent = '';
    }
  } finally { walletOperation = ''; sendWriter.estimateTransactionGas = originalEstimate; busy = false; controls(); }
}
$('live-connect').onclick = connect;
$('live-send').onclick = send;
$('live-refresh').onclick = inspect;
$('live-example').onclick = async () => { try { const r = await fetch('/event-stream.json'); if (!r.ok) throw new Error('Example is unavailable.'); await loadEnvelope(await r.json()); } catch (error) { notify(error.message); } };
$('live-envelope').onchange = async event => { try { const file = event.target.files[0]; if (!file) return; if (file.size > 100000) throw new Error('Envelope file is too large.'); await loadEnvelope(JSON.parse(await file.text())); } catch (error) { envelope = null; controls(); notify(error.message); } };
$('live-check').onclick = async () => {
  if (!deployment) { notify('Wait for the verified deployment manifest before checking a transaction.'); return; }
  const hash = $('live-hash').value.trim();
  if (!/^0x[0-9a-f]{64}$/i.test(hash)) { notify('Enter the GenLayer consensus transaction hash.'); return; }
  if (!pending || pending.hash !== hash) { pending = { hash, status: 'SUBMITTED', deadline: Date.now() + FOLLOW_WINDOW_MS }; awaitRequestGate(); }
  clearTimeout(pollTimer); pending.deadline = Date.now() + FOLLOW_WINDOW_MS; await poll();
};
$('live-download').onclick = () => {
  const blob = new Blob([json({ version: 'attaint-browser/1', chain_id: 4221, contract: deployment.contract, ...pending })], { type: 'application/json' });
  const url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = 'attaint-transaction.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
};
$('live-finalize').onclick = async () => {
  if (!writer || !pending || !['ACCEPTED', 'READY_TO_FINALIZE'].includes(pending.status) || busy) return;
  busy = true; controls();
  try {
    const [eligible] = await evmReader.readContract({ address: testnetBradbury.consensusDataContract.address, abi: testnetBradbury.consensusDataContract.abi, functionName: 'canFinalize', args: [pending.hash, BigInt(Math.floor(Date.now() / 1000))] });
    if (!eligible) throw new Error('The chain has not opened finalization for this transaction.');
    await evmReader.simulateContract({ address: testnetBradbury.consensusMainContract.address, abi: testnetBradbury.consensusMainContract.abi, functionName: 'finalizeTransaction', args: [pending.hash], account, blockTag: 'pending' });
    walletOperation = 'finalize';
    pending.finalize_hash = await writer.finalizeTransaction({ txId: pending.hash });
    $('live-finalize').hidden = true;
    notify(`Finalization submitted: ${pending.finalize_hash}. Waiting for the chain record.`);
    await poll();
  } catch (error) { notify(error.shortMessage || error.message); }
  finally { walletOperation = ''; busy = false; controls(); }
};
function disconnect() { account = null; writer = null; notify('Wallet account or network changed. Reconnect before sending.'); controls(); }
window.ethereum?.on?.('accountsChanged', disconnect); window.ethereum?.on?.('chainChanged', disconnect);
try {
  const response = await fetch('/deployment.json', { cache: 'no-store' }); if (!response.ok) throw new Error('The live gate awaits a verified Bradbury deployment and first finalized attestation. Source and pinned evidence remain available.');
  deployment = await response.json();
  if (deployment.chain_id !== 4221 || !/^0x[0-9a-f]{40}$/i.test(deployment.contract) || !Number.isSafeInteger(deployment.policy_id) || !/^[0-9a-f]{64}$/.test(deployment.policy_hash)) throw new Error('No verified Bradbury deployment is published yet.');
  $('live-contract').replaceChildren(link(deployment.contract, `address/${deployment.contract}`));
  const code = await reader.getContractCode(deployment.contract);
  if (await digest(code) !== deployment.code_sha256) throw new Error('Live contract source does not match the published release.');
  deploymentVerified = true;
  $('live-attestation').value = deployment.first_attestation_id ?? 0;
  const sample = await fetch('/event-stream.json');
  if (sample.ok) await loadEnvelope(await sample.json());
  controls(); await inspect();
} catch (error) { deploymentVerified = false; controls(); $('live-result').textContent = 'INCONCLUSIVE · deployment could not be verified · exit 2'; $('live-result').className = 'live-result INCONCLUSIVE'; notify(error.shortMessage || error.message); }
