import { createClient } from 'genlayer-js';
import { testnetBradbury } from 'genlayer-js/chains';
import { TransactionHashVariant } from 'genlayer-js/types';
import { parseEventLogs, createPublicClient, http, decodeFunctionData, encodeFunctionData } from 'viem';
import { createGasGuard } from '../scripts/gas_guard.mjs';
import { assertFinalizedConsensusReceipt } from '../scripts/finalized_receipt.mjs';
import { createSubmissionTTL } from '../scripts/submission_ttl.mjs';

const EXPLORER = 'https://explorer-bradbury.genlayer.com';
const reader = createClient({ chain: testnetBradbury });
const evmReader = createPublicClient({ chain: testnetBradbury, transport: http(testnetBradbury.rpcUrls.default.http[0]) });
const $ = id => document.getElementById(id);
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v instanceof Map ? Object.fromEntries(v) : v, 2);
const link = (label, path) => { const a = document.createElement('a'); a.textContent = label; a.href = `${EXPLORER}/${path}`; a.target = '_blank'; a.rel = 'noopener'; return a; };
let deployment, account, writer, envelope, pending, busy = false, pollTimer, generation = 0, walletOperation = '';
let walletEstimate, submissionGasGuard, submissionTTL;
const read = (method, args = []) => reader.readContract({ address: deployment.contract, functionName: method, args, jsonSafeReturn: true, transactionHashVariant: TransactionHashVariant.LATEST_FINAL });
const notify = message => { $('live-notice').textContent = message; };
function controls() {
  $('live-send').disabled = busy || !account || !envelope || !deployment?.contract;
  $('live-connect').disabled = busy || !deployment?.contract;
  $('live-envelope').disabled = busy;
  $('live-example').disabled = busy;
  $('live-connect').textContent = account ? `${account.slice(0, 6)}…${account.slice(-4)} · Bradbury` : 'Connect wallet';
  $('live-finalize').disabled = busy || !writer;
  $('live-check').disabled = busy || !deployment?.contract;
  $('live-refresh').disabled = busy || !deployment?.contract;
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
  try {
    notify('Reading finalized state from Bradbury…');
    const policy = await read('get_policy', [deployment.policy_id]);
    if (policy.policy_hash !== deployment.policy_hash) throw new Error('Published policy hash differs from chain state.');
    $('live-policy').textContent = `${policy.blocking.join(', ')} · minimum evidence level ${policy.min_level} · ${policy.min_rounds} class rounds`;
    const id = Number($('live-attestation').value);
    if (!Number.isSafeInteger(id) || id < 0) throw new Error('Enter a nonnegative attestation ID.');
    const gate = validateGate(await read('gate', [id]));
    if (epoch !== generation) return;
    showGate(gate);
    notify(`Finalized chain record #${id}: ${gate.package} ${gate.from_version} → ${gate.to_version}. This is a bounded evidence verdict, not a whole-package safety guarantee.`);
  } catch (error) { if (epoch === generation) { $('live-result').textContent = 'INCONCLUSIVE · chain read failed · exit 2'; $('live-gate').textContent = ''; notify(error.shortMessage || error.message); } }
}
async function connect() {
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
        await evmReader.call({ account, to: tx.to, data, value: BigInt(tx.value || 0), blockTag: 'pending' });
        pending.submission_ttl = submissionTTL.metadata();
        request = { ...request, params: [{ ...tx, data }, ...request.params.slice(1)] };
      }
      if (request.method === 'eth_sendTransaction' && request.params?.[0]?.gas) {
        const tx = request.params[0], cap = 16777216n, estimate = BigInt(tx.gas);
        if (estimate > cap) throw new Error('Transaction exceeds the Bradbury gas cap. No transaction was sent.');
        const headroom = (estimate * 3n + 1n) / 2n;
        request = { ...request, params: [{ ...tx, gas: '0x' + (headroom < cap ? headroom : cap).toString(16) }, ...request.params.slice(1)] };
      }
      const result = await provider.request(request);
      if (request.method === 'eth_sendTransaction' && pending && walletOperation === 'attest') { pending.evmHash = result; pending.hash = result; pending.status = 'EVM_PENDING'; renderTransaction(); }
      if (request.method === 'eth_sendTransaction' && pending && walletOperation === 'finalize') pending.finalize_hash = result;
      return result;
    } };
    writer = createClient({ chain: testnetBradbury, account, provider: tracked });
    walletEstimate = writer.estimateTransactionGas.bind(writer);
    notify('Wallet connected. An attestation spends Bradbury testnet fees; review the transaction in your wallet.');
  } catch (error) { notify(error.shortMessage || error.message); }
  controls();
}
function renderTransaction() {
  const box = $('live-transaction'); box.replaceChildren();
  if (!pending?.hash) return;
  box.append(link(`${pending.status} · ${pending.hash}`, `tx/${pending.hash}`));
  box.append(document.createElement('br'), document.createTextNode('Copy or download this record before closing. No browser storage is used.'));
  $('live-download').hidden = false;
}
async function poll() {
  if (!pending || !pending.hash) return;
  try {
    if (pending.status === 'EVM_PENDING') {
      const receipt = await reader.getTransactionReceipt({ hash: pending.evmHash });
      if (receipt.status === 'reverted') { pending.status = 'EVM_REVERTED'; throw new Error('Wallet transaction reverted.'); }
      const events = parseEventLogs({ abi: testnetBradbury.consensusMainContract.abi, eventName: 'NewTransaction', logs: receipt.logs });
      const hash = events[0]?.args?.txId;
      if (!hash) throw new Error('Waiting for the consensus transaction ID. Do not resubmit.');
      pending.hash = hash; pending.status = 'SUBMITTED';
    }
    const receipt = await reader.getTransaction({ hash: pending.hash });
    pending.receipt = receipt; pending.status = receipt.statusName || receipt.status; renderTransaction();
    $('live-receipt').textContent = json(receipt);
    $('live-finalize').hidden = true;
    if (['ACCEPTED', 'READY_TO_FINALIZE'].includes(pending.status)) {
      const [eligible] = await evmReader.readContract({ address: testnetBradbury.consensusDataContract.address, abi: testnetBradbury.consensusDataContract.abi, functionName: 'canFinalize', args: [pending.hash, BigInt(Math.floor(Date.now() / 1000))] });
      $('live-finalize').hidden = !eligible || Boolean(pending.finalize_hash);
      controls();
    }
    if (pending.status === 'FINALIZED') {
      assertFinalizedConsensusReceipt(receipt, {hash: pending.hash, recipient: deployment.contract, method: 'request_attestation'});
      if (!pending.expected) { notify('Consensus transaction finalized successfully. Enter its attestation ID and use Read chain gate to inspect the update.'); return; }
      // Match the update and sender, rather than guessing the ID from a global counter.
      const count = Number(await read('attestation_count'));
      const floor = pending.countBefore ?? Math.max(0, count - 100);
      for (let id = count - 1; id >= floor; id--) {
        const gate = await read('gate', [id]);
        if (gate.envelope_hash === pending.expected.hash && Number(gate.policy_id) === deployment.policy_id && gate.requester?.toLowerCase() === pending.account.toLowerCase()) {
          validateGate(gate, pending.expected); pending.attestation_id = id; pending.gate = gate;
          $('live-attestation').value = id; showGate(gate); notify(`Finalized successfully. Verified on-chain attestation #${id}.`); return;
        }
      }
      throw new Error('Execution succeeded, but the matching attestation could not be read. Inspect the receipt before retrying.');
    }
    if (['UNDETERMINED', 'CANCELED', 'EVM_REVERTED'].includes(pending.status)) throw new Error(`Transaction ended with ${pending.status}; no successful attestation is claimed.`);
    notify(`${pending.status}: waiting for finalized consensus. An accepted decision is provisional.`);
  } catch (error) {
    notify(error.shortMessage || error.message);
    if (pending.status === 'FINALIZED' || ['UNDETERMINED', 'CANCELED', 'EVM_REVERTED'].includes(pending.status)) {
      $('live-result').textContent = 'INCONCLUSIVE · transaction verification failed · exit 2';
      $('live-result').className = 'live-result INCONCLUSIVE';
      $('live-gate').textContent = '';
      return;
    }
  }
  if (Date.now() < pending.deadline) pollTimer = setTimeout(poll, 12000);
  else notify('Automatic checks paused after 30 minutes. Keep the hash and use Check transaction to resume.');
}
async function send() {
  if (busy || !writer || !envelope) return;
  if (pending && !['FINALIZED', 'CANCELED', 'UNDETERMINED', 'EVM_REVERTED'].includes(pending.status)) { notify('A transaction is still pending. Inspect it before starting another.'); return; }
  busy = true; controls();
  try {
    const policy = await read('get_policy', [deployment.policy_id]);
    if (policy.policy_hash !== deployment.policy_hash) throw new Error('Immutable policy mismatch.');
    const countBefore = Number(await read('attestation_count'));
    pending = { expected: envelope, account, countBefore, status: 'AWAITING_WALLET', deadline: Date.now() + 30 * 60 * 1000 };
    walletOperation = 'attest';
    submissionTTL = createSubmissionTTL({ seconds: 21600, decodeFunctionData, encodeFunctionData });
    submissionGasGuard = createGasGuard({estimate: async request => {
      const data = submissionTTL.rewrite(request.data);
      await evmReader.call({ account, to: request.to, data, value: BigInt(request.value || 0), blockTag: 'pending' });
      return walletEstimate({ ...request, data });
    }, readRpc: operation => operation()});
    writer.estimateTransactionGas = submissionGasGuard.estimate;
    notify('Confirm the attestation in your wallet. Keep this page open until you copy the transaction hash.');
    const hash = await writer.writeContract({ address: deployment.contract, functionName: 'request_attestation', args: [deployment.policy_id, envelope.body.package, envelope.body.from_version, envelope.body.to_version, 1, envelope.hash, envelope.evidence], value: 0n });
    pending.hash = hash; pending.status = 'SUBMITTED'; renderTransaction();
    clearTimeout(pollTimer); await poll();
  } catch (error) {
    notify(`${error.shortMessage || error.message}. No automatic retry was sent.`);
    if (pending?.hash) { clearTimeout(pollTimer); pollTimer = setTimeout(poll, 12000); } else pending = null;
  } finally { walletOperation = ''; if (writer) writer.estimateTransactionGas = walletEstimate; busy = false; controls(); }
}
$('live-connect').onclick = connect;
$('live-send').onclick = send;
$('live-refresh').onclick = inspect;
$('live-example').onclick = async () => { try { const r = await fetch('/event-stream.json'); if (!r.ok) throw new Error('Example is unavailable.'); await loadEnvelope(await r.json()); } catch (error) { notify(error.message); } };
$('live-envelope').onchange = async event => { try { const file = event.target.files[0]; if (!file) return; if (file.size > 100000) throw new Error('Envelope file is too large.'); await loadEnvelope(JSON.parse(await file.text())); } catch (error) { envelope = null; controls(); notify(error.message); } };
$('live-check').onclick = async () => {
  const hash = $('live-hash').value.trim();
  if (!/^0x[0-9a-f]{64}$/i.test(hash)) { notify('Enter the GenLayer consensus transaction hash.'); return; }
  if (!pending || pending.hash !== hash) pending = { hash, status: 'SUBMITTED', deadline: Date.now() + 30 * 60 * 1000 };
  clearTimeout(pollTimer); pending.deadline = Date.now() + 30 * 60 * 1000; await poll();
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
  $('live-attestation').value = deployment.first_attestation_id ?? 0;
  controls(); await inspect();
} catch (error) { controls(); notify(error.message); }
