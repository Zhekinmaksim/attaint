import { build } from 'esbuild';
import { readFile, writeFile, copyFile, mkdir, cp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { copyCorpusEvidence } from './public_evidence.mjs';

await build({ entryPoints: ['web/app.js'], bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, outfile: 'web/app.bundle.js' });
await copyFile('corpus/scan-report.json', 'web/mechanical-report.json');
await copyFile('corpus/recovered-pins.json', 'web/recovered-pins.json');
await copyFile('corpus/event-stream-3.3.4-3.3.5.json', 'web/event-stream.json');
await copyFile('contracts/attaint.py', 'web/attaint.py');
await copyFile('contracts/attaint.bradbury.py', 'web/attaint.bradbury.py');
await copyFile('cli/envelope.py', 'web/envelope.py');
await copyFile('cli/attaint_gate.py', 'web/attaint_gate.py');
await copyFile('spec/classes.md', 'web/classes.md');
await copyFile('README.md', 'web/README.md');
await copyFile('FINDINGS.md', 'web/FINDINGS.md');
await copyFile('SUBMISSION.md', 'web/SUBMISSION.md');
await cp('spec', 'web/spec', {recursive: true});
await cp('corpus', 'web/corpus', {recursive: true});
for (const dir of ['contracts', 'cli', 'scripts']) {
  await cp(dir, `web/${dir}`, {recursive: true, filter: source => !source.includes('__pycache__') && !source.endsWith('.pyc')});
}
await copyFile('package.json', 'web/package.json');
await copyFile('requirements-dev.txt', 'web/requirements-dev.txt');
const baseline = JSON.parse(await readFile('corpus/scan-report.json', 'utf8'));
if (baseline.control_total !== 45 || baseline.controls.length !== 45) throw new Error('Mechanical baseline must contain the original 45 updates.');
let html = await readFile('web/index.html', 'utf8');
const grid = baseline.controls.map(row => ({ name: `${row.package} ${row.from} → ${row.to}`, hits: row.classes }));
html = html.replace(/\/\* BEGIN REAL GRID \*\/[\s\S]*?\/\* END REAL GRID \*\//, `/* BEGIN REAL GRID */\nvar GRID = ${JSON.stringify(grid)};\n/* END REAL GRID */`);
await writeFile('web/index.html', html);
for (const path of ['web/deployment.json', 'web/consensus-report.json', 'web/ci-verification.json', 'web/receipts', 'web/runs', 'web/diagnostics']) {
  await rm(path, {recursive: true, force: true});
}
let deployment;
try { deployment = JSON.parse(await readFile('runs/deployment.json', 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
if (deployment) {
  const compiled = await readFile('contracts/attaint.bradbury.py');
  if (deployment.chain_id !== 4221 || deployment.code_sha256 !== createHash('sha256').update(compiled).digest('hex')) throw new Error('Release manifest does not match the Bradbury artifact.');
  for (const name of ['deploy', 'policy', 'first-attestation']) {
    const journal = JSON.parse(await readFile(`runs/${name}.json`, 'utf8'));
    if (journal.receipt?.statusName !== 'FINALIZED' || journal.trace?.result_code !== 0 || journal.trace_verified !== true || journal.trace_identity?.round !== Number(journal.receipt.numOfRounds) || Number(journal.trace_identity.round_data_round ?? journal.trace_identity.round) !== Number(journal.receipt.lastRound?.round)) throw new Error(`Release ${name} must have finalized successfully with its accepted-round trace verified.`);
    if (journal.chainId !== 4221 || journal.receipt.txId?.toLowerCase() !== journal.hash?.toLowerCase() || journal.receipt.txExecutionResultName !== 'FINISHED_WITH_RETURN') throw new Error(`Release ${name} receipt identity or execution mismatch.`);
    if (name === 'deploy') {
      if (journal.source_sha256 !== deployment.code_sha256 || journal.receipt.txDataDecoded?.contractAddress?.toLowerCase() !== deployment.contract.toLowerCase()) throw new Error('Deployment receipt does not match the published source and contract.');
    } else if (journal.address?.toLowerCase() !== deployment.contract.toLowerCase() || journal.receipt.recipient?.toLowerCase() !== deployment.contract.toLowerCase()) throw new Error(`Release ${name} belongs to another contract.`);
    if (name === 'policy' && (journal.method !== 'register_policy' || Number(journal.return_value) !== deployment.policy_id)) throw new Error('Policy registration does not match the release.');
    if (name === 'first-attestation' && (journal.method !== 'request_attestation' || Number(journal.args[0]) !== deployment.policy_id || Number(journal.return_value) !== deployment.first_attestation_id || journal.args[5] !== deployment.first_envelope_hash)) throw new Error('First attestation does not match the release.');
  }
  const readback = JSON.parse(await readFile('runs/first-attestation-gate.json', 'utf8'));
  const gate = readback.result || readback.gate || readback;
  if (gate.policy_hash !== deployment.policy_hash || Number(gate.policy_id) !== deployment.policy_id || Number(gate.att_id) !== deployment.first_attestation_id || gate.envelope_hash !== deployment.first_envelope_hash || gate.registry_verification !== 'VERIFIED' || Number(gate.rounds) !== 6) throw new Error('First chain gate does not match the published release.');
  await copyFile('runs/deployment.json', 'web/deployment.json');
}
// Publication badges follow the verified release, including builds after its removal.
html = html.replace(/(<span class="chip" id="deployment-status">)[^<]*(<\/span>)/, `$1${deployment ? 'Deployed on Bradbury' : 'Not yet deployed'}$2`);
html = html.replace(/(<span class="status" id="receipt-status">)[^<]*(<\/span>)/, `$1${deployment ? 'First attestation finalized · receipts published' : 'Contract not yet deployed — no receipts published'}$2`);
await writeFile('web/index.html', html);
try { await copyFile('runs/attempt-history.json', 'web/attempt-history.json'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
try { await copyFile('runs/ci-verification.json', 'web/ci-verification.json'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
for (const name of ['express-finalized-no-commit', 'yargs-finalized-no-commit', 'failed-rows-23-24', 'expired-queue-no-commit', 'expired-cleanup-summary', 'post-cleanup-unfinished-no-commit', 'canceled-retry-manifest']) {
  try { await mkdir('web/diagnostics', {recursive:true}); await copyFile(`runs/diagnostics/${name}.json`, `web/diagnostics/${name}.json`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
for (const name of ['manifest.json', 'report.json', 'leader-summary.json', 'validator-1-summary.json', 'validator-2-summary.json', 'diagnostic-code.py']) {
  const directory = 'diagnostics/locator-enum-simulation';
  try { await mkdir(`web/${directory}`, {recursive:true}); await copyFile(`runs/${directory}/${name}`, `web/${directory}/${name}`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
try { await copyFile('runs/consensus-report.json', 'web/consensus-report.json'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
await mkdir('web/receipts', { recursive: true });
for (const name of ['deploy', 'policy', 'first-attestation', 'smoke-recovery']) {
  try { await copyFile(`runs/${name}.json`, `web/receipts/${name}.json`); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
try {
  await copyCorpusEvidence('runs/consensus-report-runs', 'web/runs/consensus-report-runs');
} catch (error) { if (error.code !== 'ENOENT') throw error; }
console.log('Built browser app and public evidence.');
