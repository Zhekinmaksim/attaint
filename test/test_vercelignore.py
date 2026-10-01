"""Exercise the installed Vercel upload walker, including directory traversal."""
import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class VercelIgnoreTests(unittest.TestCase):
    def test_selected_evidence_traverses_without_exposing_private_runs(self):
        executable = shutil.which("vercel")
        if not executable:
            self.skipTest("Vercel CLI is not installed")
        chunks = pathlib.Path(executable).resolve().parent / "chunks"
        bundle = next((path for path in chunks.glob("*.js")
                       if "getVercelIgnore: () => import_utils4.getVercelIgnore" in path.read_text()), None)
        if bundle is None:
            self.skipTest("Installed Vercel CLI does not expose its upload walker")
        code = r"""
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,rmSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname,relative} from 'node:path';
import {pathToFileURL} from 'node:url';
const {require_dist}=await import(pathToFileURL(process.argv[2]));
const api=require_dist(),root=process.cwd();
const {ig}=await api.getVercelIgnore(root,false);
for(const parent of ['runs/diagnostics','runs/diagnostics/locator-enum-simulation','runs/consensus-report-runs']) assert.equal(ig.ignores(parent),false,parent);
const diagnosticNames=['manifest.json','report.json','leader-summary.json','validator-1-summary.json','validator-2-summary.json','diagnostic-code.py'];
const diagnosticPaths=['runs/diagnostics/express-finalized-no-commit.json','runs/diagnostics/yargs-finalized-no-commit.json',...diagnosticNames.map(name=>'runs/diagnostics/locator-enum-simulation/'+name)];
const selected=['runs/deploy.json','runs/attempt-history.json','runs/ci-verification.json','runs/consensus-report-runs/mechanical-baseline.json',
  ...diagnosticPaths];
for(let index=0;index<45;index++) for(const suffix of ['envelope','transaction','receipt','gate']) {
  const path=`runs/consensus-report-runs/${String(index).padStart(2,'0')}.${suffix}.json`;
  assert.equal(ig.ignores(path),false,path);
  if(suffix==='envelope') selected.push(path);
}
const excluded=['runs/attempt-01-registry-api/deploy.json','runs/attempt-02-question-polarity/policy.json',
  'runs/diagnostics/locator-enum-simulation/leader-request.json',
  'runs/diagnostics/locator-enum-simulation/leader-response.json',
  'runs/diagnostics/locator-enum-simulation/validator-1-request.json',
  'runs/diagnostics/locator-enum-simulation/validator-2-response.json',
  'runs/diagnostics/locator-enum-simulation/nested/report.json',
  'runs/diagnostics/unpublished/report.json','runs/unreviewed.json',
  'runs/consensus-report-runs/45.envelope.json','runs/consensus-report-runs/99.receipt.json',
  'runs/consensus-report-runs/private.envelope.json','runs/consensus-report-runs/00.request.json',
  'runs/consensus-report-runs/private/00.envelope.json',
  'runs/screenshot.png','runs/credentials.json',
  'web/runs/consensus-report-runs/failed-submissions/private.json',
  'web/diagnostics/private.json','.env','debug.log','node_modules/private.js','.vercel/auth.json'];
for(const path of excluded) assert.equal(ig.ignores(path),true,path);
const scratch=mkdtempSync(join(tmpdir(),'attaint-upload-test-'));
try {
  writeFileSync(join(scratch,'.vercelignore'),readFileSync(join(root,'.vercelignore')));
  for(const path of [...selected,...excluded]) {mkdirSync(dirname(join(scratch,path)),{recursive:true});writeFileSync(join(scratch,path),'{}');}
  const {fileList}=await api.buildFileTree(scratch,{isDirectory:true,prebuilt:false},()=>{});
  const included=fileList.filter(path=>statSync(path).isFile()).map(path=>relative(scratch,path)).filter(path=>path!=='.vercelignore');
  assert.deepEqual(included.sort(),selected.sort());
  const actual=await api.buildFileTree(root,{isDirectory:true,prebuilt:false},()=>{});
  const paths=actual.fileList.map(path=>relative(root,path));
  assert.equal(paths.filter(path=>/^runs\/consensus-report-runs\/\d{2}\.envelope\.json$/.test(path)).length,45);
  assert.deepEqual(paths.filter(path=>path.startsWith('runs/diagnostics/')).sort(),diagnosticPaths.sort());
} finally {rmSync(scratch,{recursive:true,force:true});}
"""
        process = subprocess.run(["node", "--input-type=module", "-", str(bundle)],
                                 input=code, text=True, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)


if __name__ == "__main__":
    unittest.main()
