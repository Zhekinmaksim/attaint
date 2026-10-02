"""Hosted corpus evidence must not include private diagnostics or attempt archives."""
import pathlib
import importlib.util
import json
import tempfile
import zipfile
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PublicEvidenceTests(unittest.TestCase):
    def test_source_archive_includes_only_reviewed_retry_diagnostics(self):
        spec = importlib.util.spec_from_file_location("package_source", ROOT/"scripts/package_source.py")
        package_source = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(package_source)
        selected = ["runs/diagnostics/finalized-retry-21-23-44-manifest.json",
                    "runs/diagnostics/finalized-42-43-readback-audit.json"]
        private = ["runs/diagnostics/finalized-42-43-readback-audit.private.json",
                   "runs/diagnostics/gate-file-recovery/44.misattributed-gate.json",
                   "runs/consensus-report-runs/failed-submissions/21.transaction.json"]
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            for name in selected+private:
                path = root/name
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(json.dumps({"audit_fixture":name}))
            archive_path = root/"source.zip"
            package_source.package(root,archive_path)
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(set(archive.namelist()),set(selected+["SHA256SUMS.json"]))
                manifest = json.loads(archive.read("SHA256SUMS.json"))
                self.assertEqual({row["path"] for row in manifest["files"]},set(selected))

    def test_build_copy_excludes_attempts_unreviewed_files_and_symlinks(self):
        code = r"""
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,symlink,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {copyCorpusEvidence} from './scripts/public_evidence.mjs';
const root=await mkdtemp(join(tmpdir(),'attaint-public-evidence-'));
try {
  const source=join(root,'source'),destination=join(root,'hosted');
  await mkdir(source);
  const published=['mechanical-baseline.json','00.envelope.json','21.transaction.json','44.gate.json'];
  const privateFiles=['45.envelope.json','99.receipt.json','00.request.json','00.receipt.json.tmp','private.json'];
  for(const name of [...published,...privateFiles]) await writeFile(join(source,name),'{}');
  await mkdir(join(source,'failed-submissions'));
  await writeFile(join(source,'failed-submissions','00.transaction.json'),'private attempt details');
  await symlink(join(source,'private.json'),join(source,'01.gate.json'));
  await copyCorpusEvidence(source,destination);
  assert.deepEqual((await readdir(destination)).sort(),published.sort());
} finally {await rm(root,{recursive:true,force:true});}
"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code,
                                text=True, capture_output=True, cwd=ROOT, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
