"""Hosted corpus evidence must not include private diagnostics or attempt archives."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class PublicEvidenceTests(unittest.TestCase):
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
