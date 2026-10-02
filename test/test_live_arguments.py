"""A CLI typo cannot silently become an empty-argument signed write."""
import os
import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class LiveArgumentsTests(unittest.TestCase):
    def test_option_parser_rejects_ambiguous_commands(self):
        code = r"""
import assert from 'node:assert/strict';
import {validateLiveArguments as validate} from './scripts/live_arguments.mjs';
validate('write',['--address','0xabc','--method','register_policy','--args-file','/tmp/policy.json','--out','/tmp/journal.json','--wait']);
validate('settle',['--hash','0xabc','--out','journal.json','--finalize-nonagreement','--timeout','120']);
validate('deploy',['--file','contract.py','--args-file','args.json','--retry-signed-intent','--retry-sender','0xabc']);
assert.throws(()=>validate('write',['--args','[1]']),/Unknown option --args.*--args-file/);
assert.throws(()=>validate('write',['--args-file']),/Missing value/);
assert.throws(()=>validate('write',['--args-file','']),/Missing value/);
assert.throws(()=>validate('write',['--args-file','--out','journal.json']),/Missing value/);
assert.throws(()=>validate('write',['--address','a','--address','b']),/Duplicate option/);
assert.throws(()=>validate('write',['--wait','--wait']),/Duplicate option/);
assert.throws(()=>validate('write',['--wait','true']),/positional argument/);
assert.throws(()=>validate('write',['--args-file=x']),/Unknown option/);
assert.throws(()=>validate('write',['--unknown']),/Unknown option/);
assert.throws(()=>validate('write',['0xabc']),/positional argument/);
assert.throws(()=>validate('write',['--']),/Unknown option/);
assert.throws(()=>validate('write',null),/Invalid live arguments/);
assert.throws(()=>validate('unknown',[]),/Unknown or missing live command/);
assert.throws(()=>validate(undefined,[]),/Unknown or missing live command/);
"""
        result = subprocess.run(['node', '--input-type=module', '-'], input=code,
                                text=True, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_rejects_before_cli_or_credentials_are_resolved(self):
        node = shutil.which('node')
        env = {**os.environ, 'PATH': '/nonexistent',
               'GENLAYER_CONFIG': '/nonexistent/no-credential-access.json'}
        cases = [(['write', '--args', '[1]'], 'Unknown option --args'),
                 (['write', '--args-file'], 'Missing value'),
                 (['write', '--out', 'a', '--out', 'b'], 'Duplicate option'),
                 (['write', 'unexpected'], 'positional argument'),
                 (['invalid-command'], 'Unknown or missing live command')]
        for args, expected in cases:
            with self.subTest(args=args):
                result = subprocess.run([node, 'scripts/live.mjs', *args], env=env,
                                        text=True, capture_output=True, cwd=ROOT, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn('which', result.stderr)
                self.assertNotIn('unlocked account', result.stderr)
                self.assertEqual(result.stdout, '')
