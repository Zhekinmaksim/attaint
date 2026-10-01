"""Finalized failed consensus must never appear as a successful browser receipt."""
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class FinalizedReceiptTests(unittest.TestCase):
    def test_actual_success_and_rejected_consensus(self):
        subprocess.run(['node', '--input-type=module', '-e', r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assertFinalizedConsensusReceipt as verify} from './scripts/finalized_receipt.mjs';
const journal=JSON.parse(readFileSync('runs/first-attestation.json','utf8'));
const receipt=journal.receipt;
const identity={hash:journal.hash,recipient:journal.address,method:'request_attestation'};
verify(receipt,identity);
// Both historical failure modes had a successful leader return, but no commit.
for(const result of [2,5]) assert.throws(()=>verify({...receipt,result},identity),/no accepted consensus/);
assert.throws(()=>verify({...receipt,lastRound:{...receipt.lastRound,result:2}},identity),/no accepted consensus/);
assert.throws(()=>verify({...receipt,txId:'0x'+'0'.repeat(64)},identity),/another transaction/);
assert.throws(()=>verify({...receipt,recipient:'0x'+'0'.repeat(40)},identity),/another transaction/);
assert.throws(()=>verify({...receipt,txDataDecoded:{callData:{method:'register_policy'}}},identity),/another contract method/);
assert.throws(()=>verify({...receipt,txExecutionResult:2},identity),/did not execute/);
assert.throws(()=>verify({...receipt,status:6,statusName:'ACCEPTED'},identity),/not finalized/);
'''], cwd=ROOT, check=True, capture_output=True, text=True)
