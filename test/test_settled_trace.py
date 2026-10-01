"""Reject traces from earlier rounds and reports carrying stale completion."""
import argparse
import copy
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scan", ROOT / "probes/scan.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class SettledTraceTests(unittest.TestCase):
    def test_latest_round_and_execution_checks(self):
        code = r"""
import assert from 'node:assert/strict';
import {selectFinalizedRound,decodeFinalizedTrace} from './scripts/settled_trace.mjs';
const hash='0x'+'1'.repeat(64),leader='0x'+'2'.repeat(40);
const lastRound={round:'2',leaderIndex:'0',roundValidators:[leader],result:1};
const receipt={txId:hash,status:7,statusName:'FINALIZED',txExecutionResult:1,result:1,numOfRounds:'2',lastLeader:leader,lastRound};
const args={hash,receipt,roundNumber:2n,lastRoundData:[2n,lastRound]};
const identity=selectFinalizedRound(args);
assert.equal(identity.round,2);assert.equal(identity.leader,leader);
const rotated=selectFinalizedRound({...args,receipt:{...receipt,numOfRounds:'4'},roundNumber:4n,lastRoundData:[4n,lastRound]});
assert.equal(rotated.round,4);assert.equal(rotated.round_data_round,2);
const traces=[{transaction_id:hash,result_code:2,return_data:'0xff'},null,{transaction_id:hash,result_code:0,return_data:'0xff'}];
const decoded=new Map([['kind','Return'],['data',17n]]);
assert.equal(decodeFinalizedTrace({hash,trace:traces[identity.round],identity,decode:()=>decoded}),17n);
assert.throws(()=>decodeFinalizedTrace({hash,trace:traces[0],identity,decode:()=>decoded}),/execution failed/);
assert.throws(()=>selectFinalizedRound({...args,receipt:{...receipt,txExecutionResult:2}}),/did not return/);
assert.throws(()=>selectFinalizedRound({...args,roundNumber:0n}),/metadata mismatch/);
assert.throws(()=>selectFinalizedRound({...args,receipt:{...receipt,lastLeader:'0x'+'3'.repeat(40)}}),/leader mismatch/);
assert.throws(()=>decodeFinalizedTrace({hash,trace:{...traces[2],transaction_id:'0x'+'9'.repeat(64)},identity,decode:()=>decoded}),/identity mismatch/);
assert.throws(()=>decodeFinalizedTrace({hash,trace:traces[2],identity,decode:()=>{throw Error('decode');}}),/cannot decode/);
assert.throws(()=>decodeFinalizedTrace({hash,trace:traces[2],identity,decode:()=>new Map([['kind','UserError'],['data',17n]])}),/successful Return/);
assert.equal(decodeFinalizedTrace({hash,trace:traces[2],identity,decode:()=>new Map([['kind','Return'],['data',null]])}),null);
"""
        process = subprocess.run(["node", "--input-type=module", "-"], input=code,
                                 text=True, capture_output=True, cwd=ROOT, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_resume_invalidates_completed_report_before_rpc_failure(self):
        baseline_path = ROOT / "corpus/scan-report.json"
        baseline = baseline_path.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory) / "report.json"
            args = argparse.Namespace(out=out, baseline=baseline_path, code_hash="source",
                                      contract="contract", policy=0, policy_hash="policy", rpc="rpc")
            controls = json.loads(baseline)["controls"]
            out.write_text(json.dumps({"source":"live-bradbury-consensus", "chainId":4221,
                "code_sha256":"source", "contract":"contract", "policy_id":0,
                "policy_hash":"policy", "rpc":"rpc", "control_total":45,
                "baseline_sha256":hashlib.sha256(baseline).hexdigest(),
                "completed":True, "consensus_counts":{"CLEAN":45},
                "risk_reduction_percentage_points":57.8,
                "controls":[{**r,"status":"FINALIZED"} for r in controls]}))
            import attaint_gate
            with patch.object(attaint_gate, "bridge", side_effect=ValueError("RPC unavailable")):
                with self.assertRaisesRegex(ValueError, "RPC unavailable"):
                    # This unit owns a temporary report; scanner-lock exclusion
                    # is covered separately without claiming the live writer's lock.
                    scan._consensus_main(args)
            report = json.loads(out.read_text())
            self.assertFalse(report["completed"])
            self.assertNotIn("consensus_counts", report)
            self.assertNotIn("risk_reduction_percentage_points", report)
            self.assertTrue(all(r["status"] == "RECHECK_PENDING" for r in report["controls"]))

    def test_scanner_rejects_saved_or_failed_execution_as_completion(self):
        tx = "0x" + "1" * 64
        contract = "0x" + "2" * 40
        leader = "0x" + "3" * 40
        document = {"chainId":4221, "hash":tx, "trace_verified":True, "return_value":"17",
            "receipt":{"txId":tx, "recipient":contract, "sender":leader, "status":7, "statusName":"FINALIZED",
                       "txExecutionResult":1, "result":1, "numOfRounds":"4", "lastRound":{"round":"2"}, "lastLeader":leader},
            "trace_identity":{"round":4, "round_data_round":2, "leader":leader, "binding":"finalized-round-and-leader"},
            "trace":{"result_code":0}}
        self.assertEqual(scan.settled_attestation(document, tx, contract), 17)
        for field, value in [("trace_verified",False), ("return_value",None), ("return_value",-1), ("return_value",True)]:
            broken = copy.deepcopy(document)
            broken[field] = value
            with self.assertRaises(ValueError):
                scan.settled_attestation(broken, tx, contract)
        for field, value in [("status",6), ("txExecutionResult",2), ("numOfRounds","0"), ("recipient",leader)]:
            broken = copy.deepcopy(document)
            broken["receipt"][field] = value
            with self.assertRaises(ValueError):
                scan.settled_attestation(broken, tx, contract)


if __name__ == "__main__":
    unittest.main()
