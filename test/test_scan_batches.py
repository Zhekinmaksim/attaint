"""Queue limits never cause automatic duplicate writes or lost failure proof."""
import copy
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("scan_batches", ROOT / "probes/scan.py")
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ScanBatchTests(unittest.TestCase):
    def test_one_reschedule_flag_never_replaces_a_failed_replacement(self):
        self.assertTrue(scan.reschedule_matches_initial_failure({}, {"hash":"original"}))
        row={"failed_consensus_attempts":[{"hash":"original"}]}
        self.assertTrue(scan.reschedule_matches_initial_failure(row,{"hash":"original"}))
        self.assertFalse(scan.reschedule_matches_initial_failure(row,{"hash":"replacement"}))
        row["failed_consensus_attempts"].append({"hash":"replacement"})
        self.assertFalse(scan.reschedule_matches_initial_failure(row,{"hash":"original"}))

    def test_undetermined_reschedule_requires_fresh_no_commit_proof(self):
        tx,contract,sender="0x"+"1"*64,"0x"+"2"*40,"0x"+"3"*40
        journal={"hash":tx,"address":contract,"args":[0,"express","5.2.1","4.22.1",1,"envelope","{}"]}
        receipt={"chainId":4221,"hash":tx,"receipt":{"txId":tx,"status":7,"statusName":"FINALIZED","result":5,"recipient":contract,"sender":sender}}
        state={"chainId":4221,"address":contract,"variant":"latest-nonfinal","count":0,"gates":[],"observed_at":"today"}
        disagree=copy.deepcopy(receipt);disagree["receipt"]["result"]=2
        with self.assertRaisesRegex(ValueError,"explicitly authorized"):
            scan.prove_uncommitted_consensus(journal,lambda _:disagree,lambda:state)
        scan.prove_uncommitted_consensus(journal,lambda _:disagree,lambda:state,allowed_results=(2,))
        with self.assertRaisesRegex(ValueError,"explicitly authorized"):
            scan.prove_uncommitted_consensus(journal,lambda _:receipt,lambda:state,allowed_results=(2,))
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/"13.transaction.json";path.write_text(json.dumps(journal));original=path.read_bytes()
            row={"transaction_hash":tx,"failure_finalized":True,"failure_receipt":"old-receipt","consensus_result":5}
            committed=copy.deepcopy(state);committed.update(count=1,gates=[{"att_id":0,"policy_id":0,"package":"express","from_version":"5.2.1","to_version":"4.22.1","requester":sender,"envelope_hash":"different"}])
            with self.assertRaisesRegex(ValueError,"committed attestation"):
                scan.archive_uncommitted_consensus(path,row,lambda _:receipt,lambda:committed)
            self.assertEqual(path.read_bytes(),original)
            accepted=copy.deepcopy(receipt);accepted["receipt"].update(status=5,statusName="ACCEPTED")
            with self.assertRaisesRegex(ValueError,"UNDETERMINED"):
                scan.archive_uncommitted_consensus(path,row,lambda _:accepted,lambda:state)
            provisional=copy.deepcopy(receipt);provisional["receipt"].update(status=6,statusName="UNDETERMINED")
            with self.assertRaisesRegex(ValueError,"UNDETERMINED"):
                scan.archive_uncommitted_consensus(path,row,lambda _:provisional,lambda:state)
            agreed=copy.deepcopy(receipt);agreed["receipt"].update(status=7,statusName="FINALIZED",result=1)
            with self.assertRaisesRegex(ValueError,"UNDETERMINED"):
                scan.archive_uncommitted_consensus(path,row,lambda _:agreed,lambda:state)
            def fail():raise OSError("failed checkpoint")
            with self.assertRaises(OSError):
                scan.archive_uncommitted_consensus(path,row,lambda _:receipt,lambda:state,fail)
            self.assertTrue(path.exists())
            receipt["receipt"].update(status=7,statusName="FINALIZED")
            scan.archive_uncommitted_consensus(path,row,lambda _:receipt,lambda:state)
            self.assertFalse(path.exists());self.assertNotIn("transaction_hash",row)
            self.assertNotIn("failure_finalized",row);self.assertNotIn("failure_receipt",row)
            self.assertEqual(len(row["failed_consensus_attempts"]),1)
            entry=row["failed_consensus_attempts"][0]
            self.assertEqual(entry["hash"],tx);self.assertFalse(entry["consensus_commit"])
            self.assertEqual((entry["status"],entry["result"]),("FINALIZED",5))
            self.assertEqual(pathlib.Path(entry["journal"]).read_bytes(),original)

    def test_process_scan_lock_covers_all_report_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=pathlib.Path(directory)
            with scan.scan_lock(root):
                with self.assertRaisesRegex(ValueError,"another consensus scanner"):
                    with scan.scan_lock(root):
                        self.fail("second scanner acquired lock")
            with scan.scan_lock(root):
                self.assertTrue((root/".attaint-scan.lock").exists())

    def test_authoritative_capacity_preserves_two_free_slots(self):
        self.assertEqual(scan.queue_capacity({"maximum":20,"pending":17}),1)
        self.assertEqual(scan.queue_capacity({"maximum":20,"pending":18}),0)
        self.assertEqual(scan.queue_capacity({"maximum":20,"pending":20}),0)
        for queue in ({"maximum":20,"pending":21},{"maximum":20,"pending":-1},{"maximum":"20","pending":0}):
            with self.assertRaises(ValueError):
                scan.queue_capacity(queue)

    def test_drain_existing_twenty_before_scheduling_another_ten(self):
        rows = [{"status":"SUBMITTED", "transaction_hash":str(i)} if i < 20 else {"status":"PINNED"} for i in range(45)]
        self.assertEqual(scan.next_scan_batch(rows,10),(list(range(20)),False))
        for row in rows[:19]:
            row["status"] = "FINALIZED"
        self.assertEqual(scan.next_scan_batch(rows,10),([19],False))
        rows[19]["status"] = "FINALIZED"
        self.assertEqual(scan.next_scan_batch(rows,10),(list(range(20,30)),True))
        for i in range(20,30):
            rows[i].update(status="FINALIZED",transaction_hash=str(i))
        self.assertEqual(scan.next_scan_batch(rows,10),(list(range(30,40)),True))

    def test_reverted_intent_is_archived_only_after_matching_live_proof(self):
        evm, sender, main = "0x"+"1"*64, "0x"+"2"*40, "0x"+"3"*40
        journal = {"hash":"", "value_wei":"0", "submission_intent":{"evm_hash":evm,"from":sender,"to":main,"nonce":"469"}}
        proof = {"chainId":4221,"hash":evm,
                 "receipt":{"transactionHash":evm,"status":"reverted","gasUsed":"40000"},
                 "transaction":{"hash":evm,"from":sender,"to":main,"nonce":469,"value":"0"}}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)/"20.transaction.json"
            original = json.dumps(journal).encode()
            path.write_bytes(original)
            broken = copy.deepcopy(proof)
            broken["receipt"]["status"] = "success"
            with self.assertRaises(ValueError):
                scan.archive_reverted_submission(path,{},lambda _:broken)
            self.assertEqual(path.read_bytes(),original)
            broken = copy.deepcopy(proof)
            broken["transaction"]["nonce"] = 470
            with self.assertRaises(ValueError):
                scan.archive_reverted_submission(path,{},lambda _:broken)
            row = {}
            scan.archive_reverted_submission(path,row,lambda _:proof)
            self.assertFalse(path.exists())
            record = row["failed_submissions"][0]
            self.assertEqual(pathlib.Path(record["journal"]).read_bytes(),original)
            self.assertEqual(json.loads(pathlib.Path(record["receipt"]).read_text()),proof)
            self.assertFalse(record["consensus_transaction_created"])
            self.assertEqual(record["evm_receipt"]["status"],"reverted")

    def test_archive_save_failure_keeps_original_journal_and_all_failure_proof(self):
        evm,sender,main="0x"+"1"*64,"0x"+"2"*40,"0x"+"3"*40
        journal={"value_wei":"0","submission_intent":{"evm_hash":evm,"from":sender,"to":main,"nonce":"469"}}
        proof={"chainId":4221,"hash":evm,"receipt":{"transactionHash":evm,"status":"reverted"},"transaction":{"hash":evm,"from":sender,"to":main,"nonce":469,"value":"0"}}
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/"20.transaction.json"
            path.write_text(json.dumps(journal))
            original=path.read_bytes()
            row={}
            def fail():
                raise OSError("disk full")
            with self.assertRaises(OSError):
                scan.archive_reverted_submission(path,row,lambda _:proof,fail)
            self.assertEqual(path.read_bytes(),original)
            self.assertEqual(len(list((path.parent/"failed-submissions").glob("*.json"))),2)
            scan.archive_reverted_submission(path,row,lambda _:proof)
            self.assertEqual(len(row["failed_submissions"]),1)

    def test_failed_estimate_blocks_signing_sdk_fallback(self):
        code = r"""
import assert from 'node:assert/strict';import {createGasGuard} from './scripts/gas_guard.mjs';
let signed=0,sent=0,journal={};
const guard=createGasGuard({estimate:async()=>{throw Error('execution reverted');},readRpc:f=>f()});
async function sdkWrite(g){let gas;try{gas=await g.estimate({});}catch{gas=200000n;}
 g.assertCanSign();signed++;journal.intent='signed';sent++;return gas;}
await assert.rejects(sdkWrite(guard),/refusing SDK fallback broadcast/);
assert.equal(signed,0);assert.equal(sent,0);assert.deepEqual(journal,{});
const successful=createGasGuard({estimate:async()=>300000n,readRpc:f=>f()});
assert.equal(await sdkWrite(successful),300000n);assert.equal(signed,1);assert.equal(sent,1);
"""
        process = subprocess.run(["node","--input-type=module","-"],input=code,text=True,capture_output=True,cwd=ROOT,timeout=30)
        self.assertEqual(process.returncode,0,process.stderr)


if __name__ == "__main__":
    unittest.main()
