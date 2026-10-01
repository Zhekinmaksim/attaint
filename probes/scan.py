#!/usr/bin/env python3
"""Measure pinned evidence mechanically, or replay the fixed sample live.

The default mode records historical incident pins and a four-class mechanical
baseline. That baseline measures visible signals, not maliciousness or ground
truth. --consensus replays its exact 45 release pairs through the deployed
six-class policy, saves real transaction journals, and reads finalized gates.
Only a complete live replay produces the mechanical/consensus comparison.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import time
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "cli"))

import envelope as env  # noqa: E402

INCIDENTS = [
    ("event-stream", "3.3.4", "3.3.5", "takeover: right9ctrl gains publish rights"),
    ("event-stream", "3.3.5", "3.3.6", "payload: flatmap-stream pulled in"),
    ("flatmap-stream", "0.1.0", "0.1.1", "payload carrier"),
    ("ua-parser-js", "0.7.28", "0.7.29", "account compromise, preinstall added"),
    ("ua-parser-js", "0.7.29", "0.7.30", "cleanup release"),
    ("node-ipc", "10.1.0", "10.1.1", "protestware, file overwrite"),
    ("node-ipc", "10.1.1", "10.1.2", "protestware follow-up"),
    ("coa", "2.0.2", "2.0.3", "account compromise"),
    ("rc", "1.2.8", "1.2.9", "account compromise"),
    ("node-ipc", "10.1.0", "11.0.0", "post-incident release, peacenotwar era"),
    ("peacenotwar", "9.1.2", "9.1.3", "the protestware dependency itself"),
]

CONTROLS = [
    "lodash",
    "chalk",
    "debug",
    "semver",
    "express",
    "axios",
    "commander",
    "yargs",
    "rimraf",
    "glob",
    "uuid",
    "dotenv",
    "cross-env",
    "esbuild",
    "prettier",
]


def classes_visible(facts: dict) -> list:
    """Mechanical reading of the four MVP classes. Deliberately dumb.

    This is what a twenty-line script sees. The point of measuring it is to show
    how much of the work is left over for judgement.
    """
    hits = []
    if facts["license"]["from"] != facts["license"]["to"]:
        hits.append("LICENSE_SHIFT")
    if (
        facts["publisher"]["from"] != facts["publisher"]["to"]
        or facts["maintainers"]["from"] != facts["maintainers"]["to"]
    ):
        hits.append("MAINTAINER_SHIFT")
    if facts["install_hooks"]["from"] != facts["install_hooks"]["to"]:
        hits.append("INSTALL_HOOK")
    if facts["opaque_candidates"]:
        hits.append("OPAQUE")
    return hits


def consecutive_pairs(package: str, count: int) -> list:
    try:
        document = env.packument(package)
    except env.Unpinnable:
        return []
    times = document.get("time") or {}
    versions = [
        version
        for version in document.get("versions", {})
        if version in times and not any(mark in version for mark in ("-", "+"))
    ]
    versions.sort(key=lambda version: times[version])
    pairs = []
    for index in range(len(versions) - 1, 0, -1):
        pairs.append((versions[index - 1], versions[index]))
        if len(pairs) >= count:
            break
    return pairs


def mechanical_main() -> int:
    out_dir = pathlib.Path(__file__).resolve().parents[1] / "corpus"
    out_dir.mkdir(exist_ok=True)

    print("== 1. historical incidents: is the evidence pinnable today?\n")
    incident_rows = []
    for package, before, after, note in INCIDENTS:
        try:
            envelope = env.build(package, before, after, note)
        except env.Unpinnable as error:
            print("  UNPINNABLE  %-16s %s -> %-8s  %s" % (package, before, after, error))
            incident_rows.append(
                {
                    "package": package,
                    "from": before,
                    "to": after,
                    "note": note,
                    "pinnable": False,
                    "reason": str(error),
                }
            )
            continue
        hits = classes_visible(envelope["facts"])
        envelope["envelope_hash"] = env.envelope_hash(envelope)
        name = "%s-%s-%s.json" % (package, before, after)
        (out_dir / name).write_text(
            json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
        print(
            "  PINNED      %-16s %s -> %-8s  classes: %s"
            % (package, before, after, ", ".join(hits) or "none")
        )
        incident_rows.append(
            {
                "package": package,
                "from": before,
                "to": after,
                "note": note,
                "pinnable": True,
                "classes": hits,
                "envelope_hash": envelope["envelope_hash"],
            }
        )

    print("\n== 2. control sample: how often does each class fire on ordinary releases?\n")
    tally = {
        "LICENSE_SHIFT": 0,
        "MAINTAINER_SHIFT": 0,
        "INSTALL_HOOK": 0,
        "OPAQUE": 0,
    }
    control_rows = []
    total = 0
    for package in CONTROLS:
        for before, after in consecutive_pairs(package, 3):
            try:
                envelope = env.build(package, before, after)
            except env.Unpinnable as error:
                print("  skip %-12s %s -> %-10s %s" % (package, before, after, error))
                continue
            hits = classes_visible(envelope["facts"])
            total += 1
            for name in hits:
                tally[name] += 1
            control_rows.append(
                {
                    "package": package,
                    "from": before,
                    "to": after,
                    "classes": hits,
                }
            )
            print(
                "  %-12s %-10s -> %-10s  %s"
                % (package, before, after, ", ".join(hits) or "clean")
            )

    print("\n  n = %d ordinary releases" % total)
    for name, count in sorted(tally.items()):
        share = (count * 1000 // total) if total else 0
        print("  %-18s fired on %3d  (%s)" % (name, count, "%.1f%%" % (share / 10)))
    clean = sum(1 for row in control_rows if not row["classes"])
    print(
        "  %-18s %3d  (%s)"
        % ("clean", clean, "%.1f%%" % (clean * 100 / total) if total else "n/a")
    )

    (out_dir / "scan-report.json").write_text(
        json.dumps(
            {
                "incidents": incident_rows,
                "controls": control_rows,
                "control_total": total,
                "control_tally": tally,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    return 0


def _save(path: pathlib.Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def invalidate_comparison(report: dict) -> None:
    """A resumed report is unverified until every live receipt is checked again."""
    report["completed"] = False
    for key in ("consensus_counts", "mechanical_blocked", "mechanical_blocked_percent",
                "consensus_risk_percent", "risk_reduction_percentage_points",
                "inconclusive_percent", "consensus_blocked_percent",
                "blocked_reduction_percentage_points"):
        report.pop(key, None)
    for row in report["controls"]:
        row["status"] = "RECHECK_PENDING"


def settled_attestation(document: dict, transaction_hash: str, contract: str) -> int:
    """Require live settlement evidence, including the accepted round trace."""
    receipt = document.get("receipt", {})
    if (document.get("chainId") != 4221 or document.get("hash") != transaction_hash
            or document.get("trace_verified") is not True
            or str(receipt.get("txId", "")).lower() != transaction_hash.lower()
            or str(receipt.get("recipient", "")).lower() != contract.lower()
            or receipt.get("statusName") != "FINALIZED" or receipt.get("status") != 7
            or receipt.get("txExecutionResult") != 1 or receipt.get("result") != 1):
        raise ValueError("receipt is not a verified successful finalized transaction")
    if not isinstance(receipt.get("sender"), str) or not receipt["sender"].startswith("0x") or len(receipt["sender"]) != 42:
        raise ValueError("receipt has no requester wallet identity")
    identity = document.get("trace_identity", {})
    if (identity.get("round") != int(receipt["numOfRounds"])
            or str(identity.get("leader", "")).lower() != str(receipt.get("lastLeader", "")).lower()
            or identity.get("binding") != "finalized-round-and-leader"
            or document.get("trace", {}).get("result_code") != 0):
        raise ValueError("receipt has no verified finalized-round trace identity")
    if identity.get("round_data_round") != int(receipt.get("lastRound", {}).get("round", -1)):
        raise ValueError("receipt round-data field does not match the trace identity")
    att_id = document.get("return_value")
    if isinstance(att_id, str) and att_id.isdecimal():
        att_id = int(att_id)
    if type(att_id) is not int or att_id < 0:
        raise ValueError("receipt has no nonnegative integer attestation return value")
    return att_id


def archive_reverted_submission(journal_path, row, read_evm, persist=lambda:None):
    """An explicit retry can archive a proven reverted EVM submission only."""
    journal = json.loads(journal_path.read_text())
    intent = journal.get("submission_intent", {})
    if journal.get("hash") or not intent.get("evm_hash"):
        raise ValueError("archive requires an unresolved EVM submission")
    proof = read_evm(intent["evm_hash"])
    receipt, transaction = proof["receipt"], proof["transaction"]
    if (proof.get("chainId") != 4221 or proof.get("hash") != intent["evm_hash"]
            or receipt.get("status") != "reverted"
            or receipt.get("transactionHash") != intent["evm_hash"]
            or transaction.get("hash") != intent["evm_hash"]
            or str(transaction.get("from", "")).lower() != str(intent.get("from", "")).lower()
            or str(transaction.get("to", "")).lower() != str(intent.get("to", "")).lower()
            or str(transaction.get("nonce")) != intent.get("nonce")
            or str(transaction.get("value")) != str(journal.get("value_wei"))):
        raise ValueError("cannot prove the original EVM submission reverted without consensus execution")
    archive = journal_path.parent / "failed-submissions"
    archive.mkdir(exist_ok=True)
    archived_journal = archive / (journal_path.stem + "-" + intent["evm_hash"] + ".json")
    archived_receipt = archive / (journal_path.stem + "-" + intent["evm_hash"] + ".receipt.json")
    if archived_journal.exists() and archived_journal.read_bytes() != journal_path.read_bytes():
        raise ValueError("failed submission archive identity mismatch")
    if not archived_journal.exists():
        temporary = archived_journal.with_suffix(".tmp")
        temporary.write_bytes(journal_path.read_bytes())
        temporary.replace(archived_journal)
    _save(archived_receipt, proof)
    record = {"evm_hash":intent["evm_hash"],
        "nonce":intent["nonce"], "status":"REVERTED", "consensus_transaction_created":False,
        "journal":str(archived_journal), "receipt":str(archived_receipt),
        "receipt_sha256":hashlib.sha256(archived_receipt.read_bytes()).hexdigest(),
        "evm_receipt":{key:receipt.get(key) for key in ("transactionHash", "blockHash", "blockNumber", "from", "to", "status", "gasUsed")}}
    previous = row.setdefault("failed_submissions", [])
    if not any(item["evm_hash"] == intent["evm_hash"] for item in previous):
        previous.append(record)
    # The archived bytes and persisted public reference must exist before the
    # active journal can be removed. Any failed save leaves that journal intact.
    persist()
    journal_path.unlink()


def prove_uncommitted_consensus(journal,read_receipt,read_gates):
    """Recheck final nonagreement and the entire current attestation set."""
    hash = journal.get("hash")
    if not hash:
        raise ValueError("rescheduling requires the original consensus transaction hash")
    receipt_proof = read_receipt(hash)
    receipt = receipt_proof.get("receipt",{})
    if (receipt_proof.get("chainId") != 4221 or receipt_proof.get("hash") != hash
            or receipt.get("txId") != hash or receipt.get("result") != 5
            or (receipt.get("status"),receipt.get("statusName")) != (7,"FINALIZED")
            or receipt.get("recipient") != journal["address"]):
        raise ValueError("rescheduling requires live FINALIZED nonagreement (UNDETERMINED result 5)")
    state = read_gates()
    if (state.get("chainId") != 4221 or state.get("address") != journal["address"]
            or state.get("variant") != "latest-nonfinal" or state.get("count") != len(state.get("gates",[]))):
        raise ValueError("no complete latest-nonfinal attestation audit")
    expected = {"policy_id":journal["args"][0],"package":journal["args"][1],
                "from_version":journal["args"][2],"to_version":journal["args"][3]}
    requester = str(receipt.get("sender","")).lower()
    if len(requester) != 42:
        raise ValueError("failed consensus transaction has no requester identity")
    if any(all(gate.get(key)==value for key,value in expected.items()) and str(gate.get("requester","")).lower()==requester for gate in state["gates"]):
        raise ValueError("release already has a committed attestation; refusing duplicate submission")
    return receipt,state,expected,requester


def archive_uncommitted_consensus(journal_path,row,read_receipt,read_gates,persist=lambda:None):
    """Explicit rescheduling requires finalized nonagreement and no committed identity."""
    journal=json.loads(journal_path.read_text());hash=journal.get("hash")
    receipt,state,expected,requester=prove_uncommitted_consensus(journal,read_receipt,read_gates)
    archive = journal_path.parent/"failed-submissions"
    archive.mkdir(exist_ok=True)
    archived_journal = archive/(journal_path.stem+"-"+hash+".json")
    archived_proof = archive/(journal_path.stem+"-"+hash+".no-commit-proof.json")
    proof = {"source":"live-bradbury-uncommitted-consensus-audit","chainId":4221,
             "hash":hash,"receipt":receipt,"observed_at":state["observed_at"],
             "contract":journal["address"],"requester":requester,"identity":expected,
             "envelope_hash":journal["args"][5],"attestation_count":state["count"],
             "matching_attestation_ids":[],"committed_gate_identities":[{key:g.get(key) for key in
                 ("att_id","policy_id","requester","package","from_version","to_version","envelope_hash")} for g in state["gates"]]}
    if archived_journal.exists() and archived_journal.read_bytes()!=journal_path.read_bytes():
        raise ValueError("failed consensus journal archive changed")
    if not archived_journal.exists():
        temporary=archived_journal.with_suffix(".tmp");temporary.write_bytes(journal_path.read_bytes());temporary.replace(archived_journal)
    _save(archived_proof,proof)
    records=row.setdefault("failed_consensus_attempts",[])
    if not any(record["hash"]==hash for record in records):
        records.append({"hash":hash,"status":receipt["statusName"],"result":receipt["result"],
            "result_name":receipt.get("resultName"),"consensus_commit":False,
            "requester":requester,"observed_at":state["observed_at"],"attestation_count":state["count"],
            "matching_attestation_ids":[],"proof_sha256":hashlib.sha256(archived_proof.read_bytes()).hexdigest(),
            "journal":str(archived_journal),"proof":str(archived_proof)})
    row.pop("transaction_hash",None);row.pop("reason",None);row["status"]="PINNED"
    persist()
    journal_path.unlink()


def next_scan_batch(rows, batch_size):
    """Drain every existing transaction before allocating more queue capacity."""
    unsettled = [i for i, row in enumerate(rows) if row.get("transaction_hash") and row["status"] != "FINALIZED"]
    if unsettled:
        return unsettled, False
    return [i for i, row in enumerate(rows) if not row.get("transaction_hash")][:batch_size], True


def queue_capacity(queue, margin=2):
    maximum, pending = queue.get("maximum"), queue.get("pending")
    if type(maximum) is not int or type(pending) is not int or not 0 <= pending <= maximum or maximum <= margin:
        raise ValueError("invalid authoritative pending queue state")
    return max(0, maximum-pending-margin)


@contextlib.contextmanager
def scan_lock(root):
    """Hold one canonical process lock across preparation, archives and writes."""
    import fcntl
    path = root/".attaint-scan.lock"
    descriptor = os.open(path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,"r+") as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another consensus scanner is active; refusing concurrent report/journal mutation")
        lock.truncate(0)
        lock.write(json.dumps({"pid":os.getpid()}))
        lock.flush()
        try:
            yield
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN)


def consensus_main(arguments) -> int:
    with scan_lock(pathlib.Path(__file__).resolve().parents[1]):
        return _consensus_main(arguments)


def _consensus_main(arguments) -> int:
    """Replay exactly the original control pairs; only live chain gates decide."""
    import attaint_gate as gate_cli
    import subprocess

    root = pathlib.Path(__file__).resolve().parents[1]
    baseline_bytes = arguments.baseline.read_bytes()
    baseline = json.loads(baseline_bytes)
    pairs = baseline["controls"]
    identities = [(r["package"], r["from"], r["to"]) for r in pairs]
    if len(pairs) != 45 or len(set(identities)) != 45:
        raise ValueError("baseline must contain exactly 45 distinct control pairs")
    run_dir = arguments.out.parent / (arguments.out.stem + "-runs")
    run_dir.mkdir(parents=True, exist_ok=True)
    baseline_path = run_dir / "mechanical-baseline.json"
    if baseline_path.exists() and baseline_path.read_bytes() != baseline_bytes:
        raise ValueError("mechanical baseline changed; use a separate report path")
    if not baseline_path.exists():
        baseline_path.write_bytes(baseline_bytes)
    source = root / "contracts/attaint.bradbury.py"
    if not source.exists():
        source = root / "contracts/attaint.py"
    arguments.code_hash = arguments.code_hash or hashlib.sha256(source.read_bytes()).hexdigest()
    meta = {"source": "live-bradbury-consensus", "chainId": 4221,
            "code_sha256": arguments.code_hash,
            "contract": arguments.contract, "policy_id": arguments.policy,
            "policy_hash": arguments.policy_hash, "rpc": arguments.rpc,
            "baseline_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
            "control_total": 45}
    report = {**meta, "controls": [], "completed": False}
    if arguments.out.exists():
        report = json.loads(arguments.out.read_text())
        for key, value in meta.items():
            if report.get(key) != value:
                raise ValueError("resume identity mismatch: " + key)
        if [(r["package"], r["from"], r["to"]) for r in report["controls"]] != identities[:len(report["controls"])]:
            raise ValueError("saved report does not follow the pinned control pairs")
    invalidate_comparison(report)
    _save(arguments.out, report)
    code = gate_cli.bridge("code", rpc=arguments.rpc, address=arguments.contract)
    if code.get("code_sha256") != arguments.code_hash:
        raise ValueError("deployed source hash does not match the pinned scan contract")
    policy = gate_cli.bridge("read", rpc=arguments.rpc, address=arguments.contract,
                             method="get_policy", args=[arguments.policy], variant="latest-nonfinal")["result"]
    if policy["policy_hash"] != arguments.policy_hash or policy.get("policy_id") != arguments.policy:
        raise ValueError("consumer policy hash does not match live chain")

    # Validate all exact pins first. Existing transactions drain before a new
    # bounded batch, so a per-contract pending queue cannot be filled blindly.
    prepared_args = []
    def persist_failure_history(row):
        _save(arguments.out,report)
        history_path = root/"runs/attempt-history.json"
        if history_path.exists():
            history = json.loads(history_path.read_text())
            records = history.setdefault("evm_submission_failures",[])
            for failure in row.get("failed_submissions",[]):
                if not any(record.get("evm_hash") == failure["evm_hash"] for record in records):
                    records.append({"kind":"PENDING_QUEUE_REVERT","contract":arguments.contract,
                        "package":row["package"],"from":row["from"],"to":row["to"],
                        "evm_hash":failure["evm_hash"],"nonce":failure["nonce"],
                        "receipt":failure["evm_receipt"],"receipt_sha256":failure["receipt_sha256"],
                        "consensus_transaction_created":False,"selector":"0xd48a82a3",
                        "error":"PendingQueueFull(address,uint256)","maximum":20,
                        "retry_basis":"Confirmed EVM revert; original intent/nonce preserved in archive before replacement scheduling."})
            _save(history_path,history)
    def persist_consensus_history(row):
        _save(arguments.out,report)
        history_path=root/"runs/attempt-history.json"
        if history_path.exists():
            history=json.loads(history_path.read_text());records=history.setdefault("uncommitted_consensus_failures",[])
            for failure in row.get("failed_consensus_attempts",[]):
                if not any(record["hash"]==failure["hash"] for record in records):
                    records.append({**failure,"contract":arguments.contract,"package":row["package"],"from":row["from"],"to":row["to"],
                        "retry_basis":"Explicit reschedule after live UNDETERMINED receipt and complete latest-nonfinal attestation audit proved no committed release identity."})
            _save(history_path,history)
    for index, pair in enumerate(pairs):
        prefix = run_dir / ("%02d" % index)
        envelope_path = prefix.with_suffix(".envelope.json")
        if envelope_path.exists():
            evidence = json.loads(envelope_path.read_text())
        else:
            evidence = env.build(pair["package"], pair["from"], pair["to"])
            evidence["envelope_hash"] = env.envelope_hash(evidence)
            _save(envelope_path, evidence)
        if tuple(evidence[k] for k in ("package", "from_version", "to_version")) != identities[index]:
            raise ValueError("envelope identity mismatch at pair %d" % index)
        if evidence.get("envelope_hash") != env.envelope_hash(evidence):
            raise ValueError("saved evidence hash mismatch at pair %d" % index)
        evidence_text = env.canonical(evidence)
        if len(evidence_text.encode("utf-8")) > env.MAX_EVIDENCE:
            raise ValueError("canonical envelope exceeds contract limit at pair %d" % index)
        write_args = [arguments.policy, evidence["package"], evidence["from_version"],
                      evidence["to_version"], int(evidence.get("evidence_level", 1)),
                      env.envelope_hash(evidence), evidence_text]
        prepared_args.append(write_args)
        journal_path = prefix.with_suffix(".transaction.json")
        if index >= len(report["controls"]):
            row = {**pair, "mechanical_classes": pair["classes"], "envelope_hash": env.envelope_hash(evidence),
                   "status": "PINNED", "envelope": str(envelope_path), "journal": str(journal_path)}
            row.pop("classes", None)
            report["controls"].append(row)
            _save(arguments.out, report)
        row = report["controls"][index]
        if index in getattr(arguments,"defer_pair",[]):
            row.update(status="RETRY_APPROVAL_PENDING",reason="operator deferred this pair; no resubmission authorized")
            _save(arguments.out,report)
            continue
        if journal_path.exists():
            journal = json.loads(journal_path.read_text())
            if (journal.get("chainId") != 4221 or journal.get("address") != arguments.contract
                    or journal.get("command") != "write" or journal.get("method") != "request_attestation"
                    or journal.get("args") != write_args):
                raise ValueError("saved submission identity mismatch at pair %d" % index)
            if journal.get("hash"):
                if row.get("transaction_hash") and row["transaction_hash"] != journal["hash"]:
                    raise ValueError("report/journal transaction mismatch at pair %d" % index)
                if index in arguments.reschedule_undetermined:
                    archive_uncommitted_consensus(journal_path,row,
                        lambda hash:gate_cli.bridge("receipt",rpc=arguments.rpc,hash=hash),
                        lambda:gate_cli.bridge("gates",rpc=arguments.rpc,address=arguments.contract),
                        lambda:persist_consensus_history(row))
                else:
                    row["transaction_hash"] = journal["hash"]
                    row["status"] = "SUBMITTED"
            elif journal.get("submission_intent") and arguments.archive_reverted_submissions:
                archive_reverted_submission(journal_path,row,lambda hash:gate_cli.bridge("evm-receipt",rpc=arguments.rpc,hash=hash),lambda:persist_failure_history(row))
            elif journal.get("submission_intent"):
                # Resolve an uncertain receipt without authorizing a replacement.
                journal = gate_cli.bridge("write", rpc=arguments.rpc, address=arguments.contract,
                    method="request_attestation", args=write_args, account=arguments.account, out=journal_path)
                row["transaction_hash"], row["status"] = journal["hash"], "SUBMITTED"
        if not row.get("transaction_hash"):
            row["status"] = "PINNED"
        _save(arguments.out, report)

    failures = []
    def settle_row(index):
        row = report["controls"][index]
        prefix = run_dir / ("%02d" % index)
        receipt_path = prefix.with_suffix(".receipt.json")
        command = ["node", str(root / "scripts/live.mjs"), "settle", "--hash", row["transaction_hash"],
                   "--out", str(receipt_path), "--rpc", arguments.rpc, "--account", arguments.account,
                   "--timeout", str(arguments.timeout)]
        # A finalized receipt is reread and the gate is always refreshed live.
        try:
            process = subprocess.run(command, text=True, capture_output=True,
                                     timeout=arguments.timeout + 120)
            if process.returncode:
                raise ValueError(process.stderr.strip() or "settlement failed")
            receipt = json.loads(process.stdout)
            att_id = settled_attestation(receipt, row["transaction_hash"], arguments.contract)
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
            row["status"] = "INCONCLUSIVE_EXECUTION"
            row["reason"] = str(error)
            failures.append(index)
            _save(arguments.out, report)
            print("INCONCLUSIVE pair %d: %s" % (index, row["reason"]), flush=True)
            return False
        try:
            evidence = json.loads(pathlib.Path(row["envelope"]).read_text())
            live = gate_cli.live_gate(contract=arguments.contract, policy_id=arguments.policy,
                                      policy_hash=arguments.policy_hash, attestation=att_id,
                                      evidence=evidence, rpc=arguments.rpc, code_hash=arguments.code_hash,
                                      expected_requester=receipt["receipt"]["sender"])
            _save(prefix.with_suffix(".gate.json"), live)
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
            row.update(status="INCONCLUSIVE_READBACK", reason=str(error))
            failures.append(index)
            _save(arguments.out, report)
            print("INCONCLUSIVE pair %d: %s" % (index, row["reason"]), flush=True)
            return False
        row.update({"status": "FINALIZED", "attestation_id": att_id,
                    "receipt": str(receipt_path), "gate": live["gate"], "exit_code": live["exit_code"]})
        row.pop("reason", None)
        _save(arguments.out, report)
        print("FINALIZED %02d/45 %s %s" % (index+1,row["package"],live["gate"]["gate"]), flush=True)
        return True

    def submit_row(index):
        row = report["controls"][index]
        if row.get("failed_consensus_attempts"):
            if index not in arguments.reschedule_undetermined:
                raise ValueError("replacement requires explicit --reschedule-undetermined authorization")
            prior=json.loads(pathlib.Path(row["failed_consensus_attempts"][-1]["journal"]).read_text())
            prove_uncommitted_consensus(prior,
                lambda hash:gate_cli.bridge("receipt",rpc=arguments.rpc,hash=hash),
                lambda:gate_cli.bridge("gates",rpc=arguments.rpc,address=arguments.contract))
        journal = gate_cli.bridge("write", rpc=arguments.rpc, address=arguments.contract,
            method="request_attestation", args=prepared_args[index],
            account=arguments.account, out=pathlib.Path(row["journal"]))
        row.update(transaction_hash=journal["hash"], status="SUBMITTED")
        _save(arguments.out, report)
        print("SUBMITTED %02d/45 %s %s → %s %s" %
              (index+1,row["package"],row["from"],row["to"],journal["hash"]), flush=True)

    def release_journals():
        if not arguments.finalize_release:
            return {}
        result = {name:json.loads((root/"runs"/(name+".json")).read_text())
                  for name in ("deploy","policy","first-attestation")}
        for name, journal in result.items():
            if journal.get("chainId") != 4221 or not journal.get("hash"):
                raise ValueError("release journal chain/transaction mismatch: " + name)
            if name == "deploy":
                if journal.get("command") != "deploy" or journal.get("source_sha256") != arguments.code_hash:
                    raise ValueError("release deployment source mismatch")
            elif journal.get("address") != arguments.contract or journal.get("command") != "write":
                raise ValueError("release journal contract/command mismatch: " + name)
            elif journal.get("method") != {"policy":"register_policy","first-attestation":"request_attestation"}[name]:
                raise ValueError("release journal method mismatch: " + name)
            if name == "first-attestation" and journal.get("args",[])[0] != arguments.policy:
                raise ValueError("first release attestation policy mismatch")
        return result

    def settle_release(name,journal):
        path = root/"runs"/(name+".json")
        command = ["node",str(root/"scripts/live.mjs"),journal["command"],"--out",str(path),
                   "--account",arguments.account,"--rpc",arguments.rpc,"--wait","--timeout","180"]
        if name == "deploy":
            command += ["--file",str(source)]
        else:
            command += ["--address",arguments.contract,"--method",journal["method"],
                        "--args-file",str(root/"runs"/(name+"-args.json"))]
        process = subprocess.run(command,text=True,capture_output=True,timeout=300)
        if process.returncode:
            raise ValueError("release settlement failed: " + name + ": " + process.stderr.strip())
        print("FINALIZED release " + name,flush=True)

    release_published = False
    def publish_release():
        nonlocal release_published
        if release_published:
            return True
        journals = release_journals()
        if not journals or any(j.get("trace_verified") is not True or j.get("receipt",{}).get("statusName") != "FINALIZED" for j in journals.values()):
            return False
        first = journals["first-attestation"]
        evidence = json.loads(first["args"][6])
        attestation = settled_attestation(first,first["hash"],arguments.contract)
        live = gate_cli.live_gate(contract=arguments.contract,policy_id=arguments.policy,
            policy_hash=arguments.policy_hash,attestation=attestation,evidence=evidence,
            rpc=arguments.rpc,code_hash=arguments.code_hash,expected_requester=first["receipt"]["sender"])
        if live["gate"].get("registry_verification") != "VERIFIED" or live["gate"].get("rounds") != 6:
            raise ValueError("first finalized gate did not verify registry/six judgments")
        _save(root/"runs/first-attestation-gate.json",live)
        _save(root/"runs/deployment.json",{"chain_id":4221,"network":"bradbury","rpc":arguments.rpc,
            "contract":arguments.contract,"code_sha256":arguments.code_hash,"policy_id":arguments.policy,
            "policy_hash":arguments.policy_hash,"first_attestation_id":attestation,
            "first_envelope_hash":first["args"][5],"status":"FINALIZED",
            "transactions":{name:j["hash"] for name,j in journals.items()}})
        release_published = True
        print("RELEASE finalized manifest and first live gate published",flush=True)
        return True

    report["batch_size"] = arguments.batch_size
    deadline = time.monotonic()+arguments.timeout
    last_progress = ""
    while arguments.queue_paced:
        if time.monotonic() >= deadline:
            raise ValueError("paced scan timeout; resume the same report/journals")
        releases = release_journals()
        unfinished = [r for r in report["controls"] if r.get("transaction_hash") and r["status"] not in {"FINALIZED","RETRY_APPROVAL_PENDING"}]
        hashes = [r["transaction_hash"] for r in unfinished]
        hashes += [j["hash"] for j in releases.values() if not j.get("trace_verified")]
        observation = gate_cli.bridge("poll",rpc=arguments.rpc,address=arguments.contract,args=hashes)
        report["queue"] = observation["queue"]
        by_hash = {state["hash"]:state for state in observation["states"]}
        for index,row in enumerate(report["controls"]):
            if row not in unfinished:
                continue
            state = by_hash[row["transaction_hash"]]
            row["consensus_status"] = state["status"]
            if state["status"] in {"CANCELED","UNDETERMINED","VALIDATORS_TIMEOUT","LEADER_TIMEOUT"}:
                row.update(status="INCONCLUSIVE_EXECUTION",reason="terminal consensus status: "+state["status"])
                failures.append(index)
        _save(arguments.out,report)
        acted = False
        # Initial release finalizations have priority over corpus submissions.
        for name,journal in releases.items():
            state = by_hash.get(journal["hash"])
            if state and (state["status"] == "FINALIZED" or (state.get("capability") or {}).get("eligible")):
                settle_release(name,journal)
                acted = True
        publish_release()
        for index,row in enumerate(report["controls"]):
            state = by_hash.get(row.get("transaction_hash"))
            if row["status"] != "FINALIZED" and state and (state["status"] == "FINALIZED" or (state.get("capability") or {}).get("eligible")):
                settle_row(index)
                acted = True
        if failures:
            break
        if all(row["status"] in {"FINALIZED","RETRY_APPROVAL_PENDING"} for row in report["controls"]):
            break
        # Refresh authoritative capacity before each paid write, including
        # pending submissions made by other wallets or a browser.
        submitted = 0
        for index,row in enumerate(report["controls"]):
            if row["status"] == "RETRY_APPROVAL_PENDING" or row.get("transaction_hash") or submitted >= arguments.batch_size:
                continue
            queue = gate_cli.bridge("poll",rpc=arguments.rpc,address=arguments.contract,args=[])["queue"]
            report["queue"] = queue
            if not queue_capacity(queue):
                break
            submit_row(index)
            submitted += 1
            acted = True
        progress = "pending=%s/%s submitted=%s/45 finalized=%s/45" % (report["queue"]["pending"],report["queue"]["maximum"],sum(bool(r.get("transaction_hash")) for r in report["controls"]),sum(r["status"]=="FINALIZED" for r in report["controls"]))
        if progress != last_progress:
            print("QUEUE " + progress,flush=True)
            last_progress = progress
        if not acted:
            time.sleep(10)
    while not arguments.queue_paced:
        batch, submit = next_scan_batch(report["controls"], arguments.batch_size)
        if not batch:
            break
        if submit:
            for index in batch:
                submit_row(index)
        print("SETTLING batch %s; no further submissions until it drains" % ",".join(str(i) for i in batch), flush=True)
        for index in batch:
            settle_row(index)
        if failures:
            break  # Do not allocate another batch while a transaction is unresolved.
    finished = [r for r in report["controls"] if r.get("status") == "FINALIZED"]
    counts = {name: sum(r["gate"]["gate"] == name for r in finished)
              for name in ("CLEAN", "RISK", "INCONCLUSIVE")}
    mechanical_blocked = sum(bool(r["classes"]) for r in pairs)
    report["completed"] = len(finished) == 45
    report["consensus_counts"] = counts
    report["mechanical_blocked"] = mechanical_blocked
    report["mechanical_blocked_percent"] = mechanical_blocked * 100 / 45
    # A comparison is published only when all 45 exact pairs have real gates.
    if report["completed"]:
        report["consensus_risk_percent"] = counts["RISK"] * 100 / 45
        report["risk_reduction_percentage_points"] = (mechanical_blocked-counts["RISK"]) * 100 / 45
        report["inconclusive_percent"] = counts["INCONCLUSIVE"] * 100 / 45
        report["consensus_blocked_percent"] = (counts["RISK"] + counts["INCONCLUSIVE"]) * 100 / 45
        report["blocked_reduction_percentage_points"] = (mechanical_blocked - counts["RISK"] - counts["INCONCLUSIVE"]) * 100 / 45
    _save(arguments.out, report)
    return 0 if report["completed"] else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consensus", action="store_true", help="live replay of the fixed 45 control pairs")
    parser.add_argument("--contract")
    parser.add_argument("--policy", type=int)
    parser.add_argument("--policy-hash")
    parser.add_argument("--code-hash", help="optional deployed source hash override")
    parser.add_argument("--account", default="recuse-deployer")
    parser.add_argument("--rpc", default="https://rpc-bradbury.genlayer.com")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--batch-size", type=int, default=10, help="submit at most this many writes before finalizing them (1–20)")
    parser.add_argument("--archive-reverted-submissions", action="store_true", help="explicitly archive proven reverted EVM submissions before scheduling replacement writes")
    parser.add_argument("--queue-paced", action="store_true", help="pace writes by authoritative queue capacity with two free slots, finalizing eligible receipts serially")
    parser.add_argument("--finalize-release", action="store_true", help="prioritize existing runs deploy/policy/first-attestation journals in the single-writer paced loop")
    parser.add_argument("--reschedule-undetermined",type=int,action="append",default=[],metavar="INDEX",help="explicitly reschedule this pair only after live no-commit proof; preserve failed consensus hash and journal")
    parser.add_argument("--defer-pair",type=int,action="append",default=[],metavar="INDEX",help="leave this pair awaiting operator approval while completing others; report stays incomplete")
    root = pathlib.Path(__file__).resolve().parents[1]
    parser.add_argument("--baseline", type=pathlib.Path, default=root / "corpus/scan-report.json")
    parser.add_argument("--out", type=pathlib.Path, default=root / "runs/consensus-report.json")
    args = parser.parse_args()
    if not 1 <= args.batch_size <= 20:
        parser.error("--batch-size must be between 1 and 20")
    if args.finalize_release and not args.queue_paced:
        parser.error("--finalize-release requires --queue-paced")
    if any(index < 0 or index >= 45 for index in args.reschedule_undetermined+args.defer_pair):
        parser.error("pair index must be between 0 and 44")
    if args.defer_pair and not args.queue_paced:
        parser.error("--defer-pair requires --queue-paced")
    if set(args.defer_pair)&set(args.reschedule_undetermined):
        parser.error("a pair cannot be both deferred and rescheduled")
    if not args.consensus:
        return mechanical_main()
    if not args.contract or args.policy is None or not args.policy_hash:
        parser.error("--consensus requires --contract, --policy and --policy-hash")
    try:
        return consensus_main(args)
    except Exception as error:
        print("INCONCLUSIVE: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
