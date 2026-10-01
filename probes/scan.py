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
import hashlib
import json
import time
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
    att_id = document.get("return_value")
    if isinstance(att_id, str) and att_id.isdecimal():
        att_id = int(att_id)
    if type(att_id) is not int or att_id < 0:
        raise ValueError("receipt has no nonnegative integer attestation return value")
    return att_id


def consensus_main(arguments) -> int:
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

    # First pin and broadcast the fixed sample. Finalization windows overlap;
    # each write gets a permanent journal immediately after its hash is known.
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
        journal_path = prefix.with_suffix(".transaction.json")
        if index >= len(report["controls"]):
            row = {**pair, "mechanical_classes": pair["classes"], "envelope_hash": env.envelope_hash(evidence),
                   "status": "PINNED", "envelope": str(envelope_path), "journal": str(journal_path)}
            row.pop("classes", None)
            report["controls"].append(row)
            _save(arguments.out, report)
        row = report["controls"][index]
        # Existing journals are resumed by the runner, never resubmitted.
        journal = gate_cli.bridge("write", rpc=arguments.rpc, address=arguments.contract,
                                  method="request_attestation", args=write_args,
                                  account=arguments.account, out=journal_path)
        row["transaction_hash"] = journal["hash"]
        row["status"] = "SUBMITTED"
        _save(arguments.out, report)
        print("SUBMITTED %02d/45 %s %s → %s %s" %
              (index+1, pair["package"], pair["from"], pair["to"], journal["hash"]), flush=True)

    failures = []
    for index, row in enumerate(report["controls"]):
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
            continue
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
            continue
        row.update({"status": "FINALIZED", "attestation_id": att_id,
                    "receipt": str(receipt_path), "gate": live["gate"], "exit_code": live["exit_code"]})
        row.pop("reason", None)
        _save(arguments.out, report)
        print("FINALIZED %02d/45 %s %s" % (index+1,row["package"],live["gate"]["gate"]), flush=True)
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
    root = pathlib.Path(__file__).resolve().parents[1]
    parser.add_argument("--baseline", type=pathlib.Path, default=root / "corpus/scan-report.json")
    parser.add_argument("--out", type=pathlib.Path, default=root / "runs/consensus-report.json")
    args = parser.parse_args()
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
