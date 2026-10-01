#!/usr/bin/env python3
"""Read a finalized Bradbury attestation. CLEAN=0, RISK=1, INCONCLUSIVE=2.

The expected policy hash and envelope are supplied by the consumer. Saved JSON
is audit evidence only: every invocation verifies chain, code, policy and gate
from the live network. A transport or identity failure blocks CI with exit 2.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

import envelope as env

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXIT = {"CLEAN": 0, "RISK": 1, "INCONCLUSIVE": 2}


def bridge(command: str, *, rpc: str, **kwargs) -> dict:
    """Invoke the SDK with JSON on disk so evidence never becomes shell code."""
    with tempfile.TemporaryDirectory(prefix="attaint-rpc-") as directory:
        args = ["node", str(ROOT / "scripts/live.mjs"), command, "--rpc", rpc]
        for name, value in kwargs.items():
            if name == "args":
                file = pathlib.Path(directory) / "args.json"
                file.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
                args.extend(["--args-file", str(file)])
            else:
                args.extend(["--" + name.replace("_", "-"), str(value)])
        process = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if process.returncode:
            raise ValueError(process.stderr.strip() or "SDK call failed")
        result = json.loads(process.stdout)
        if result.get("chainId") != 4221:
            raise ValueError("Bradbury chain mismatch")
        return result


def verify_gate(gate: dict, policy: dict, evidence: dict, *, policy_id: int,
                policy_hash: str, attestation: int) -> int:
    expected_hash = env.envelope_hash(evidence)
    declared = evidence.get("envelope_hash")
    if declared is not None and declared != expected_hash:
        raise ValueError("local envelope hash mismatch")
    expected = {"att_id": attestation, "policy_id": policy_id,
                "policy_hash": policy_hash, "envelope_hash": expected_hash}
    expected.update({k: evidence[k] for k in ("package", "from_version", "to_version")})
    for key, value in expected.items():
        if gate.get(key) != value:
            raise ValueError("gate identity mismatch: " + key)
    if policy.get("policy_id") != policy_id or policy.get("policy_hash") != policy_hash:
        raise ValueError("live policy does not match the consumer's pinned policy")
    level = int(evidence.get("evidence_level", 1))
    if gate.get("level") != level:
        raise ValueError("evidence level mismatch")
    result = gate.get("gate")
    if result not in EXIT:
        raise ValueError("unknown gate result")
    if result == "CLEAN":
        if gate.get("verdict") != "CLEAN" or gate.get("inconclusive_classes") or gate.get("findings"):
            raise ValueError("inconsistent CLEAN gate")
        if level > int(policy["min_level"]) or int(gate["rounds"]) < int(policy["min_rounds"]):
            raise ValueError("CLEAN does not meet the pinned policy")
    if result == "RISK" and gate.get("verdict") not in policy.get("blocking", []):
        raise ValueError("risk verdict is outside the pinned policy")
    return EXIT[result]


def live_gate(*, contract: str, policy_id: int, policy_hash: str, attestation: int,
              evidence: dict, rpc: str, code_hash: str | None = None, expected_requester: str | None = None) -> dict:
    code = bridge("code", rpc=rpc, address=contract)
    if "class Attaint" not in code["code"] or "def gate(" not in code["code"]:
        raise ValueError("address does not contain an Attaint gate")
    expected_source = ROOT / "contracts/attaint.bradbury.py"
    if not expected_source.exists():
        expected_source = ROOT / "contracts/attaint.py"
    code_hash = code_hash or hashlib.sha256(expected_source.read_bytes()).hexdigest()
    if code["code_sha256"] != code_hash:
        raise ValueError("deployed code hash mismatch")
    policy = bridge("read", rpc=rpc, address=contract, method="get_policy", args=[policy_id])["result"]
    gate = bridge("read", rpc=rpc, address=contract, method="gate", args=[attestation])["result"]
    if expected_requester and str(gate.get("requester", "")).lower() != expected_requester.lower():
        raise ValueError("attestation requester mismatch")
    exit_code = verify_gate(gate, policy, evidence, policy_id=policy_id,
                            policy_hash=policy_hash, attestation=attestation)
    return {"source": "live-finalized-bradbury", "chainId": 4221, "rpc": rpc,
            "contract": contract, "code_sha256": code["code_sha256"],
            "policy": policy, "gate": gate, "exit_code": exit_code}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--policy", required=True, type=int)
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--attestation", required=True, type=int)
    parser.add_argument("--envelope", required=True, type=pathlib.Path)
    parser.add_argument("--json", action="store_true", help="compatibility flag; output is always JSON")
    parser.add_argument("--expected-requester", help="optional pin of the attestation requester wallet")
    parser.add_argument("--code-hash", help="expected deployed source hash; defaults to this checkout compiled Bradbury contract")
    parser.add_argument("--rpc", default="https://rpc-bradbury.genlayer.com")
    parser.add_argument("--out", type=pathlib.Path, help="save the live readback for auditing")
    arguments = parser.parse_args()
    try:
        evidence = json.loads(arguments.envelope.read_text(encoding="utf-8"))
        result = live_gate(contract=arguments.contract, policy_id=arguments.policy,
                           policy_hash=arguments.policy_hash, attestation=arguments.attestation,
                           evidence=evidence, rpc=arguments.rpc, code_hash=arguments.code_hash,
                           expected_requester=arguments.expected_requester)
        if arguments.out:
            arguments.out.parent.mkdir(parents=True, exist_ok=True)
            arguments.out.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return result["exit_code"]
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"gate": "INCONCLUSIVE", "exit_code": 2, "reason": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
