#!/usr/bin/env python3
"""Package reviewable source and current release evidence using an allowlist.

The archive never walks environment, account, build-cache or dependency folders.
Known credential patterns abort packaging without printing matching values.
SHA256SUMS.json records the exact bytes of every archived file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIRECTORIES = {
    "contracts": {".py"}, "cli": {".py"}, "probes": {".py"},
    "scripts": {".py", ".mjs"}, "spec": {".md"},
    "test": {".py", ".json"}, "corpus": {".json", ".md"},
    ".github/workflows": {".yml", ".yaml"},
}
FILES = (
    "README.md", "FINDINGS.md", "SUBMISSION.md", "package.json", "package-lock.json",
    "requirements-dev.txt", "vercel.json", "web/index.html", "web/app.js", ".gitignore", ".vercelignore",
    "scripts/transaction_manager_abi.json", "scripts/queue_head_abi.json",
)
RELEASE_FILES = (
    "runs/deployment.json", "runs/consensus-report.json", "runs/deploy.json",
    "runs/policy.json", "runs/policy-readback.json", "runs/policy-args.json",
    "runs/policy-read-args.json", "runs/first-attestation.json",
    "runs/first-attestation-args.json", "runs/first-attestation-gate.json",
    "runs/first-attestation-readback.json", "runs/deployed-code.json",
    "runs/smoke-recovery.json",
    "runs/attempt-history.json",
    "runs/ci-verification.json",
    "runs/browser-verification.json", "runs/browser-attestation.json", "runs/browser-envelope.json",
    "runs/diagnostics/express-finalized-no-commit.json",
    "runs/diagnostics/yargs-finalized-no-commit.json",
    "runs/diagnostics/failed-rows-23-24.json",
    "runs/diagnostics/expired-queue-no-commit.json",
    "runs/diagnostics/expired-cleanup-summary.json",
    "runs/diagnostics/post-cleanup-unfinished-no-commit.json",
    "runs/diagnostics/canceled-retry-manifest.json",
    "runs/diagnostics/expired-cleanup-43-summary.json",
    "runs/diagnostics/canceled-retry-42-43-manifest.json",
    "runs/diagnostics/finalized-retries-no-commit.json",
    "runs/diagnostics/finalized-retry-21-23-44-manifest.json",
    "runs/diagnostics/finalized-42-43-readback-audit.json",
    "runs/diagnostics/public-instance-recovery.json",
    "runs/benchmark-release/deployment.json",
    "runs/benchmark-release/deploy.json",
    "runs/benchmark-release/policy.json",
    "runs/benchmark-release/first-attestation.json",
    "runs/benchmark-release/first-attestation-gate.json",
    "runs/benchmark-release/policy-readback.json",
    "runs/benchmark-release/deployed-code.json",
    "runs/benchmark-release/ci-verification.json",
    "runs/diagnostics/locator-enum-simulation/manifest.json",
    "runs/diagnostics/locator-enum-simulation/report.json",
    "runs/diagnostics/locator-enum-simulation/leader-summary.json",
    "runs/diagnostics/locator-enum-simulation/validator-1-summary.json",
    "runs/diagnostics/locator-enum-simulation/validator-2-summary.json",
    "runs/diagnostics/locator-enum-simulation/diagnostic-code.py",
)
RUN_SUFFIXES = (".envelope.json", ".transaction.json", ".receipt.json", ".gate.json")
MAX_FILES = 512
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
EXCLUDED_PARTS = {"__pycache__", "node_modules", ".vercel", ".git", ".aws", ".agents", ".codex"}

SECRET_PATTERNS = {
    "OpenAI API key": r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}",
    "GitHub token": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    "GitLab token": r"\bglpat-[A-Za-z0-9_-]{20,}",
    "Slack token": r"\bxox[baprs]-[A-Za-z0-9-]{20,}",
    "Vercel token": r"\bvcp_[A-Za-z0-9_-]{20,}",
    "AWS access key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "Private key PEM": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "Assigned private key": r"(?i)[\"']?(?:private[_-]?key|GENLAYER_PRIVATE_KEY)[\"']?\s*[:=]\s*[\"'](?:0x)?[a-f0-9]{64}[\"']",
    "Embedded HTTP credential": r"https?://[^\s/\"']+:[^\s/\"']+@",
    "Assigned service secret": r"(?i)[\"']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_/-]{24,}[\"']",
}


def scan_credentials(name: str, payload: bytes) -> None:
    text = payload.decode("utf-8")
    texts = [text]
    if name.endswith(".json"):
        try:
            stack = [json.loads(text)]
        except json.JSONDecodeError:
            raise ValueError("invalid JSON source: " + name)
        while stack:
            value = stack.pop()
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    for candidate in texts:
        for label, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, candidate):
                # Never print or include the matching credential in an exception.
                raise ValueError("credential pattern detected in %s (%s)" % (name, label))


def allowed_sources(root: pathlib.Path) -> list[pathlib.Path]:
    selected = {root / name for name in FILES + RELEASE_FILES if (root / name).exists()}
    for directory, extensions in DIRECTORIES.items():
        parent = root / directory
        if parent.exists():
            selected.update(path for path in parent.rglob("*") if path.suffix in extensions and path.is_file())
    run_directory = root / "runs/consensus-report-runs"
    if run_directory.exists():
        for path in run_directory.iterdir():
            if path.name == "mechanical-baseline.json" or re.fullmatch(
                    r"(?:[0-3]\d|4[0-4])(?:\.envelope|\.transaction|\.receipt|\.gate)\.json", path.name):
                selected.add(path)
    approved = []
    for path in sorted(selected):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS or part.startswith(".env") for part in relative.parts):
            continue
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root.parent):
            raise ValueError("symlinks are not allowed: " + relative.as_posix())
        if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("source is not a regular workspace file: " + relative.as_posix())
        approved.append(path)
    return approved


def package(root: pathlib.Path, destination: pathlib.Path) -> dict:
    paths = allowed_sources(root)
    if len(paths) > MAX_FILES:
        raise ValueError("source archive exceeds file-count limit")
    records, payloads = [], []
    total = 0
    for path in paths:
        name = path.relative_to(root).as_posix()
        payload = path.read_bytes()
        total += len(payload)
        if len(payload) > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError("source archive exceeds byte limit: " + name)
        scan_credentials(name, payload)
        records.append({"path": name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        payloads.append((name, payload))
    manifest = {"format": "attaint-source-archive/1", "credential_pattern_scan": "passed",
                "files": records, "source_bytes": total,
                "exclusions": ["credentials", "attempt archives", "dependencies", "caches", "browser bundle"]}
    manifest_payload = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    scan_credentials("SHA256SUMS.json", manifest_payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, payload in payloads + [("SHA256SUMS.json", manifest_payload)]:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, payload)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise ValueError("archive integrity check failed")
            for record in records:
                if hashlib.sha256(archive.read(record["path"])).hexdigest() != record["sha256"]:
                    raise ValueError("archive content hash mismatch")
        temporary.replace(destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"archive": str(destination), "files": len(records) + 1,
            "bytes": destination.stat().st_size,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "credential_pattern_scan": "passed"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "web/source.zip")
    arguments = parser.parse_args()
    try:
        print(json.dumps(package(ROOT, arguments.out), indent=2))
        return 0
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile) as error:
        print("Source packaging failed: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
