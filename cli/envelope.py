#!/usr/bin/env python3
"""Build an `attaint/1` evidence envelope for one npm dependency update.

The envelope is the unit of judgement, the unit of dedup and the unit a rerun
replays. It follows the canonicalisation rules of `suborn/1`: unlisted keys are
dropped, empty optional keys are dropped, serialisation is sorted-key with
`,`/`:` separators and no whitespace, and `envelope_hash` is the lowercase hex
sha256 of that string.

Two properties are carried over from Suborn deliberately.

Judging sees the facts verbatim. Dedup sees a flattened form. The builder never
decides a class: it extracts candidates and pins them, and the verdict is the
consensus' job. A builder that decided `INSTALL_HOOK` itself would make the
contract decorative.

Fail closed. If the tarball does not hash to the integrity recorded by the
registry, or the version is gone, no envelope is produced and the caller gets a
non-zero exit. An unpinnable update is `INCONCLUSIVE`, never `CLEAN`.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.error
import urllib.request
import urllib.parse

REGISTRY = "https://registry.npmjs.org"
ENVELOPE_VERSION = "attaint/1"
USER_AGENT = "attaint-envelope/1"

# Bounded on purpose. npm tarballs run to megabytes and the judged material has
# to fit a prompt, so only these slices of a candidate file travel.
HEAD_BYTES = 1200
MAX_CANDIDATES = 12
MAX_FILE_LIST = 400
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_UNPACKED = 128 * 1024 * 1024
MAX_EVIDENCE = 12288

TOP_KEYS = (
    "version",
    "registry",
    "package",
    "from_version",
    "to_version",
    "pin",
    "facts",
    "fetched_from",
    "author_note",
)


class Unpinnable(Exception):
    """Evidence could not be pinned. The caller must report INCONCLUSIVE."""


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------


def _get(url: str, as_json: bool = True):
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(MAX_DOWNLOAD + 1)
            if len(payload) > MAX_DOWNLOAD:
                raise Unpinnable("download exceeds 64 MiB")
    except urllib.error.HTTPError as error:
        raise Unpinnable("%s -> HTTP %d" % (url, error.code))
    except Exception as error:  # network, DNS, timeout
        raise Unpinnable("%s -> %s" % (url, error))
    if as_json:
        try:
            return json.loads(payload)
        except (ValueError, UnicodeError) as error:
            raise Unpinnable("invalid registry JSON") from error
    return payload


def packument(package: str) -> dict:
    return _get("%s/%s" % (REGISTRY, urllib.parse.quote(package, safe="")))


def integrity_sha512(blob: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode()


# ---------------------------------------------------------------------------
# candidate extraction
# ---------------------------------------------------------------------------

_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/=]{160,}")
_HEX_RUN = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){40,}")

SOURCE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".json", ".map", ".sh", ".py")
_NETWORK = re.compile(
    rb"https?://|(?:fetch|XMLHttpRequest|WebSocket)\s*\(|"
    rb"(?:https?|net|tls|dgram)\s*\.\s*(?:request|get|connect|createConnection|createSocket)\s*\(|"
    rb"require\s*\(\s*['\"](?:node:)?(?:https?|net|tls|dgram)['\"]|"
    rb"\b(?:curl|wget)\s+", re.IGNORECASE
)
INSTALL_HOOKS = (
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
    "prepublish",
)


def _opacity(blob: bytes) -> dict:
    """Cheap, explainable signals. Not a verdict — the judge decides."""
    if not blob:
        return {}
    lines = blob.split(b"\n")
    longest = max(len(line) for line in lines)
    printable = sum(1 for byte in blob if 32 <= byte < 127 or byte in (9, 10, 13))
    return {
        "bytes": len(blob),
        "lines": len(lines),
        "longest_line": longest,
        "nonprintable_milli": int(round((1 - printable / len(blob)) * 1000)),
        "base64_runs": len(_BASE64_RUN.findall(blob)),
        "hex_escape_runs": len(_HEX_RUN.findall(blob)),
    }


def _read_tarball(blob: bytes) -> dict:
    """File list plus bounded heads of source files, for candidate extraction."""
    listing = []
    contents = {}
    skipped = []
    total = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        for member in archive:
            if not member.isfile():
                continue
            name = member.name
            if name.startswith("package/"):
                name = name[len("package/"):]
            listing.append({"path": name, "size": int(member.size)})
            total += member.size
            if total > MAX_UNPACKED:
                raise Unpinnable("tarball expands beyond 128 MiB")
            if name in contents:
                raise Unpinnable("duplicate tarball path: " + name)
            if name.endswith(SOURCE_SUFFIXES) and member.size <= 4_000_000:
                handle = archive.extractfile(member)
                if handle is not None:
                    contents[name] = handle.read()
            elif name.endswith(SOURCE_SUFFIXES) or name.endswith(".node"):
                skipped.append(name)
    listing.sort(key=lambda row: row["path"])
    return {"listing": listing, "contents": contents, "skipped": skipped}


def _egress_candidates(before: dict, after: dict) -> dict:
    """Bounded changed-line network candidates, never a verdict.

    Coverage is explicit: an unread source file or a dropped candidate cannot
    support a CLEAN EGRESS judgement. Dynamic/encoded calls remain outside this
    static extractor and can be challenged using the pinned material.
    """
    candidates = []
    truncated = False
    for path, blob in sorted(after["contents"].items()):
        previous = before["contents"].get(path)
        if previous == blob:
            continue
        old_lines = set((previous or b"").splitlines())
        for line_no, line in enumerate(blob.splitlines(), 1):
            if line in old_lines or not _NETWORK.search(line):
                continue
            match = _NETWORK.search(line)
            start = max(0, match.start() - 160)
            excerpt = line[start:start + HEAD_BYTES]
            candidates.append({"path": path, "line": line_no,
                               "excerpt": excerpt.decode("utf-8", "replace"),
                               "line_bytes": len(line)})
            truncated = truncated or len(line) > len(excerpt)
    total = len(candidates)
    return {"candidates": candidates[:MAX_CANDIDATES], "candidate_count": total,
            "complete": not truncated and total <= MAX_CANDIDATES
            and not before["skipped"] and not after["skipped"],
            "skipped_files": sorted(set(before["skipped"] + after["skipped"]))[:MAX_FILE_LIST],
            "scope": "static changed-source network patterns; not a whole-program proof"}


def _opaque_candidates(before: dict, after: dict) -> list:
    """Files added or changed whose shape is worth a judgement.

    Ranked, bounded, and always accompanied by the head of the file, so the
    judge sees the material rather than the builder's opinion of it.
    """
    candidates = []
    for path, blob in sorted(after.items()):
        previous = before.get(path)
        if previous == blob:
            continue
        signals = _opacity(blob)
        if not signals:
            continue
        interesting = (
            signals["longest_line"] >= 500
            or signals["base64_runs"] > 0
            or signals["hex_escape_runs"] > 0
            or signals["nonprintable_milli"] > 20
        )
        if not interesting:
            continue
        candidates.append(
            {
                "path": path,
                "status": "added" if previous is None else "changed",
                "signals": signals,
                "head": blob[:HEAD_BYTES].decode("utf-8", "replace"),
            }
        )
    candidates.sort(
        key=lambda row: (
            row["signals"]["base64_runs"] + row["signals"]["hex_escape_runs"],
            row["signals"]["longest_line"],
        ),
        reverse=True,
    )
    return candidates


# ---------------------------------------------------------------------------
# facts
# ---------------------------------------------------------------------------


def _publisher(manifest: dict) -> str:
    return str((manifest.get("_npmUser") or {}).get("name") or "")


def _maintainers(manifest: dict) -> list:
    return sorted(
        str(entry.get("name") or "") for entry in (manifest.get("maintainers") or [])
    )


def _license(manifest: dict) -> str:
    value = manifest.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    if value is None and manifest.get("licenses"):
        entries = manifest["licenses"]
        if isinstance(entries, list) and entries:
            value = entries[0].get("type") if isinstance(entries[0], dict) else entries[0]
    return str(value or "")


def _hooks(manifest: dict) -> dict:
    scripts = manifest.get("scripts") or {}
    return {name: str(scripts[name]) for name in INSTALL_HOOKS if name in scripts}


def _dependency_delta(before: dict, after: dict) -> dict:
    old = before.get("dependencies") or {}
    new = after.get("dependencies") or {}
    return {
        "added": {key: str(new[key]) for key in sorted(set(new) - set(old))},
        "removed": sorted(set(old) - set(new)),
        "changed": {
            key: [str(old[key]), str(new[key])]
            for key in sorted(set(old) & set(new))
            if old[key] != new[key]
        },
    }


def build(package: str, from_version: str, to_version: str, note: str = "") -> dict:
    document = packument(package)
    versions = document.get("versions") or {}
    times = document.get("time") or {}

    for label, version in (("from", from_version), ("to", to_version)):
        if version not in versions:
            published = times.get(version)
            raise Unpinnable(
                "%s@%s (%s side) is not in the registry%s"
                % (
                    package,
                    version,
                    label,
                    " but was published at " + published if published else "",
                )
            )

    before_manifest = versions[from_version]
    after_manifest = versions[to_version]

    pins = {}
    tarballs = {}
    for label, manifest in (("from", before_manifest), ("to", after_manifest)):
        dist = manifest.get("dist") or {}
        url = dist.get("tarball")
        if not url:
            raise Unpinnable("%s side has no tarball url" % label)
        blob = _get(url, as_json=False)
        declared = dist.get("integrity")
        computed = integrity_sha512(blob)
        if declared and declared != computed:
            raise Unpinnable(
                "%s side integrity mismatch: registry says %s, bytes hash to %s"
                % (label, declared, computed)
            )
        if not declared:
            shasum = dist.get("shasum")
            if not shasum:
                raise Unpinnable("%s side has no registry integrity or shasum" % label)
            if shasum != hashlib.sha1(blob).hexdigest():
                raise Unpinnable("%s side shasum mismatch" % label)
        tarballs[label] = blob
        pins[label] = {
            "integrity": str(declared or computed),
            "tarball_sha256": hashlib.sha256(blob).hexdigest(),
            "tarball_bytes": len(blob),
            "published_at": str(times.get(manifest["version"]) or ""),
            "registry_integrity": str(declared or ""),
            "registry_shasum": str(dist.get("shasum") or ""),
        }

    try:
        before_files = _read_tarball(tarballs["from"])
        after_files = _read_tarball(tarballs["to"])
    except (tarfile.TarError, EOFError, OSError) as error:
        raise Unpinnable("invalid tarball") from error

    before_paths = {row["path"] for row in before_files["listing"]}
    after_paths = {row["path"] for row in after_files["listing"]}

    facts = {
        "license": {
            "from": _license(before_manifest),
            "to": _license(after_manifest),
        },
        "publisher": {
            "from": _publisher(before_manifest),
            "to": _publisher(after_manifest),
        },
        "maintainers": {
            "from": _maintainers(before_manifest),
            "to": _maintainers(after_manifest),
        },
        "install_hooks": {
            "from": _hooks(before_manifest),
            "to": _hooks(after_manifest),
        },
        "dependencies": _dependency_delta(before_manifest, after_manifest),
        "files": {
            "added": sorted(after_paths - before_paths)[:MAX_FILE_LIST],
            "removed": sorted(before_paths - after_paths)[:MAX_FILE_LIST],
            "count_from": len(before_files["listing"]),
            "count_to": len(after_files["listing"]),
            "changed_source_count": sum(
                1 for path, blob in after_files["contents"].items()
                if before_files["contents"].get(path) != blob
            ),
            "changed_sources": [path for path, blob in sorted(after_files["contents"].items())
                                if before_files["contents"].get(path) != blob][:MAX_FILE_LIST],
        },
        "opaque_candidates": _opaque_candidates(
            before_files["contents"], after_files["contents"]
        ),
        "egress": _egress_candidates(before_files, after_files),
        "purpose": {
            "description": str(after_manifest.get("description") or "")[:800],
            "keywords": [str(item)[:80] for item in (after_manifest.get("keywords") or [])][:20],
        },
    }
    all_opaque = facts["opaque_candidates"]
    facts["opaque_candidates"] = all_opaque[:MAX_CANDIDATES]
    facts["opaque_coverage"] = {"candidate_count": len(all_opaque),
                                "complete": len(all_opaque) <= MAX_CANDIDATES
                                and not before_files["skipped"] and not after_files["skipped"]}

    envelope = {
        "version": ENVELOPE_VERSION,
        "registry": "npm",
        "package": package,
        "from_version": from_version,
        "to_version": to_version,
        "pin": pins,
        "facts": facts,
        "fetched_from": [
            "%s/%s" % (REGISTRY, package),
            str((before_manifest.get("dist") or {}).get("tarball") or ""),
            str((after_manifest.get("dist") or {}).get("tarball") or ""),
        ],
        "author_note": note,
    }
    # Budget trimming is disclosed. A class with dropped candidates is
    # INCONCLUSIVE on-chain; metadata remains available for other classes.
    if len(canonical(envelope).encode("utf-8")) > MAX_EVIDENCE:
        facts["files"]["listing_truncated"] = True
        for key in ("added", "removed", "changed_sources"):
            facts["files"][key] = facts["files"][key][:20]
        for row in facts["opaque_candidates"]:
            row["head"] = row["head"][:320]
            row["excerpt_truncated"] = True
        for row in facts["egress"]["candidates"]:
            if len(row["excerpt"]) > 480:
                row["excerpt"] = row["excerpt"][:480]
                facts["egress"]["complete"] = False
        while len(canonical(envelope).encode("utf-8")) > MAX_EVIDENCE and facts["opaque_candidates"]:
            facts["opaque_candidates"].pop()
            facts["opaque_coverage"]["complete"] = False
        while len(canonical(envelope).encode("utf-8")) > MAX_EVIDENCE and facts["egress"]["candidates"]:
            facts["egress"]["candidates"].pop()
            facts["egress"]["complete"] = False
        if len(canonical(envelope).encode("utf-8")) > MAX_EVIDENCE:
            raise Unpinnable("required metadata exceeds 12288-byte evidence budget")
    return envelope


# ---------------------------------------------------------------------------
# canonical form
# ---------------------------------------------------------------------------


def canonical(envelope: dict) -> str:
    trimmed = {}
    for key in TOP_KEYS:
        if key not in envelope:
            continue
        value = envelope[key]
        if key in ("fetched_from", "author_note") and not value:
            continue
        trimmed[key] = value
    return json.dumps(
        trimmed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def envelope_hash(envelope: dict) -> str:
    return hashlib.sha256(canonical(envelope).encode("utf-8")).hexdigest()


def flatten_for_dedup(envelope: dict) -> str:
    """Dedup normalisation. NOT what gets judged.

    Judging sees the facts byte for byte, because invisible characters in a file
    head are themselves the attack surface. Dedup sees this flattened form, so
    that resubmitting the same update with one extra space is not a new finding.
    """
    text = canonical(envelope)
    out = []
    for char in text:
        if ord(char) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
            continue
        out.append(" " if char.isspace() else char.lower())
    flat = "".join(out)
    while "  " in flat:
        flat = flat.replace("  ", " ")
    return flat.strip()


def dedup_key(envelope: dict) -> str:
    return hashlib.sha256(flatten_for_dedup(envelope).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package")
    parser.add_argument("from_version")
    parser.add_argument("to_version")
    parser.add_argument("--note", default="")
    parser.add_argument("--out", help="write the envelope here")
    arguments = parser.parse_args()

    try:
        envelope = build(
            arguments.package,
            arguments.from_version,
            arguments.to_version,
            arguments.note,
        )
    except Unpinnable as error:
        print("INCONCLUSIVE: " + str(error), file=sys.stderr)
        return 2

    envelope["envelope_hash"] = envelope_hash(envelope)
    envelope["dedup_key"] = dedup_key(envelope)
    text = json.dumps(envelope, indent=2, sort_keys=True, ensure_ascii=False)
    if arguments.out:
        with open(arguments.out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
        print(envelope["envelope_hash"])
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
