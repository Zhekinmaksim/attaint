#!/usr/bin/env python3
"""Recover the pin of an unpublished npm version from third-party lockfiles.

When a version is unpublished, npm stops serving the tarball and drops the
version manifest. What survives is every lockfile in the world that resolved
that version before the takedown: `package-lock.json` and `yarn.lock` both
record the resolved tarball URL together with its `integrity` hash.

The pin is therefore recoverable even though the artifact is not. This does not
recover the tarball — npm and the yarn mirror both return 404 — it recovers the
number that would verify one if a copy is found elsewhere.

Three rules, each learned from a wrong answer on the first run:

* **Vote by repository, not by file.** Two lockfiles in one repository are one
  opinion. The first run counted them as two and reported agreement that was
  not there.
* **Reject fixtures.** Paths under `fixtures/`, `samples/`, `__tests__/` and the
  like hold hand-written lockfiles. The first run recovered the literal string
  `sha512-demo` from one and ranked it top.
* **Validate the shape.** A sha512 subresource integrity value is `sha512-`
  followed by 88 base64 characters. Anything else is not a hash.

A recovered pin is evidence, not proof. It is reported with the number of
independent repositories behind it, and a pin backed by one repository is marked
WEAK rather than accepted.
"""

from __future__ import annotations

import base64
import collections
import json
import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN = pathlib.Path("/home/claude/.ghtoken").read_text().strip()
API = "https://api.github.com"

TARGETS = [
    ("event-stream", "3.3.6"),
    ("flatmap-stream", "0.1.1"),
    ("ua-parser-js", "0.7.29"),
    ("ua-parser-js", "0.8.0"),
    ("ua-parser-js", "1.0.0"),
    ("node-ipc", "10.1.1"),
    ("node-ipc", "9.2.2"),
    ("coa", "2.0.3"),
    ("rc", "1.2.9"),
]

PER_PAGE = 30

JUNK_PATH = re.compile(
    r"(^|/)(fixtures?|samples?|examples?|__tests__|testdata|mocks?|demo)(/|$)",
    re.IGNORECASE,
)

SHA512_SRI = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
SHA1_SRI = re.compile(r"^sha1-[A-Za-z0-9+/]{27}=$")


def valid_integrity(value) -> bool:
    if not isinstance(value, str):
        return False
    if not (SHA512_SRI.match(value) or SHA1_SRI.match(value)):
        return False
    try:
        base64.b64decode(value.split("-", 1)[1], validate=True)
    except Exception:
        return False
    return True


def api(url: str):
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Accept": "application/vnd.github+json",
            "User-Agent": "attaint-pin-recovery",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    for _ in range(5):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            if error.code in (403, 429):
                time.sleep(25)
                continue
            if error.code == 422:
                return {"items": []}
            raise
    return {"items": []}


def raw(repository: str, ref: str, path: str):
    url = "https://raw.githubusercontent.com/%s/%s/%s" % (
        repository,
        ref,
        urllib.parse.quote(path),
    )
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "User-Agent": "attaint-pin-recovery",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except Exception:
        return None


def search(package: str, version: str, filename: str) -> list:
    bare = package.split("/")[-1]
    needle = "%s/-/%s-%s.tgz" % (package, bare, version)
    query = '"%s" filename:%s' % (needle, filename)
    url = "%s/search/code?q=%s&per_page=%d" % (
        API,
        urllib.parse.quote(query),
        PER_PAGE,
    )
    time.sleep(7)
    return api(url).get("items") or []


def from_package_lock(blob: bytes, package: str, version: str):
    try:
        document = json.loads(blob)
    except Exception:
        return None
    marker = "%s/-/%s-%s.tgz" % (package, package.split("/")[-1], version)

    def walk(node):
        if isinstance(node, dict):
            resolved = node.get("resolved")
            if isinstance(resolved, str) and marker in resolved:
                if node.get("version") in (version, None):
                    candidate = node.get("integrity")
                    if valid_integrity(candidate):
                        yield candidate
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)

    for found in walk(document):
        return found
    return None


def from_yarn_lock(blob: bytes, package: str, version: str):
    """yarn.lock is not JSON. The resolved line and the integrity line sit in
    the same stanza, so read forward from the resolved line."""
    marker = "%s/-/%s-%s.tgz" % (package, package.split("/")[-1], version)
    text = blob.decode("utf-8", "replace")
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if marker not in line:
            continue
        for follow in lines[index : index + 6]:
            stripped = follow.strip()
            if stripped.startswith("integrity "):
                candidate = stripped.split(None, 1)[1].strip().strip('"')
                if valid_integrity(candidate):
                    return candidate
    return None


def collect(package: str, version: str) -> dict:
    by_repository = {}
    scanned = 0
    skipped_junk = 0

    for filename, parser in (
        ("package-lock.json", from_package_lock),
        ("yarn.lock", from_yarn_lock),
    ):
        for item in search(package, version, filename):
            repository = item["repository"]["full_name"]
            path = item["path"]
            if JUNK_PATH.search(path):
                skipped_junk += 1
                continue
            if repository in by_repository:
                continue
            ref = item["repository"].get("default_branch") or "HEAD"
            blob = raw(repository, ref, path) or raw(repository, "HEAD", path)
            if not blob:
                continue
            scanned += 1
            integrity = parser(blob, package, version)
            if integrity:
                by_repository[repository] = (integrity, path)

    votes = collections.Counter(value for value, _ in by_repository.values())
    if not votes:
        return {
            "recovered": False,
            "files_scanned": scanned,
            "fixtures_skipped": skipped_junk,
        }
    best, count = votes.most_common(1)[0]
    return {
        "recovered": True,
        "integrity": best,
        "independent_repositories": count,
        "distinct_values": len(votes),
        "confidence": "STRONG" if count >= 3 else ("WEAK" if count == 1 else "FAIR"),
        "sources": sorted(
            repository + "/" + path
            for repository, (value, path) in by_repository.items()
            if value == best
        ),
        "files_scanned": scanned,
        "fixtures_skipped": skipped_junk,
    }


def main() -> int:
    results = {}
    for package, version in TARGETS:
        key = "%s@%s" % (package, version)
        print("\n== " + key)
        record = collect(package, version)
        results[key] = record
        if not record["recovered"]:
            print(
                "   NO PIN  (%d files read, %d fixtures skipped)"
                % (record["files_scanned"], record["fixtures_skipped"])
            )
            continue
        print("   %s  %s" % (record["confidence"], record["integrity"]))
        print(
            "   %d independent repositories, %d distinct values, %d fixtures skipped"
            % (
                record["independent_repositories"],
                record["distinct_values"],
                record["fixtures_skipped"],
            )
        )
        for source in record["sources"][:4]:
            print("     - " + source)

    out = pathlib.Path(__file__).resolve().parents[1] / "corpus" / "recovered-pins.json"
    out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print("\nwrote " + str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
