#!/usr/bin/env python3
"""Find committed copies of an unpublished npm version and cross-check them.

The pin recovered from lockfiles verifies a tarball, and no tarball survives.
The remaining route to the bytes is repositories that committed `node_modules`
while the bad version was installed.

That evidence is weaker by construction and is labelled as such. A committed
directory cannot be re-tarred byte for byte, so the recovered `integrity` cannot
validate it. What can be checked is agreement: if unrelated repositories hold
the same file with the same sha256, the content is what was published, whatever
the tarball hashed to.

Output records hashes, sizes and shape signals. Payload source is written to
disk for the corpus and never printed.
"""

from __future__ import annotations

import collections
import hashlib
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
    ("flatmap-stream", "0.1.1"),
    ("event-stream", "3.3.6"),
    ("node-ipc", "9.2.2"),
]

OUT = pathlib.Path(__file__).resolve().parents[1] / "corpus" / "recovered-sources"


def api(url: str):
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Accept": "application/vnd.github+json",
            "User-Agent": "attaint-source-recovery",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    for _ in range(4):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            if error.code in (403, 429):
                time.sleep(25)
                continue
            return {}
    return {}


def raw(repository: str, ref: str, path: str):
    url = "https://raw.githubusercontent.com/%s/%s/%s" % (
        repository,
        ref,
        urllib.parse.quote(path),
    )
    request = urllib.request.Request(
        url, headers={"Authorization": "Bearer " + TOKEN, "User-Agent": "attaint"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read()
    except Exception:
        return None


def find_manifests(package: str) -> list:
    query = 'path:node_modules/%s filename:package.json "%s"' % (package, package)
    url = "%s/search/code?q=%s&per_page=40" % (API, urllib.parse.quote(query))
    time.sleep(7)
    return api(url).get("items") or []


def opacity(blob: bytes) -> dict:
    lines = blob.split(b"\n")
    printable = sum(1 for byte in blob if 32 <= byte < 127 or byte in (9, 10, 13))
    return {
        "bytes": len(blob),
        "longest_line": max(len(line) for line in lines),
        "nonprintable_milli": int(round((1 - printable / len(blob)) * 1000)),
        "base64_runs": len(re.findall(rb"[A-Za-z0-9+/=]{160,}", blob)),
        "hex_escape_runs": len(re.findall(rb"(?:\\x[0-9a-fA-F]{2}){40,}", blob)),
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report = {}

    for package, wanted in TARGETS:
        key = "%s@%s" % (package, wanted)
        print("\n== " + key)
        hits = find_manifests(package)
        print("   committed node_modules copies found: %d" % len(hits))

        file_votes = collections.defaultdict(collections.Counter)
        saved = {}
        matching_repos = []

        for item in hits[:25]:
            repository = item["repository"]["full_name"]
            path = item["path"]
            ref = item["repository"].get("default_branch") or "HEAD"
            blob = raw(repository, ref, path) or raw(repository, "HEAD", path)
            if not blob:
                continue
            try:
                manifest = json.loads(blob)
            except Exception:
                continue
            if str(manifest.get("version")) != wanted:
                continue
            matching_repos.append(repository)
            base = path.rsplit("/", 1)[0]

            names = ["package.json"]
            main_file = manifest.get("main")
            if isinstance(main_file, str):
                names.append(main_file.lstrip("./"))
            names += ["index.js", "index.min.js", "dangerous.js"]

            for name in dict.fromkeys(names):
                data = raw(repository, ref, base + "/" + name)
                if not data:
                    continue
                digest = hashlib.sha256(data).hexdigest()
                file_votes[name][digest] += 1
                if digest not in saved:
                    saved[digest] = (name, data)

        if not matching_repos:
            print("   NO COPY at that exact version")
            report[key] = {"recovered": False, "copies": 0}
            continue

        print("   repositories holding version %s: %d" % (wanted, len(matching_repos)))
        files = {}
        for name, votes in sorted(file_votes.items()):
            digest, count = votes.most_common(1)[0]
            _, data = saved[digest]
            signals = opacity(data)
            files[name] = {
                "sha256": digest,
                "agreeing_repositories": count,
                "distinct_versions_seen": len(votes),
                "signals": signals,
            }
            target = OUT / ("%s-%s-%s" % (package, wanted, name.replace("/", "_")))
            target.write_bytes(data)
            print(
                "     %-16s sha256 %s  agree=%d  bytes=%d longest_line=%d b64=%d hex=%d"
                % (
                    name,
                    digest[:16],
                    count,
                    signals["bytes"],
                    signals["longest_line"],
                    signals["base64_runs"],
                    signals["hex_escape_runs"],
                )
            )
        report[key] = {
            "recovered": True,
            "copies": len(matching_repos),
            "repositories": sorted(set(matching_repos)),
            "files": files,
            "provenance": "committed node_modules, not tarball-verified",
        }

    out = OUT.parent / "recovered-sources.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("\nwrote " + str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
