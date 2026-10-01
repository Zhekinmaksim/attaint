# Verdict vocabulary: `attaint/1`

Attaint judges one npm update against a registered consumer policy. Candidate
extraction is deterministic; a candidate is a question for consensus, not a
risk verdict. Every question has the same polarity: `found=true` means a risk
introduced by this update, never an explanation or ordinary behaviour. A complete
empty candidate set means not found for that class within its extraction scope;
incomplete coverage is inconclusive. `CLEAN` is limited to the policy's blocking classes and the supplied
evidence. It does not certify the package or prove the absence of malicious code.

## Risk classes

| Class | Question | Ordinary or insufficient evidence |
|---|---|---|
| `LICENSE_SHIFT` | Does the new licence forbid required use? | Licences on the policy's allowed list are ordinary; moving outside that list is a risk. |
| `MAINTAINER_SHIFT` | Does the publisher change indicate an unexplained transfer of trust? | Adding an active maintainer is ordinary. A takeover with little change beyond dependency ranges may be a risk. Publishing history cannot be invented. |
| `INSTALL_HOOK` | Does new or changed install/build behaviour exceed build needs? | Unchanged `npm ls`/`npm test` and known bundlers are ordinary. New environment reads, network calls or external writes may be risks. An ambiguous new command without its script body is inconclusive. |
| `OPAQUE` | Does new unreadable content have an unexplained origin? | A minified bundle linked to evidenced sources/build inputs is ordinary. An encoded blob without a source/build explanation may be a risk. Missing origin evidence is inconclusive. |
| `EGRESS` | Does the update introduce an outbound network call that the package's stated purpose does not require? | A URL or network API call alone does not establish unjustified egress. |
| `DEP_ADDED` | Does a new dependency have an unexplained role in this release? | An unrelated package may be a risk; a known library serving the stated purpose is ordinary. No additions means not found. History cannot be invented. |

`EGRESS` and `DEP_ADDED` are included in the implementation. Policies choose a
nonempty subset of these six classes. Licence interpretation uses the policy's
allowed list; Attaint does not provide legal advice about licence obligations.

## Result states

`CLEAN` means no blocking class was confirmed, every required class was readable,
the evidence level met the policy, and enough class judgments completed.
`INCONCLUSIVE` means a required judgment could not be completed reliably. Missing,
contradictory, incomplete or malformed evidence is not a pass. A confirmed class
is a risk finding; `gate()` exposes it as `RISK` with the original class verdict
and locators. Initial locators are constrained to the class's evidence field,
a newly added dependency name, or an OPAQUE/EGRESS candidate path. Free-form
explanations, JSON fragments and unlisted identifiers are invalid.
Findings may remain visible even if unreadable classes make the
aggregate result `INCONCLUSIVE`.

## Evidence levels

| Level | Evidence | Supported classes |
|---|---|---|
| 1 | Builder downloaded both tarballs and checked their bytes against registry integrity. The envelope contains metadata and bounded extracted material. | All six, subject to the recorded coverage and sufficient context. |
| 2 | Recovered checksums and dependency graph, with explicit supporting sources. Tarball bytes are unavailable. | `MAINTAINER_SHIFT` and `DEP_ADDED`, only when the required metadata is present. |
| 3 | No usable pin. | None; always `INCONCLUSIVE`. |

A lockfile checksum does not establish publisher identity, nor does it recover
source bytes. Level 2 therefore does not automatically prove a takeover or catch
an incident. If a policy also blocks a class that requires tarball evidence,
that update remains `INCONCLUSIVE` at level 2.

The contract validates the envelope and its declared pin. For level 1 it also
fetches npm version manifests and compares identity, integrity and selected
metadata with the envelope. It does not independently download the tarballs or
authenticate the client's extracted file content. A hash commits to the submitted text; it cannot make fabricated text true. Reviewers can rebuild
an envelope from its source URLs and compare it with the stored evidence.

## Coverage and hostile evidence

File heads, candidate counts and excerpts are bounded to fit the contract prompt.
Static network patterns do not cover computed URLs, encoded payloads or arbitrary
runtime behaviour. The contract rejects a pass when EGRESS coverage is absent or
incomplete, or OPAQUE coverage explicitly reports incomplete extraction. The model
is also instructed to mark insufficient context, truncated excerpts, unsupported
publishing history or missing referenced script bodies as inconclusive. That
context assessment depends on consensus judgment. A complete empty static
candidate set establishes no candidate in that scope, not absence of every
whole-program risk.

The publisher controls much of the evidence. The prompt fences it and treats
embedded instructions or authority claims as data. Each class uses GenLayer's
comparative consensus primitive. Challenges quote the same stored evidence and
must pass two referee framings. These defences reduce particular attack surfaces;
they do not establish immunity to prompt injection.

## Evaluation

The historical mechanical baseline covers 45 release pairs and four candidate
classes. Its candidate hit rates are `OPAQUE` 44.4%, `MAINTAINER_SHIFT` 15.5%,
`INSTALL_HOOK` 2.2%, and `LICENSE_SHIFT` 0.0%; 57.8% of pairs hit at least one.
These are prefilter results, not consensus verdicts or measured false positives.

A consensus comparison must retain the same package/version pairs, publish the
policy and evidence hashes, and preserve risk, clean, inconclusive and transaction
failure counts. A run using all six classes differs in scope from the four-class
baseline and must say so. `event-stream 3.3.4 → 3.3.5` probes a historical
publisher handover; a risk verdict is not guaranteed. Report the actual final
network outcome, including a miss or an inconclusive result. A simulated risk
finding cannot be counted as a live detection.
