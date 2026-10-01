# Attaint

A GenLayer consensus gate for npm dependency updates. It judges one package moving
from version A to version B under an immutable consumer policy, then exposes a
CI decision: `CLEAN` → 0, `RISK` → 1, `INCONCLUSIVE` → 2.

Hosted application: [attaint.vercel.app](https://attaint.vercel.app).
The corrected contract has a `FINALIZED` attestation and a live CLI exit code `0`.
The current gate is `CLEAN`, while the earlier diagnostic returned `RISK`. Read
the release status before using either result as CI evidence.

The six judgment classes are licence incompatibility (`LICENSE_SHIFT`), unexplained
transfer of publisher trust (`MAINTAINER_SHIFT`), new or changed install behaviour
beyond build needs (`INSTALL_HOOK`), new unreadable content of unexplained origin
(`OPAQUE`), unjustified outbound calls (`EGRESS`), and new dependencies with an
unexplained role (`DEP_ADDED`). A deterministic builder collects
candidates. GenLayer consensus decides whether they establish a blocked class.
Every positive finding means newly introduced risk. Explained opaque content or
a dependency serving an evidenced purpose is ordinary. A complete empty candidate
set means no finding within that extraction scope; incomplete coverage or missing
context remains inconclusive. Initial findings use a constrained locator: the
class's evidence field, an added dependency name, or an evidenced candidate path.
Arbitrary explanations and JSON fragments cannot serve as locators.

The publisher controls much of the evidence. The contract fences that material,
uses comparative consensus for each class, and accepts bonded challenges against
the same stored evidence. A successful challenge changes the recorded verdict and
returns the challenger's bond as a withdrawable credit.

## What a result establishes

A result applies to the policy's selected classes and the supplied evidence. It
is not a certificate that an entire package is safe. The builder checks downloaded
tarball bytes against registry integrity, but extracts bounded excerpts. Static
network candidates can miss encoded or computed calls. Explicitly incomplete
EGRESS or OPAQUE coverage blocks a pass. For other context gaps, the consensus
judge is instructed to return `INCONCLUSIVE`; this depends on its judgment.

| Level | Evidence | Judgment scope |
|---|---|---|
| 1 | Both tarballs downloaded and byte integrity checked by the builder. | All six classes, subject to sufficient context and coverage. |
| 2 | Recovered checksums and dependency graph, with supporting sources. | `MAINTAINER_SHIFT` and `DEP_ADDED`, only with the required metadata. |
| 3 | No usable pin. | Always `INCONCLUSIVE`. |

A recovered checksum cannot recover bytes or establish publisher history. At level
1 the contract independently fetches npm version manifests to compare
identity, declared integrity, licence, publisher, hooks and dependency changes.
It does not fetch the tarball or authenticate client-built file excerpts. A hash
commits to submitted text; it cannot make fabricated excerpts true. Rebuild
envelopes from the public sources to verify the extracted evidence. Read
[`spec/classes.md`](spec/classes.md) for the class questions and
[`spec/attaint-spec.md`](spec/attaint-spec.md) for the ABI and trust boundaries.

## Historical baseline

The original mechanical scan used 45 release pairs from 15 popular npm packages.
It hit at least one of four candidate classes on 57.8% of those pairs:
`OPAQUE` 44.4%, `MAINTAINER_SHIFT` 15.5%, `INSTALL_HOOK` 2.2%, and
`LICENSE_SHIFT` 0.0%. These are candidate hit rates, not consensus verdicts or
measured false positives. Raw results are in [`FINDINGS.md`](FINDINGS.md) and
[`corpus/scan-report.json`](corpus/scan-report.json).

Most historical malicious versions in the incident corpus are no longer served
by npm. Recovered lockfile checksums and graph data are in
[`corpus/recovered-pins.json`](corpus/recovered-pins.json); recovery limitations
are in [`corpus/RECOVERY.md`](corpus/RECOVERY.md). The loss of source bytes is
reported as missing evidence, never converted into a clean result.

A consensus comparison must reuse those same 45 package/version pairs and report
its policy, receipts, failures and inconclusive rows. A six-class policy has a
different scope from the four-class baseline. No consensus improvement is claimed
until the actual run is complete. The final report's `comparison_scope` records
these class counts, the same 45 pinned pairs and that inconclusive results block
CI. Its rate differences describe these two policies; without ground truth they
do not measure accuracy or a reduction in false positives.

## Build evidence and run checks

The envelope builder and offline tests use Python 3.10+ and the standard library.

```sh
python3 cli/envelope.py event-stream 3.3.4 3.3.5 --out corpus/event-stream-live.json
python3 test/run_tests.py
```

The builder writes no new envelope and exits 2 if fetching or byte verification
fails. The offline scripted stub exercises state, validation and accounting. It
does not simulate validator consensus or prove Bradbury compatibility. Run the
contract tests after every contract edit.

With a confirmed attestation, read the live gate in CI:

```sh
python3 cli/attaint_gate.py \
  --contract "$ATTAINT_CONTRACT" \
  --policy "$ATTAINT_POLICY_ID" \
  --policy-hash "$ATTAINT_POLICY_HASH" \
  --attestation "$ATTAINT_ATTESTATION_ID" \
  --envelope corpus/event-stream-live.json --json
```

This command must verify the expected policy and update, not accept an unrelated
clean attestation. Network errors, pending transactions, invalid responses and
identity mismatches exit 2. A challenge may change an earlier gate result; CI
reads current contract state.

## Live transaction runner

The Bradbury source artifact is generated from `contracts/attaint.py` by
`scripts/compile_contract.py`. The pinned `python-minifier` version removes
comments/docstrings and shortens internal names and whitespace to fit the RPC
transaction gas cap. Public method and argument names, storage fields, annotations
and prompt strings are preserved. The compiler checks the public ABI; run the
full offline suite against both forms. Deploy `contracts/attaint.bradbury.py`,
keeping the readable source for review.

The SDK runner requires Node.js and an installed GenLayer CLI. Run `npm ci` to
install the lockfile-pinned SDK dependencies. It imports the GenLayer SDK from
local dependencies or the CLI installation. Writes use an
unlocked CLI account from the system keychain; `--account` selects one. The
`GENLAYER_PRIVATE_KEY` environment variable is an alternative. Never publish
credentials in source or output artifacts.

```sh
npm ci
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/compile_contract.py
python3 test/run_tests.py
ATTAINT_CONTRACT_PATH=contracts/attaint.bradbury.py python3 test/run_tests.py
node scripts/live.mjs deploy --file contracts/attaint.bradbury.py --out deployment.json --wait
node scripts/live.mjs write --address "$ATTAINT_CONTRACT" \
  --method register_policy --args-file policy-args.json \
  --out policy-receipt.json --wait
```

The proposed six-class policy uses this `policy-args.json` JSON argument array:

```json
["mit,apache-2.0,isc,bsd-2-clause,bsd-3-clause", "DEP_ADDED,EGRESS,INSTALL_HOOK,LICENSE_SHIFT,MAINTAINER_SHIFT,OPAQUE", 6, 1, 1000000000000000]
```

Registering a different policy creates a new immutable ID. `min_rounds` counts
class judgments completed by the contract; it is not a count of validator votes.
A threshold above the number of readable blocking classes produces an inconclusive
result. This policy requires all six class judgments, evidence level 1,
and a minimum challenge bond of 1,000,000,000,000,000 wei. This example registration attaches no value and starts with a pool of 0.

Use `write` for `request_attestation`, `read` for `gate`, and `settle` to wait for
a transaction by hash. Submit the canonical envelope body as the `evidence`
argument. Its package, versions, hash and evidence level must match the request.
Keep confirmed receipts with the run artifacts and verify the resulting state.
Reusing a journal resumes its transaction instead of broadcasting a duplicate.

Repeat the exact saved 45-pair control sample through live consensus:

```sh
python3 probes/scan.py --consensus \
  --contract "$ATTAINT_CONTRACT" --policy "$ATTAINT_POLICY_ID" \
  --policy-hash "$ATTAINT_POLICY_HASH" \
  --out runs/consensus-report.json --account "$GENLAYER_ACCOUNT" \
  --queue-paced --finalize-release --timeout 3600
```

Resume with the same command and output path. The saved mechanical baseline
remains separate from confirmed consensus outcomes. Count both `RISK` and
`INCONCLUSIVE` as CI blocks; a reduction in risk findings alone is not a reduction
in blocked updates. The report's sibling
`consensus-report-runs/` directory holds per-pair envelopes and transaction
journals. The CLI checks deployed code against the generated Bradbury artifact
when present; `--code-hash` pins an explicitly reviewed alternative.
`--expected-requester` can additionally pin the attestation requester.

The paced scheduler reads the authoritative pending queue before each new write
and keeps two places free; the current queue limit is 20. It settles eligible
initial-release transactions first. One process lock protects the entire scan,
and a separate canonical lock serializes local signed writes. Existing accepted
transaction hashes are resumed and reread, never automatically resubmitted.

`--defer-pair INDEX` uses a zero-based corpus index, preserves its journal and
failed hash, and leaves it `RETRY_APPROVAL_PENDING` while the other pairs proceed.
Each approved retry is limited to one fresh request for its exact pair. Once
submitted, resume its saved hash; reusing a retry flag cannot authorize another
replacement. Pairs 13 and 21 have already used their approved requests.
The approved requests for indices 23 and 24 have also been submitted. The sole
writer has submitted the one approved replacement each for indices 42 and 43,
using `--reschedule-canceled runs/diagnostics/canceled-retry-42-43-manifest.json`.
This immutable manifest pins each old hash and envelope, the policy, code and
requester. Each fresh write requires raw `CANCELED` state outside the pending
queue and complete final/current gate audits showing no committed identity.
A signed replacement consumes that one-request allowance even if it fails.
The new submissions use a six-hour submission deadline
(`--submission-ttl 21600`) for new writes. The runner changes only the V6
`validUntil` argument, simulates the exact calldata before estimation and signing,
preserving the first five arguments, and saves the deadline with the journal.
A longer deadline does not restore any
expired transaction or authorize another request.
A 44-pair run remains `completed: false`, exits `2`, and publishes no full-sample
comparison percentages. `--reschedule-undetermined INDEX` authorizes a fresh
paid request and requires explicit operator approval. It proceeds only after a
live `FINALIZED / NO_MAJORITY` receipt (result 5) and a complete latest-nonfinal
attestation audit prove that this requester/update/policy identity never committed.
The original journal, hash and proof remain archived. An unresolved transaction
or a matching committed attestation cannot use this retry path.
`--reschedule-disagree INDEX` applies the same fresh no-commit checks to an
explicitly approved `FINALIZED / MajorityDisagree` result (2). Neither flag
grants authorization for further retries after its one approved request.

## Repository

| Path | Purpose |
|---|---|
| `contracts/attaint.py` | Readable Intelligent Contract source. |
| `contracts/attaint.bradbury.py` | Generated Bradbury deployment artifact. |
| `scripts/compile_contract.py` | Minify with a pinned dependency and verify the public ABI. |
| `cli/envelope.py` | Checksum verification and bounded evidence extraction. |
| `cli/attaint_gate.py` | Live CI gate with exit codes 0, 1 and 2. |
| `scripts/live.mjs` | SDK deployment, write, read and transaction settlement. |
| `probes/scan.py` | Corpus scan and consensus comparison. |
| `probes/recover_pins.py` | Recover unpublished-version checksum records. |
| `probes/recover_sources.py` | Document attempts to recover source bytes. |
| `test/run_tests.py` | Offline state-machine and accounting tests. |
| `web/index.html` | Public page and contract interface. |
| `corpus/` | Baseline results and evidence artifacts. |

## Release status

As of 1 October 2026 at 13:59 UTC, the corrected contract, policy registration and
first live attestation have reached `FINALIZED`. The current gate for
`event-stream 3.3.4 → 3.3.5` is `CLEAN`: registry metadata `VERIFIED`, six class
judgments, no findings and no inconclusive classes. A fresh read of finalized
state passed the CLI's code, policy, envelope and requester checks with exit `0`.
The local proof is in `runs/deployment.json`, the three transaction journals and
`runs/first-attestation-gate.json`.

The published Vercel application was verified in a real browser: its Bradbury
read returned `CLEAN`, registry metadata `VERIFIED` and six judgments, and its
manual transaction-hash check returned `FINALIZED`.
Manual success also requires consensus result `AGREE` (1), the finalized last
round's result 1, a matching transaction/contract identity and a
`request_attestation` method. Finalized failure decisions are not successful
attestations.
The [GitHub Actions run](https://github.com/Zhekinmaksim/attaint/actions/runs/36879515907)
passed both the offline tests and the live gate for attestation `0`, on commit
`c27f67f9af8ae74034630cbaef8d839b57c09e9f`; the live gate exited `0`.
The record is in `runs/ci-verification.json`.

- Network: Bradbury, chain ID 4221.
- Contract: [`0x686C79234138FBF1734C8457c917acD9A6C3Fa7a`](https://explorer-bradbury.genlayer.com/address/0x686C79234138FBF1734C8457c917acD9A6C3Fa7a).
- Deployed source SHA-256: `80aef33c040d44fe71ae528afd9946f9aec9c39655635d08edf03944e5cea9fa` (20,100 UTF-8 bytes), verified against the fetched contract code.
- Immutable policy ID: `0`; hash: `ac1d48cb20fe3c5a9662afd24cf7a7353cfc1eb528fd82bd3dbebfcbf9705ce1`.
- Attestation ID: `0`; envelope SHA-256: `49e222e812104fc865421eb55f886bc378a60c87889b125dc73fc2a08e529042`.
- [Deployment transaction](https://explorer-bradbury.genlayer.com/tx/0x6b0c6281bc6f4ac7103290238ee2cae89fa5a3de10c54e16f4de7c5400929b68).
- [Policy transaction](https://explorer-bradbury.genlayer.com/tx/0x0eba23ed228cb6d0803a4d17efe671d9f0bdcbd21aa1bbd1cedf4e526e3f2549).
- [First live attestation transaction](https://explorer-bradbury.genlayer.com/tx/0xe53abde17154cbf3cbb41ced701fa8a42e1c327beb1ded40e351b31ebe4cbe18).

The earlier [read-only GenVM diagnostic](https://attaint.vercel.app/diagnostics/locator-enum-simulation/report.json)
returned `RISK / MAINTAINER_SHIFT` at `publisher`, and two validator replays
reported no disagreement. It used the same pinned envelope and policy parameters
in a diagnostic wrapper. The live transaction ran fresh nondeterministic
judgments and returned `CLEAN`. Agreement with a recorded simulation trace does
not force the network to reproduce that classification. The finalized live run did
not confirm the publisher handover as a risk; do not count the simulated result
as a live detection. The finalized clean outcome is a miss for this historical
handover case. Offline tests and simulations establish different things
from a receipt-backed consensus judgment.

At the verified checkpoint (`observed_at: 2026-10-01T16:39:00Z`), 21 of the
original 45 corpus pairs had finalized gates: 14 `CLEAN`, seven `INCONCLUSIVE`
and zero `RISK`. The Express pair at index 13
(`5.2.1 → 4.22.1`) ended `FINALIZED / NO_MAJORITY`, with no matching committed
attestation; its original journal and hash are archived. The user explicitly
approved exactly one fresh Express request. Its
[replacement](https://explorer-bradbury.genlayer.com/tx/0xc4a6b8a7f1488230da97ea26550985eb73585bc3ca8e8fee330ad58081e9084c)
was projected as `CANCELED` at this checkpoint. The no-commit audit is
`runs/diagnostics/express-finalized-no-commit.json`. Yargs index 21
(`17.7.3 → 18.1.0`) ended `FINALIZED / MajorityDisagree` (result 2). Both state
views contained 22 attestations and no matching Yargs identity; the sanitized
audit is `runs/diagnostics/yargs-finalized-no-commit.json`. The user explicitly
approved exactly one fresh Yargs request with the same policy and envelope.
Its [replacement](https://explorer-bradbury.genlayer.com/tx/0xc496de7de05cdb11dbce0c4fd606e2dc9d0b1c287c51fe3ce8e71dcf5a83b48f)
subsequently reached `FINALIZED / NO_MAJORITY` (result 5), without a committed
attestation. Its one-request approval is used; no third request is authorized.
Both original failed-finalization audits remain preserved. The user has
separately approved one retry each for indices 23 and 24. These retries and
original index 44 have now been submitted with `--submission-ttl 21600`:

- [Index 23](https://explorer-bradbury.genlayer.com/tx/0x64b675b6497880018d26281ed90614e69fc21f13adae86accb0018c853a0ce3d).
- [Index 24](https://explorer-bradbury.genlayer.com/tx/0xe0d87e4fa0ce20e486572c0330a9c86a1d6951c6f2405cedab22493ace1017ae).
- [Index 44](https://explorer-bradbury.genlayer.com/tx/0xfd481df56855efb35eb64cf903f42f2a5c2a9f1878941d063f4f9bcea5ff0491).

The subsequent queue read showed six pending entries. Submission does not count
as a finalized gate. Index 23's replacement has reached `FINALIZED`, result 2,
without a committed attestation. The public
[finalized-retry audit](https://attaint.vercel.app/diagnostics/finalized-retries-no-commit.json)
checks failed replacements 21 and 23 against both complete state views, each
with a stable count of 23. Those counts do not prove finality of other requests.
No further retries of indices 13, 21 or 23 are authorized. Index 24 is
`ACCEPTED`, result 1, awaiting normal finalization eligibility at 18:57:20 UTC;
it is not yet counted as a finalized gate. Numeric status 14 was confirmed from
the official SDK as nonterminal `LEADER_REVEALING` and added to the observer and
browser decoder. Index 44 has since reached `UNDETERMINED / NO_MAJORITY`
(result 5), with normal finalization eligibility at 19:05:33 UTC. Indices 42 and
43 project `CANCELED` while their raw records remain unexpired `PENDING` (1)
followers. Their hashes are retained and no replacement is authorized.
The counts above are a verified checkpoint, not an updated live total. This is partial progress;
the full 45-pair comparison and measured risk/block-rate differences remain
pending, with no full-sample percentages or improvement claimed.

An expired or canceled observation, `READ_ERROR`, or a
`ValidatorSelectionFailed` metadata fallback is not a verdict. If the full
receipt read fails with that exact error, the observer may use the official
minimal view only to report a matching transaction in `CANCELED` state; it marks
execution unavailable, the receipt partial and finalization capability absent.
This cannot certify acceptance, a finalized gate, or permission to resubmit.
When a matching raw read confirms an expired `PENDING` entry, the observer reports
`EXPIRED_PENDING_CLEANUP`, with no finalization capability or verdict.
The browser requires raw status 8 before treating projected cancellation as
materialized and clears the previous gate during a new pending request. A
projected cancellation cannot create a fresh-request authorization or leave an
old clean result displayed as the new request's result.
The historical queue audit at block `0x16333bd` (1 October 2026, 16:43:19 UTC)
confirmed 15 exact entries whose raw transaction-manager state remained
`PENDING` (1), while the projected status was `CANCELED` (8) because block time
had passed `validUntil`. These expired raw entries still occupied the pending
queue. The audit covers indices 28–39, the already-used replacement at index 13,
and indices 40–41, with no matching committed attestations in either state view.
The sanitized proof is `runs/diagnostics/expired-queue-no-commit.json`.
The approved cleanup completed at 16:56 UTC: eight successful EVM cancellation
calls removed those 15 expired slots and reduced pending entries from 18 to 3.
Actual fees totalled 0.00136827391252365 test GEN. It stopped at the Yargs
replacement at index 21, outside the fixed list, leaving indices 21, 42 and 43
untouched. The receipt-backed
[cleanup summary](https://attaint.vercel.app/diagnostics/expired-cleanup-summary.json)
is also saved as `runs/diagnostics/expired-cleanup-summary.json`.
This cleanup authorized no new retries and produced no consensus verdicts;
the 21/45 gate checkpoint remains unchanged.

A separate, explicitly approved index-43 cleanup completed at 17:50 UTC. Its
[successful EVM transaction](https://explorer-bradbury.genlayer.com/tx/0x32c575376e9d74f9f1387a0a2e65e0f06ecd4ecd28218942bffeb8e65691f9cd)
reduced pending entries from 4 to 3, costing 0.0003009118063437 test GEN against
a 0.00075 test GEN cap. The public
[index-43 summary](https://attaint.vercel.app/diagnostics/expired-cleanup-43-summary.json)
records zero attestation requests. The one approved replacement each for indices
42 and 43 has now been submitted with a 21,600-second deadline; both allowances
are used:

- [Index 42 consensus transaction](https://explorer-bradbury.genlayer.com/tx/0x2d3c7a7ee860fa8e7a3a22c51c3a35441f254923113470690f67c983c4eeda9a), EVM hash `0xae2fbc16b2b64544f09ba7307ee297d04789f69cff078ed0754db6bff5fc7e7d`.
- [Index 43 consensus transaction](https://explorer-bradbury.genlayer.com/tx/0xaf98606b962d010e2b7c25c5da31f09ce1df987ef78bb5581bc5b44b971aaf5f), EVM hash `0x1a0301a8ba0cb223f1d18006f19541291ed4ae2d15982b786ca4a62be9bb84c7`.

The earlier pre-sign RPC error was resolved by passing the tested gas cap in the
simulation. These are submitted requests, not finalized gates. The 18-entry
batch remains unapproved, and the 21/45 gate checkpoint is unchanged.

The historical
[post-cleanup no-commit audit](https://attaint.vercel.app/diagnostics/post-cleanup-unfinished-no-commit.json)
identified 18 raw canceled releases without matching attestations: index 13 and
indices 25–41. A separate batch of fresh requests is being prepared for explicit
authorization; none of those 18 requests is approved or submitted. Existing
active hashes are preserved. Audit conclusions must be rechecked against current
state before any signature.

The previous attempt at
[`0x74407aE5e92002F4F0E1A912C7e785837a67F3C8`](https://explorer-bradbury.genlayer.com/address/0x74407aE5e92002F4F0E1A912C7e785837a67F3C8)
had finalized deployment and policy registration. An earlier registry-API
attempt failed closed before any class judgments; its corpus submissions are
excluded from the final measurement. The question-polarity attempt's smoke transaction
[`0x73a16013b755850a3c399b8955ca4564f22f29a996cea7bac769ebcf0a5ce393`](https://explorer-bradbury.genlayer.com/tx/0x73a16013b755850a3c399b8955ca4564f22f29a996cea7bac769ebcf0a5ce393)
ended `UNDETERMINED`, producing no accepted attestation. Validator simulations
reproduced `nondet_disagree` at `INSTALL_HOOK`: the leader and validator disagreed
on whether the answer was inconclusive. The SDK incorrectly labelled numeric vote
4 as `DETERMINISTIC_VIOLATION`; that stale label does not establish a deterministic
replay fault. The questions also needed corrected risk
polarity for `OPAQUE`/`DEP_ADDED` and clearer install behaviour scope. These
findings are summarized in the public
[failed-attempt history](https://attaint.vercel.app/attempt-history.json).
That contract is failed-attempt evidence, not the current release.

The application and CLI continue to fail closed for unconfirmed transactions,
incomplete evidence or mismatched current gate state. The consensus
report must retain failures and inconclusive rows; no improvement is claimed
before a completed confirmed run.

Published source paths: [readable contract](https://attaint.vercel.app/attaint.py),
[Bradbury artifact](https://attaint.vercel.app/attaint.bradbury.py),
[evidence builder](https://attaint.vercel.app/envelope.py),
[CLI gate](https://attaint.vercel.app/attaint_gate.py),
[class vocabulary](https://attaint.vercel.app/spec/classes.md), and
[specification](https://attaint.vercel.app/spec/attaint-spec.md).
The [complete source archive](https://attaint.vercel.app/source.zip) is published
with a SHA-256 manifest. Check the manifest/release status for its revision; a
published source artifact alone does not establish a successful deployment.
Source repository: [Zhekinmaksim/attaint](https://github.com/Zhekinmaksim/attaint). `attaint.xyz` will be configured
by the user; its live routing has not been verified.
