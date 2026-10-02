# Attaint

A GenLayer consensus gate for npm dependency updates. It judges one package moving
from version A to version B under an immutable consumer policy, then exposes a
CI decision: `CLEAN` → 0, `RISK` → 1, `INCONCLUSIVE` → 2.

Hosted application: [attaint.vercel.app](https://attaint.vercel.app).
The public application now uses a separate Bradbury instance with the same
reviewed contract code and immutable policy as the benchmark. Deployment, policy
and attestation 0 are finalized. A fresh verified read for `event-stream
3.3.4 → 3.3.5` returned `RISK / MAINTAINER_SHIFT`, and the CLI exited 1.
The earlier benchmark returned `CLEAN` for this same envelope; both outcomes
are preserved. See the release status for exact identities and limits.

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

## Verify the published example

Open [the live gate](https://attaint.vercel.app/#live) without a wallet. The page
reads attestation 0 from Bradbury and verifies its consensus receipt. For a new
update, upload the builder's envelope or expand **Or paste an envelope**, paste
the JSON and click **Load pasted envelope**. Inspect the selected package,
versions and evidence before requesting a wallet signature. To check
the published record from a terminal:

```sh
git clone https://github.com/Zhekinmaksim/attaint.git
cd attaint
npm ci
python3 cli/attaint_gate.py \
  --contract 0xbC94Fc0015574e85226DAaAdD2fC2CB8b2FbF42A \
  --policy 0 \
  --policy-hash ac1d48cb20fe3c5a9662afd24cf7a7353cfc1eb528fd82bd3dbebfcbf9705ce1 \
  --attestation 0 \
  --envelope corpus/event-stream-3.3.4-3.3.5.json --json
```

The process exit is the gate decision: 0 permits, 1 blocks a risk, and 2 blocks
an inconclusive result. A nonzero exit is intentional when the update is blocked.
The live result may change after a successful on-chain challenge.

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
  --envelope corpus/event-stream-3.3.4-3.3.5.json --json
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

Read-only verification requires Node.js 20+ and `npm ci` for the lockfile-pinned
SDK dependencies. It does not require a wallet or a global GenLayer CLI. The
runner can also import dependencies from an installed GenLayer CLI. Writes use an
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
node scripts/live.mjs deploy --file contracts/attaint.bradbury.py --out deployment.json --submission-ttl 21600 --wait --timeout 21600
node scripts/live.mjs write --address "$ATTAINT_CONTRACT" \
  --method register_policy --args-file policy-args.json \
  --out policy-receipt.json --submission-ttl 21600 --wait --timeout 21600
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
Pass arguments through `--args-file`, a file containing a JSON array. The runner
rejects unknown options, duplicate flags, missing values and positional arguments
before credentials or network access. `--args` is not supported.

Bradbury's observed finality window is about 30 minutes after acceptance; this is
not a completion guarantee. Keep the transaction hash and check that same request
while it is pending or accepted. After reopening the page, enter that same hash
and click **Check transaction**. Once it is finalized, the app verifies the
receipt's envelope and sender and finds the matching attestation without a wallet.
A six-hour submission deadline gives a request time in the queue; it does not
shorten finality or permit automatic resubmission.

Repeat the exact saved 45-pair control sample only on a dedicated benchmark
instance. The public application instance must not share the batch's growing
history. The existing benchmark address is
`0x686C79234138FBF1734C8457c917acD9A6C3Fa7a`; its current read limitation must be
resolved before resuming that run:

```sh
python3 probes/scan.py --consensus \
  --contract "$ATTAINT_BENCHMARK_CONTRACT" --policy "$ATTAINT_POLICY_ID" \
  --policy-hash "$ATTAINT_POLICY_HASH" \
  --out runs/consensus-report.json --account "$GENLAYER_ACCOUNT" \
  --queue-paced --finalize-release --timeout 21600 --submission-ttl 21600
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
For failed finalized generations, `--reschedule-finalized` takes a separate
immutable manifest pinning the exact old hash and expected result 2 or 5.
It requires RAW 7, both complete gate views, and a durable archived proof before
releasing a journal. It cannot reuse an older generation's allowance.
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
| `scripts/read_capacity.mjs` | Current-block accepted-history gas check before admitting a new public request. |
| `probes/scan.py` | Corpus scan and consensus comparison. |
| `probes/recover_pins.py` | Recover unpublished-version checksum records. |
| `probes/recover_sources.py` | Document attempts to recover source bytes. |
| `test/run_tests.py` | Offline state-machine and accounting tests. |
| `web/index.html` | Public page and contract interface. |
| `corpus/` | Baseline results and evidence artifacts. |

## Release status

### Public application instance

The public instance is
[`0xbC94Fc0015574e85226DAaAdD2fC2CB8b2FbF42A`](https://explorer-bradbury.genlayer.com/address/0xbC94Fc0015574e85226DAaAdD2fC2CB8b2FbF42A)
on Bradbury, chain ID 4221. Its deployed source SHA-256 is
`80aef33c040d44fe71ae528afd9946f9aec9c39655635d08edf03944e5cea9fa`
(20,100 UTF-8 bytes). Policy `0` has hash
`ac1d48cb20fe3c5a9662afd24cf7a7353cfc1eb528fd82bd3dbebfcbf9705ce1`.
These match the benchmark's code and policy parameters; attestations and balances
belong to each contract separately.

- [Public deployment](https://explorer-bradbury.genlayer.com/tx/0x6f1263222ab164243bdbc4cf5d023341ea211d72f658a1543da95d6e2d548df8): finalized; accepted-round trace verified.
- [Public policy registration](https://explorer-bradbury.genlayer.com/tx/0x82fd7f2d5742e7a9872a1e13357975c3702c1e5c4ffc7c07d15e2e3c0e01ca0a): finalized; immutable policy independently read back.
- [Public first attestation](https://explorer-bradbury.genlayer.com/tx/0x83f2ed64e1615d58ff39fdfee7b55958b4ec281ae1fec88f9c4d20c30297e3e2): finalized; attestation 0 reads `RISK / MAINTAINER_SHIFT` at `publisher`.

On 2 October 2026 at 06:36 UTC, the CLI independently verified the live source,
policy, update identity, requester and envelope, and exited `1`. The result has
registry metadata `VERIFIED`, six class judgments and one finding,
`MAINTAINER_SHIFT@publisher`. This is a risk block, not a transport failure.
The same envelope and policy previously returned `CLEAN` on the benchmark
instance. The different outcomes show judgment variability, not repeatable
detection accuracy; neither attempt has been discarded.

The benchmark's accumulated accepted history made the public node's current-state
lookup fail. A direct EVM read of all 30 accepted records reverted with a gas
limit of 16,777,216 and succeeded with 95,000,000. The same read estimated
26,776,380 gas. Another instance with three accepted records estimated 2,990,683
and remained readable. This identifies a history-read capacity problem; moving
the public workflow to a fresh instance does not repair the node or establish
unbounded scalability.

The public pre-sign capacity check resolves ConsensusData through the official
AddressManager and estimates the full accepted-history read at one current block.
It refuses a request above 8,000,000 gas, above 100 accepted records, or when the
check fails. The 8-million threshold is conservative application headroom below
the observed failing limit, not a network guarantee. The check does not replace
live code, policy or gate verification and does not predict every future result's
storage cost. Once capacity is exhausted, new requests must remain disabled until
an explicitly reviewed deployment or infrastructure change restores the path.

Finalized views independently check the entire bounded accepted history before
and after each node read. Every transaction must be finalized with agreement;
the ordered history and canonical block must remain unchanged. An unconfirmed
earlier transaction blocks the read even when the newest one is finalized.
A wallet send without an acknowledged hash remains unresolved; inspect wallet
activity and resume that hash before another request.


The [2 October live CI run](https://github.com/Zhekinmaksim/attaint/actions/runs/36974756604)
verified the public-instance gate and exited 1 for `RISK / MAINTAINER_SHIFT`.
Its live-gate job is red because it correctly blocks this update; the offline
job passed. This is the intended CI outcome, not an RPC error. The result and
job identities are recorded in `runs/ci-verification.json`.

### Historical benchmark instance

On 1 October 2026 at 13:59 UTC, the benchmark contract, policy registration and
first live attestation reached `FINALIZED`. The gate read at that checkpoint for
`event-stream 3.3.4 → 3.3.5` is `CLEAN`: registry metadata `VERIFIED`, six class
judgments, no findings and no inconclusive classes. A fresh read of finalized
state passed the CLI's code, policy, envelope and requester checks with exit `0`.
The local proof is in `runs/benchmark-release/deployment.json`, the three transaction journals and
`runs/benchmark-release/first-attestation-gate.json`.

The then-published Vercel application was verified in a real browser: its Bradbury
read returned `CLEAN`, registry metadata `VERIFIED` and six judgments, and its
manual transaction-hash check returned `FINALIZED`.
Manual success also requires consensus result `AGREE` (1), the finalized last
round's result 1, a matching transaction/contract identity and a
`request_attestation` method. Finalized failure decisions are not successful
attestations.
The [GitHub Actions run](https://github.com/Zhekinmaksim/attaint/actions/runs/36879515907)
passed both the offline tests and the live gate for attestation `0`, on commit
`c27f67f9af8ae74034630cbaef8d839b57c09e9f`; the live gate exited `0`.
The record is in `runs/benchmark-release/ci-verification.json`.

- Network: Bradbury, chain ID 4221.
- Benchmark contract: [`0x686C79234138FBF1734C8457c917acD9A6C3Fa7a`](https://explorer-bradbury.genlayer.com/address/0x686C79234138FBF1734C8457c917acD9A6C3Fa7a).
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

At the 2 October 2026 checkpoint, the saved report contains 22/45 finalized
corpus gates: 14 `CLEAN`, eight `INCONCLUSIVE` and zero `RISK`. Index 24 is now
finalized. Indices 42 and 43 have successful finalized receipts and accepted-round
traces identifying attestations 23 and 24, but remain `INCONCLUSIVE_READBACK`:
the public node's current-state lookup fails for this benchmark's accumulated
accepted history. The separate public instance does not resolve these rows.
These two traces alone do not certify the current gate. The
[readback audit](https://attaint.vercel.app/diagnostics/finalized-42-43-readback-audit.json)
records that distinction. No replacement of either successful request is planned.

Indices 21, 23 and 44 finalized without agreement (results 5, 2 and 5). Eighteen
other requests, index 13 and indices 25–41, were canceled without committed gates
at the saved audit. The operator has requested completion of the remaining run.
The bounded recovery uses the existing 18-entry canceled manifest and a separate
[three-entry finalized-failure manifest](https://attaint.vercel.app/diagnostics/finalized-retry-21-23-44-manifest.json).
Each exact failed hash permits one replacement only after a fresh raw terminal
status, matching calldata/requester and complete audits of both state views prove
there is no committed update. An existing signing intent consumes its allowance.
The benchmark's current-state read failure blocks these checks, so no new replacement has been sent in this
recovery session. Failed attempts and their original hashes remain preserved.

The full 45-pair comparison remains incomplete. No full-sample consensus rates,
improvement or accuracy claim is published. Saved gates are historical verified
observations; a network read failure cannot become a passing CI result.

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
that cleanup itself did not change the then-current 21/45 gate checkpoint.

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

The pre-sign simulation issue was resolved by passing the tested gas cap.
Both replacements now have successful finalized receipts; their gate readback
remains subject to the current RPC limitation described above.

The historical
[post-cleanup no-commit audit](https://attaint.vercel.app/diagnostics/post-cleanup-unfinished-no-commit.json)
covers the 18 canceled releases. It must be rechecked against current state before
any replacement signature; it cannot stand in for a fresh audit.

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
