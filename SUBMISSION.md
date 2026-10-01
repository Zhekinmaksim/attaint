# GenLayer Project submission copy

Use the verification notes and live links only after the corresponding confirmed
artifacts exist. Pending deployment, receipts or corpus coverage are release
limitations and must remain visible in the application.

## Project name

Attaint

## One-line description

A consensus CI gate for npm dependency updates: pinned evidence, immutable consumer policies, and contestable risk judgments on GenLayer.

## Project description

Attaint judges one npm version update against an immutable consumer policy.
GenLayer consensus evaluates six risk classes: incompatible licence changes,
unexplained transfers of publisher trust, new or changed install behaviour beyond build needs,
new opaque content of unexplained origin, unjustified outbound calls and new
dependencies with an unexplained role. A client
checks tarball integrity and builds bounded evidence; the contract independently
checks npm metadata and stores the result. Bonded challenges must cite the same
stored evidence. The CLI returns 0 for clean, 1 for risk and 2 for inconclusive.
Positive findings mean introduced risk; ordinary explanations do not count.
Missing required evidence fails closed. The frontend submits a real attestation
and reads the finalized gate. Results cover selected classes and supplied
excerpts; they do not certify whole-package safety. A saved 45-pair mechanical
baseline supports a separate receipt-backed consensus comparison.

## How-to steps

1. Open the hosted application. Confirm the displayed Bradbury contract and
   policy match the published deployment artifacts.
2. Select the pinned `event-stream 3.3.4 → 3.3.5` envelope, or build and inspect an
   envelope with `python3 cli/envelope.py PACKAGE FROM TO --out envelope.json`.
3. Connect a Bradbury wallet and submit the attestation. Follow the actual pending,
   accepted and finalized transaction states. A failed transaction is not a verdict.
4. Read the confirmed attestation and current gate. Inspect its policy hash,
   update identity, evidence hash, findings, evidence level and provenance.
5. Run the README's CLI gate command against that same attestation and envelope.
   Compare the printed state with the application; verify its exit code.

## Expected verification outcome

The app sends an actual Bradbury request_attestation transaction and reads gate()
for the confirmed attestation. Package, versions, envelope hash, policy ID and hash
match the submitted evidence. CI exits 0/1/2 according to the current clean/risk/
inconclusive state. Unconfirmed transactions and incomplete evidence cannot pass.
Report the actual verdict; a risk classification for the historical case is not
guaranteed by this verification path.

## Supporting evidence to attach

- [Public repository](https://github.com/Zhekinmaksim/attaint) and
  [source archive](https://attaint.vercel.app/source.zip), containing the readable
  contract, generated artifact, pinned minifier/ABI verifier, tests and setup docs.
- Hosted website with the working contract interface.
- Exact Bradbury contract explorer URL.
- Deployment, policy registration and first attestation receipts, plus current
  gate output matching the immutable policy and envelope.
- Consensus report with the same 45 baseline pairs, confirmed receipt references,
  failures and inconclusive results. State partial coverage if the run is incomplete.
- Optional video showing the submission, finalization and CI result.

The historical 57.8% rate is a mechanical candidate baseline. Do not label it a
consensus block rate or claim a measured improvement without the completed results.
The baseline covers four candidate classes and the consensus policy covers six.
The final report's `comparison_scope` preserves this distinction; rate differences
do not establish accuracy or reduced false positives without ground truth.


## Current links and verified status

Website: [attaint.vercel.app](https://attaint.vercel.app).
Repository: [Zhekinmaksim/attaint](https://github.com/Zhekinmaksim/attaint).
Contract: [`0x686C79234138FBF1734C8457c917acD9A6C3Fa7a`](https://explorer-bradbury.genlayer.com/address/0x686C79234138FBF1734C8457c917acD9A6C3Fa7a).
Policy: ID `0`, hash `ac1d48cb20fe3c5a9662afd24cf7a7353cfc1eb528fd82bd3dbebfcbf9705ce1`.
Deployed source SHA-256: `80aef33c040d44fe71ae528afd9946f9aec9c39655635d08edf03944e5cea9fa`.

The [first live attestation](https://explorer-bradbury.genlayer.com/tx/0xe53abde17154cbf3cbb41ced701fa8a42e1c327beb1ded40e351b31ebe4cbe18)
is `FINALIZED` (confirmed 1 October 2026 at 13:59 UTC). Its current gate for
`event-stream 3.3.4 → 3.3.5` is `CLEAN`, with registry metadata `VERIFIED`, six
class judgments, no findings and no inconclusive classes. A fresh finalized-state
CLI check returned exit `0`; the local proof is `runs/first-attestation-gate.json`
and the release bindings are in `runs/deployment.json`.

The production browser read verified `CLEAN`, registry metadata `VERIFIED` and
six judgments; the manual transaction-hash check verified `FINALIZED`.
Manual success requires consensus result 1, finalized last-round result 1,
matching transaction/contract identity and a `request_attestation` method.
The [GitHub Actions run](https://github.com/Zhekinmaksim/attaint/actions/runs/36879515907)
passed offline tests and the live gate for attestation `0` on commit
`c27f67f9af8ae74034630cbaef8d839b57c09e9f`. The CI record is
`runs/ci-verification.json`.

Two read-only GenVM validator replays passed with a simulated leader verdict
`RISK / MAINTAINER_SHIFT` at `publisher`. The live transaction performed fresh
judgments and returned `CLEAN` for the same pinned envelope and policy parameters.
A diagnostic replay is not network consensus. Do not advertise that simulated
risk finding as a live detection; the finalized live result missed the historical
handover risk. At the verified checkpoint (`observed_at: 2026-10-01T16:39:00Z`),
21/45 original corpus pairs had finalized gates: 14 `CLEAN`, seven `INCONCLUSIVE`,
zero `RISK`. Express index 13 ended
`FINALIZED / NO_MAJORITY` without a committed attestation. Its original hash and
no-commit proof are preserved. The user explicitly approved exactly one fresh Express request.
Its [replacement transaction](https://explorer-bradbury.genlayer.com/tx/0xc4a6b8a7f1488230da97ea26550985eb73585bc3ca8e8fee330ad58081e9084c)
was submitted and projected as `CANCELED` at this checkpoint. Yargs index 21 ended
`FINALIZED / MajorityDisagree` (result 2), without a committed attestation in
either state view. The sanitized proof is
`runs/diagnostics/yargs-finalized-no-commit.json`. The user explicitly approved
exactly one fresh Yargs request with the same policy and envelope. Its
[replacement](https://explorer-bradbury.genlayer.com/tx/0xc496de7de05cdb11dbce0c4fd606e2dc9d0b1c287c51fe3ce8e71dcf5a83b48f)
was projected as `CANCELED` at this checkpoint. Both approvals have been used. One retry
each for indices 23 and 24 is separately approved. Those requests and original
index 44 have now been submitted with six-hour V6 deadlines, preserving all other
submission arguments:
[23](https://explorer-bradbury.genlayer.com/tx/0x64b675b6497880018d26281ed90614e69fc21f13adae86accb0018c853a0ce3d),
[24](https://explorer-bradbury.genlayer.com/tx/0xe0d87e4fa0ce20e486572c0330a9c86a1d6951c6f2405cedab22493ace1017ae),
[44](https://explorer-bradbury.genlayer.com/tx/0xfd481df56855efb35eb64cf903f42f2a5c2a9f1878941d063f4f9bcea5ff0491).
The subsequent queue read showed six pending entries. These submissions are not
finalized gates. Original audits are
preserved; no further retries of indices 13 or 21 are authorized.
The counts above remain a verified
checkpoint, not a live total.
The full 45-pair comparison and measured consensus metrics remain pending;
no full-sample percentages or improvement are claimed. See the README for
queue pacing, resume behavior and the guarded operator-authorized retry.

Canceled or expired observations and a `ValidatorSelectionFailed` minimal-metadata
fallback are not verdicts. The fallback cannot prove successful execution or
produce an accepted gate. The historical audit at block `0x16333bd`
(1 October 2026, 16:43:19 UTC) confirmed 15 raw `PENDING` entries past
`validUntil`, projected as `CANCELED` but still occupying the pending queue.
They had no matching committed attestations in either state view. The public
proof is `runs/diagnostics/expired-queue-no-commit.json`. Cleanup completed at
16:56 UTC: eight successful EVM cancellation calls removed the 15 expired slots,
reducing pending entries from 18 to 3, with fees of 0.00136827391252365 test GEN.
It stopped at the outside-list Yargs replacement, leaving indices 21, 42 and 43
untouched. The public
[cleanup summary](https://attaint.vercel.app/diagnostics/expired-cleanup-summary.json)
preserves the receipts. This authorized no new retries and supplied no consensus
verdicts; the 21/45 gate checkpoint is unchanged.

The historical
[post-cleanup no-commit audit](https://attaint.vercel.app/diagnostics/post-cleanup-unfinished-no-commit.json)
identified 18 raw canceled releases without matching attestations (index 13 and
25–41). A separate fresh-request batch is being prepared for explicit approval;
none of these 18 requests is approved or submitted. Existing active hashes remain
preserved, and the historical audit must be rechecked before any signature.

The prior contract
[`0x74407aE5e92002F4F0E1A912C7e785837a67F3C8`](https://explorer-bradbury.genlayer.com/address/0x74407aE5e92002F4F0E1A912C7e785837a67F3C8)
is failed-attempt evidence. Its deployment and policy finalized, but the smoke
transaction ended `UNDETERMINED` after validator disagreement at `INSTALL_HOOK`.
It produced no accepted attestation. The diagnostic was `nondet_disagree`; a
stale SDK label of `DETERMINISTIC_VIOLATION` is not proof of a replay fault.
The [failed-attempt history](https://attaint.vercel.app/attempt-history.json)
publishes the contract and transaction identities with archived statuses. Do not attach
this attempt as proof of a successful current-release workflow.

[Readable contract](https://attaint.vercel.app/attaint.py),
[Bradbury artifact](https://attaint.vercel.app/attaint.bradbury.py),
[project documentation](https://attaint.vercel.app/README.md), and the
[source archive](https://attaint.vercel.app/source.zip) are published. Check their
revision against the archive's SHA-256 manifest; source publication is separate
from a successful chain release. Source repository: [Zhekinmaksim/attaint](https://github.com/Zhekinmaksim/attaint).
Use the Vercel URL; `attaint.xyz` routing will be configured by the user and has
not been verified.
