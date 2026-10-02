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
is `FINALIZED` (confirmed 1 October 2026 at 13:59 UTC). Its verified gate on 1 October 2026 for
`event-stream 3.3.4 → 3.3.5` is `CLEAN`, with registry metadata `VERIFIED`, six
class judgments, no findings and no inconclusive classes. The finalized-state
CLI check at that checkpoint returned exit `0`; the local proof is `runs/first-attestation-gate.json`
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
handover risk. At the 2 October 2026 checkpoint, the saved report contains 22/45 finalized
corpus gates: 14 `CLEAN`, eight `INCONCLUSIVE` and zero `RISK`. Index 24 is now
finalized. Indices 42 and 43 have successful finalized receipts and accepted-round
traces identifying attestations 23 and 24, but remain `INCONCLUSIVE_READBACK`:
the Bradbury RPC currently fails to return contract code and current state.
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
The RPC outage blocks these checks, so no new replacement has been sent in this
recovery session. Failed attempts and their original hashes remain preserved.

The full 45-pair comparison remains incomplete. No full-sample consensus rates,
improvement or accuracy claim is published. Saved gates are historical verified
observations; a network read failure cannot become a passing CI result.

Canceled or expired observations and a `ValidatorSelectionFailed` minimal-metadata
fallback are not verdicts. The fallback cannot prove successful execution or
produce an accepted gate. The browser checks raw status 8 before treating a
projected cancellation as materialized and clears old gate results during a new
pending request. The historical audit at block `0x16333bd`
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

A separate approved index-43 cleanup completed at 17:50 UTC, reducing the queue
from 4 to 3. Its successful
[transaction](https://explorer-bradbury.genlayer.com/tx/0x32c575376e9d74f9f1387a0a2e65e0f06ecd4ecd28218942bffeb8e65691f9cd)
cost 0.0003009118063437 test GEN within a 0.00075 cap; the public
[summary](https://attaint.vercel.app/diagnostics/expired-cleanup-43-summary.json)
records no attestation requests. The one approved replacement each for indices
42 and 43 has now been submitted with six-hour deadlines:
[42](https://explorer-bradbury.genlayer.com/tx/0x2d3c7a7ee860fa8e7a3a22c51c3a35441f254923113470690f67c983c4eeda9a),
[43](https://explorer-bradbury.genlayer.com/tx/0xaf98606b962d010e2b7c25c5da31f09ce1df987ef78bb5581bc5b44b971aaf5f).
Both allowances are used. Their successful finalized receipts are preserved;
current gate reads remain blocked by the RPC failure described above.
