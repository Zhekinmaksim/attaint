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


## Current links and verified status

Website: [attaint.vercel.app](https://attaint.vercel.app).
Repository: [Zhekinmaksim/attaint](https://github.com/Zhekinmaksim/attaint).
Contract: [`0x686C79234138FBF1734C8457c917acD9A6C3Fa7a`](https://explorer-bradbury.genlayer.com/contracts/0x686C79234138FBF1734C8457c917acD9A6C3Fa7a).
Policy: ID `0`, hash `ac1d48cb20fe3c5a9662afd24cf7a7353cfc1eb528fd82bd3dbebfcbf9705ce1`.
Deployed source SHA-256: `80aef33c040d44fe71ae528afd9946f9aec9c39655635d08edf03944e5cea9fa`.

The [first live attestation](https://explorer-bradbury.genlayer.com/transactions/0xe53abde17154cbf3cbb41ced701fa8a42e1c327beb1ded40e351b31ebe4cbe18)
is `FINALIZED` (confirmed 1 October 2026 at 13:59 UTC). Its current gate for
`event-stream 3.3.4 → 3.3.5` is `CLEAN`, with registry metadata `VERIFIED`, six
class judgments, no findings and no inconclusive classes. A fresh finalized-state
CLI check returned exit `0`; the local proof is `runs/first-attestation-gate.json`
and the release bindings are in `runs/deployment.json`.

The production browser read verified `CLEAN`, registry metadata `VERIFIED` and
six judgments; the manual transaction-hash check verified `FINALIZED`.
The [GitHub Actions run](https://github.com/Zhekinmaksim/attaint/actions/runs/36879515907)
passed offline tests and the live gate for attestation `0` on commit
`c27f67f9af8ae74034630cbaef8d839b57c09e9f`. The CI record is
`runs/ci-verification.json`.

Two read-only GenVM validator replays passed with a simulated leader verdict
`RISK / MAINTAINER_SHIFT` at `publisher`. The live transaction performed fresh
judgments and returned `CLEAN` for the same pinned envelope and policy parameters.
A diagnostic replay is not network consensus. Do not advertise that simulated
risk finding as a live detection; the finalized live result missed the historical
handover risk. At the verified checkpoint, 19/45 original corpus pairs had finalized
gates: 13 `CLEAN`, six `INCONCLUSIVE`, zero `RISK`. Express index 13 ended
`FINALIZED / NO_MAJORITY` without a committed attestation. Its original hash and
no-commit proof are preserved. After automatic approval review rejected
resubmission, the user explicitly approved exactly one fresh Express request;
the sole writer is executing that guarded retry. The scheduler resumes with
`--queue-paced --reschedule-undetermined 13 --defer-pair 21`. Yargs index 21 has
a provisional `UNDETERMINED` transaction under read-only diagnosis; no retry or
recovery is authorized for it. This grants no authorization for further Express
retries. The counts above remain a verified checkpoint; a 44-pair run is incomplete.
The full 45-pair comparison and measured consensus metrics remain pending;
no full-sample percentages or improvement are claimed. See the README for
queue pacing, resume behavior and the guarded operator-authorized retry.

The prior contract
[`0x74407aE5e92002F4F0E1A912C7e785837a67F3C8`](https://explorer-bradbury.genlayer.com/contracts/0x74407aE5e92002F4F0E1A912C7e785837a67F3C8)
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
