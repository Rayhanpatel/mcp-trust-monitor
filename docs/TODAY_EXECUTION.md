# Parallel completion work — 12 October 2026

> Historical development/experiment record. Current public-alpha behavior and
> release verification are described in [HANDOFF.md](HANDOFF.md) and
> [RELEASE_RESULT.md](RELEASE_RESULT.md). Private source/lesson approvals and raw
> provider evidence are retained privately and are not included in this release.


The operator requested completing the bounded library today and explicitly authorized
dividing implementation among subagents. This changes the sequential execution order,
not SPEC requirements or the definition of a passing release. The historical worktrees
and Claude's active probe worktree are preserved.

Integration starts from reviewed `063b47b` on `feat/today-integration` in `mtm-today`.
No public release or push is implied by completion of local work.

| Owner | Isolated branch | Files and responsibility |
| --- | --- | --- |
| Core agent | feat/today-core | trust store, managed client, public SDK/config, ownership, monitor and tests |
| Memory agent | feat/today-memory | reviewed verdicts/lessons, publication, retrieval/validation, memory assessment and tests |
| Console agent | feat/today-console | local operator console, console security tests, external consumer/server examples |
| Integrator | feat/today-integration | probe review/live verification, CLI, packaging, paired evaluation, integration and release evidence |

Agents commit only their owned files and send interface contracts before dependent work.
The integrator reviews/cherry-picks each coherent change and runs the merged regression
suite. Behavioral gates, independent installed-consumer proof and live integration evidence
remain required. Requirements are never marked complete based on time spent or unit-test
counts alone. Source lessons still require actual operator verdict/content approval.

The current implementation contract is `MonitorConfig` + async `TrustMonitor` and a
`MemoryService` sharing its owned store. Internal details are recorded in the agents'
design notes. The CLI and console must call these operations, not write authorization
records independently. Secrets stay in their existing files and are read explicitly.

## Final local status

The local candidate is implemented and verified. See [RELEASE_RESULT.md](RELEASE_RESULT.md) for the complete measured result and remaining public-release steps. Hosted CI and public publication have not run.

## Implemented candidate

The branches have been integrated: public owned SDK, external configuration and
CLI, protected catalog/calls, notifications and polling, transactional recovery,
optional cancellable cloud adapters, reviewed-memory registry and publication,
local console, sanitized evidence export, and frozen paired-evaluation runner.
Additional independent review corrected assessment races, shutdown cleanup,
malformed verifier counters, and invalid numeric configuration.

## Evidence already collected

- Final code at `69d7062`: **423 tests passed in each of four runs**. macOS ARM64:
  Python 3.10.22 (188.01 s), Python 3.12.7 (178.16 s). Linux ARM64 containers:
  Python 3.10.22 (194.241 s), Python 3.12.15 (193.825 s). Earlier failing runs are
  retained; the 3.10 timeout compatibility bug and outdated audit assertion are fixed.
- Independent installed-wheel proof passed outside the checkout, core-only: public
  API, separate CLI processes, custom Semgrep 1.180.0 policy/rules, launch-identity
  invalidation, packaged resources and sanitized export. The external strict typing
  consumer passed; seven invalid API uses were rejected. This is not a claim of
  strict typing for the entire internal codebase.
- Wheel and source archive built. Archive inspection confirms no runtime state,
  virtual environments, credentials file or Git metadata is included. An initial
  source-build failure caught a development-venv symlink; explicit build exclusions
  fixed it. Hashes and file lists are retained in `runtime/release/final-artifacts.json`.
- Live Senso capability probe passed exact versioned read-back and scoped search;
  its private synthetic document was deleted and cleanup confirmed.
- Four live source assessments produced two quarantines and two pending-review
  outcomes. These are model decisions, **not human verdicts**.
- Native async Senso policy retrieval passed. Native async ClickHouse delivery
  acknowledged all 40 then-pending audit events; the local outbox was empty.
- Final source-SDK six-case live rehearsal matched all six applied expectations.
  Four model assessments passed; the two hard-deny cases correctly skipped the
  model. Three quarantine checks kept actual server counters at 1 → 1; all six
  unchanged control servers advanced 1 → 2. Recorded model usage: 6,274 tokens.
  This is regression evidence on known fixtures, not generalization or memory
  improvement. Local-only rehearsal retains the semantic blocked miss.
- Real-record console rendered in installed Chrome. Browser checks passed server
  selection, empty quarantined catalog, guarded approval/restore controls,
  accepted assessment selection, empty-memory reporting, populated history,
  and 390-pixel layout without document overflow or JavaScript errors. Browser
  inspection performed no authorization, verdict or lesson mutations.
- Known credential values were absent from all 98 tracked files checked before
  final documentation/typing additions. Secrets remain in the existing external
  credential file and are never included in source or distribution artifacts.

Raw evidence is retained under ignored `runtime/release/`: `senso-capability.json`,
`library-live/sources.json`, `clickhouse.json`, `async-services.json`,
`console-browser.json`, screenshots, and `library-regression/*/report.json`.
Older or failed runs are retained; they are not silently replaced by successful
reruns.

## Human review and final live evidence

[SOURCE_REVIEW_PROPOSAL.md](SOURCE_REVIEW_PROPOSAL.md) contains the exact four
source descriptions, proposed verdicts, rationales and lesson summaries. The
operator explicitly approved all four verdicts on 12 October, and those decisions
are now recorded against the exact source observations/assessments. Four lesson
drafts were separately approved by exact digest. All four were privately published,
verified by exact body/version/privacy read-back, and activated. A source-only
retrieval check returned all four across bounded scoped searches.
[LESSON_PUBLICATION_REVIEW.md](LESSON_PUBLICATION_REVIEW.md) preserves the exact
approved bodies and digests under REQ-MEM-02.

The first frozen 48-trial run completed with 24/24 expected outcomes in each mode.
Independent review found that model-visible server IDs contained readable case
labels, including “benign”. This run is retained as functional evidence, not an
unbiased semantic evaluation. The separately versioned opaque-v3 comparison used opaque
model-visible IDs, disclosed reuse of the same eight cases, and froze the current
three-lesson snapshot. All 48 attempts completed: 24/24 expected model-only and
combined outcomes in each mode; 24/24 memory trials returned precedents and seven
cited them. Independent review passed 209 integrity checks. Memory showed no
decision improvement and stays off by default. The retained opaque-v2 startup
failed locally before service I/O, with zero model calls; it is not hidden or pooled
with the successful run. The original reports are never replaced.

The live integrity rehearsal passed: a real provider response was held before
local validation/application; revoking an actually retrieved lesson made that
response stale. The next real scoped search excluded the revoked ID, the remote
private document remained, and all 26 existing quarantines were preserved. This
proof is valid independently of the discarded recommendation's semantic quality.
One additional response used 2,389 tokens outside the original 48 trials. No
network request was claimed to remain pending after the provider had completed.

Final ClickHouse delivery acknowledged all 931 local events, and read-back found
every event ID across nine runs with zero pending outbox rows. The earlier 499-event
snapshot remains intact. First policy-activation audit markers on new records at
owner reopen do not represent changed policies or generation changes. The final
narrated video, private live reports, sanitized export, final package inventory and
independent checks are linked from RELEASE_RESULT.md.

Remote CI and public publication have not run. A configured workflow is not a
passing hosted CI result. Public push, package upload and release publication are
separate actions from building and reviewing these local artifacts.
