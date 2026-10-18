# MCP Trust Monitor: library release plan

> Historical development/experiment record. Current public-alpha behavior and
> release verification are described in [HANDOFF.md](HANDOFF.md) and
> [RELEASE_RESULT.md](RELEASE_RESULT.md). Private source/lesson approvals and raw
> provider evidence are retained privately and are not included in this release.


Updated 10 October 2026. [SPEC.md](SPEC.md) defines behavior; this document sequences the work. The goal is a usable, distributable Python library with monitored enforcement, reviewed Senso precedents and one local operator screen. A weekend is a target, not permission to skip release gates.

## Starting point

**12 October execution update:** the operator explicitly requested completing the
bounded library today with parallel agents. The old L1-only sequencing below is
historical; the current work is integrated on `feat/today-integration` in
`mtm-today`. [RELEASE_RESULT.md](RELEASE_RESULT.md) records final local acceptance and
remaining public-release steps; [TODAY_EXECUTION.md](TODAY_EXECUTION.md) preserves
the execution history. Parallel implementation does not waive human lesson review,
the frozen paired evaluation, or the release acceptance requirements.

Use `0c13bfc`, the public hackathon baseline. Its implementation is the approved M3 code at `67cd30c`; later commits corrected documentation. M1 enforcement, M2 detection/history and M3 assessment are implemented. The previous M4 monitoring and M5 interface were never built; their scope is superseded by L2 and L5 below. Historical tests and live measurements are in [HANDOFF.md](HANDOFF.md) and [EVIDENCE.md](EVIDENCE.md), not new validation of this release.

The specification worktree was a local `mcp-trust-monitor-next` checkout, branch `docs/library-release-spec`. Preserve the existing development worktrees, `hackathon-submission` tag and `mtm-record` recording copy. Use one implementation writer in this worktree after spec review; start a feature branch from the reviewed documentation commit. Do not resume the older M2 WIP branch.

## Milestones and review gates

Each code milestone ends with appropriate behavior tests, the full regression suite, an updated handoff, a commit and independent review. Stop before the next milestone. Documentation-only milestones use document checks and do not need runtime tests or paid service calls. Never merge or publish merely because a time box expires. Coverage denotes milestone responsibility, not premature completion of the whole requirement: L1 implements on-demand per-session freshness and explicit refresh-and-call alongside state/revision/identity checks; L2 adds automatic polling, notification invalidation and the complete in-flight lifecycle. L1 is an intermediate candidate, not the finished release.

| Stage | Deliverable and acceptance evidence | Requirement coverage |
| --- | --- | --- |
| L0: specification | Reconcile baseline versus target, interfaces, boundaries and acceptance plan. This documentation update completes the spec draft; independent review remains a gate. The frozen evaluation manifests are still to be written before L3. | All requirements scoped; REQ-EVAL-03 design |
| L1: library foundation | Typed public API, external stdio configuration, optional adapters, generic CLI, launch-bound trust and approved catalog. Implement on-demand session freshness, explicit refresh-and-call, no automatic tool replay, exclusive ownership, durable store-fault recovery and version-safe migrations. Validate custom policy/rules bindings. Build wheel/sdist and pass the installed API and separate-process CLI proofs plus L1 fault tests below. | REQ-LIB-01–05, REQ-REV-01–05, REQ-ENF-01–04, REQ-ENF-06–08, REQ-TRU-01–07 (notification portion in L2), REQ-DEC-06; preserve REQ-DEC-01–05, REQ-SRC-01 and REQ-AUD-01 |
| L2: reliable monitor | Notifications plus polling, per-session dirty epochs, bounded review queue, explicit policy reload, whole-result context staleness, background audit delivery and in-flight reporting. Real stdio tests cover two independent stdio subprocess sessions under one owner, notification during tools/list and during a tool call, unaffected servers, outage/restart and bounded shutdown. Delayed assessment and an in-flight tool response must not prevent invalidation/quarantine from committing. Complete the Senso capability gate below before L3 design. | REQ-MON-01–03, REQ-TRU-03, REQ-TRU-07, REQ-ENF-02, REQ-ENF-04–08, REQ-DEC-04, REQ-AUD-01–03 |
| L3: reviewed memory | After the capability gate and frozen evaluation manifests, add explicit verdicts, preview/review, immutable local lesson versions, eligibility registry, private Senso publication/read-back, retrieval and revocation. Support inactive indeterminate uploads and explicit reconciliation. Real Senso proof uses approved synthetic cases. Test upload ambiguity, tampering, poisoned text, empty results, outage, policy/verdict changes and revocation during publication/assessment. | REQ-MEM-01–05, REQ-EVAL-03, REQ-DEC-03–06, REQ-SRC-01, REQ-TRU-06, REQ-AUD-01, REQ-AUD-03 |
| L4: honest evaluation | Preserve six original regressions. Use at least eight held-out cases (four benign, four intended model-only violations), at least four families and three interleaved pairs per case: at least 48 scheduled trials. Keep failures and actual detector outcomes; distinguish cases from repeats. Export sources/configuration/snapshot, model-only versus combined outcomes, latency and usage. No required improvement claim; investigate semantic regressions. Enforcement and memory-integrity failures block release. | REQ-EVAL-01–05 |
| L5: local review screen | One loopback screen using the owning SDK instance and real records. Show catalog/state, diff, policy/precedent sources, verdict/lesson lifecycle and audit/verification levels. Test revision/generation-bound actions, local token, Host/origin checks, CSRF protection and escaped untrusted text. Synthetic fixture controls stay explicitly labeled and isolated. | REQ-UI-01–02, REQ-TRU-02, REQ-AUD-02–03 |
| L6: release candidate | Build final wheel/sdist; independently install and reproduce public API/CLI examples; run CI, compatibility and migration checks; choose license/distribution identity; document supported environments, failure modes and limits. Rehearse monitor → verdict → lesson → different-case retrieval → revocation plus separate M2/M3 demonstrations. Capture video after behavior is stable. Publish only reviewed artifacts through the intended release workflow. | REQ-LIB-02, REQ-LIB-04, REQ-EVAL-05; all SPEC completion gates |

## X1: bounded reviewed-memory experiment (separate track)

Approved 12 October 2026. X1 is an additive experiment that runs before L1 in its own review batches. It asks two questions with real evidence: can Senso hold verified, revocable precedents, and do operator-reviewed precedents change model-only decisions on held-out cases? It does not complete L3 or L4, does not implement L1 ownership, migration or packaging, and does not change the library target or the L1–L6 order. The approved plan and requirement map are in [HANDOFF.md](HANDOFF.md).

- **Branches.** Decisions are recorded on `docs/library-release-spec`. Implementation is on `exp/reviewed-memory`, branched from the decision commit, with one writer in this worktree.
- **Scope.** The Senso capability gate below; frozen lesson-source and held-out cases; explicit human verdicts; approved immutable lessons; a local eligibility registry; separate policy and precedent citations; verified private publication; retrieval; local revocation; stale-result rejection; a paired policy-only versus memory evaluation; and a correction to evaluation reporting.
- **Excluded.** Generated rules, automatic approval, speed or cost claims, remote lesson deletion, ClickHouse delivery of memory events and any public API.
- **Isolation.** Synthetic state lives in a directory the experiment creates fresh. One serial owner holds each directory. A storage failure aborts the run and blocks reuse until explicit experiment recovery or a fresh run. These controls are experiment-scoped and do not satisfy REQ-LIB-04 or REQ-ENF-07.
- **Graduation.** Independently reviewed fixes and reusable modules may graduate into the library through their own reviewed commits, cherry-picked or reimplemented, with library tests. X1 state directories, databases and CLI commands are unsupported and disposable; the library never promises to open or migrate them. X1 does not change `SCHEMA_VERSION`.
- **Gate timing.** X1 runs the Senso capability gate before L1. The evidence is dated, and L3 must re-accept it against the then-current API.
- **Held-out reuse.** X1 consumes its held-out set. L4 uses a fresh held-out version or discloses the reuse (REQ-EVAL-03).
- **Publication and remote writes.** No public repository, package or content publication. Planned remote writes are limited to private, synthetic Senso knowledge-base uploads: one capability-probe document and the approved X1 lessons. No ClickHouse writes are planned. No push, merge, tag or release.
- **Credentials.** X1 never writes shared credential files. Live steps run only after explicit approval and read an explicitly named credential file read-only.
- **Review batches.** Each batch stops for independent review.
  1. Decision record, evaluation-evidence fixes and frozen cases.
  2. Probe code; then credential approval; then the live probe and gate.
  3. Isolation and seams; registry, verdicts and lessons; publication; retrieval and stale rejection.
  4. Paired runner, then the live run.

## Public contract to settle in L1

Keep the existing enforcement engine. Extract a small facade and adapters rather than rewriting it or inventing a general plug-in framework. Decide exact exported names/signatures and record them before dependent work begins.

| Operation group | Required consumer-facing behavior |
| --- | --- |
| Configuration and lifecycle | Typed server launch profile and secret references; explicit policy/state paths, adapter modes and resource ownership; async lifecycle; no import-time I/O or automatic environment loading |
| Discovery and calls | Observe a configured server; inspect raw data through an operator API; obtain an immutable approved catalog with a complete selection token; call through the gate with an optional complete catalog selection token; explicit observe_and_call / CLI call --refresh for new or stale sessions |
| Trust and review | Status; revision-bound approve/restore; quarantine; review once; reload active policy atomically; inspect current versus stale results and typed failures |
| Monitoring | Run/stop bounded observation/review/delivery; expose health and invalidation events without coupling consumers to private store tables |
| Learning and evidence | Record an explicit verdict; preview/approve/publish/revoke a lesson; inspect actual retrieved context; export sanitized decision records. Add these operations in L3 behind the settled API conventions. |

The first installable core must work without Senso, OpenAI, ClickHouse or Semgrep credentials/dependencies. Adapter extras must not collide with the MCP environment. Preserve the existing OpenAI provider, exact evidence validation and hard-deny precedence; changing models is not an L1 task.

Launch-profile normalization, secret-reference representation, ownership and durable fault-marker behavior, resource paths, typed errors, session freshness defaults, migration compatibility, policy/rules binding and compatibility matrix are mandatory L1 design decisions, not defaults left to each UI or integration. Review any API change that affects authorization semantics before proceeding.

## L1 acceptance: first implementation chat

Settle exact API/configuration names in a short L1 design note, then implement this slice. The behavior below is already decided; the design note must not reopen it silently.

1. **Independent consumers.** Build wheel/sdist. Install the wheel into a clean environment outside all worktrees, with no editable install or PYTHONPATH workaround. A separate configurable stdio sample with a non-demo server ID proves observe → explicit approve → protected catalog → successful call → observed change → blocked call through the public async API.
2. **Separate CLI processes.** In successive clean processes, run generic observe, approve and call --refresh successfully. Plain call reports session_refresh_required. Pending/quarantined or mismatched identity/policy/token fails the composite before any server launch. Refresh discovering changed/invalid metadata dispatches no tool request. Document the deliberate new flag requirement; do not claim unchanged CLI behavior.
3. **Session isolation.** Two independent stdio subprocess sessions under one owner share a logical profile: refreshing A cannot freshen expired B. A new transport requires its own observation. Invalid observations still block all sessions through shared trust. Notification-driven invalidation arrives in L2.
4. **Authoritative fault and crash recovery.** Inject read-only/write/read failures, including failures while quarantining or recording an observation failure. All subsequent protected calls/catalogs block, no cached approval is used, and the uncommitted action is labeled honestly. Test failure to durably create the owner marker, unclean exit, interrupted recovery, and clean marker removal. Reopening invalidates old approvals and requires successful observation plus explicit approval; quarantine/failure markers survive. Pending remote delivery alone permits a clean shutdown.
5. **Migration.** Refuse a synthetic newer schema without changing its marker or data. Test supported upgrades, interruption/rollback/retry and read-only access without migration. Preserve a separate legacy database/backup; never test an old executable against the only upgraded store.
6. **No duplicate side effects.** An instrumented tool performs one effect and loses its response. One call attempt causes at most one dispatch; expose outcome-unknown. A deliberate caller retry is a separate operation with fresh authorization.
7. **Custom policy and detector binding.** A custom non-demo policy/rules pair passes; unchanged demo rules with a new policy fail even on zero-match input. Same IDs with a new policy digest require a new binding. Missing/undeclared/incorrectly mapped rules fail. Candidate reload rejection leaves the old active pair visibly unchanged. Core mode works without detector/cloud dependencies; adapter validation is tested separately.
8. **Regression gate.** Preserve existing revision, generation, explicit restore, shared failure recovery, hard-deny precedence and exact evidence validation. Run focused real-transport tests and the full suite. Record changes to public CLI semantics and packaging; do not reinterpret old results as new evidence.

## Senso capability gate before L3

This gate is **pending**, not established by the old policy upload. Complete it after L2 review and before committing to the lesson-persistence design. The approved X1 experiment runs it earlier; that dated evidence must be re-accepted at L3. Check current official API documentation and run a small private synthetic test covering upload/processing, exact content read-back, scoped retrieval, content/version identity and cleanup. Record actual fields, request outcomes and supported guarantees without exposing keys or unrelated documents.

Determine whether a lost upload response can be reconciled through an evidenced remote idempotency or lookup mechanism. A stable local operation ID does not prove that capability. If automatic reconciliation is unavailable, specify `publication_indeterminate`: inactive, durable and never blindly retried. An explicit reconciliation operation may accept a discovered remote ID only after exact approved-content/version verification and a new local eligibility check. Explicit abandonment/new publication must disclose possible orphaned content; unknown content never enters the retrieval allowlist. Local revocation takes effect even if remote cleanup fails.

If required content/version integrity cannot be established, the gate remains unmet and L3 cannot claim completion. Do not invent fields, assume remote immutability or weaken the contract to get a demo. The supported reconciliation path is a design decision backed by this check, not a requirement that the remote API provide automatic idempotency.

Before L3 implementation, also freeze lesson-source and held-out manifests under REQ-EVAL-03. The eight semantic cases are separate from memory-integrity tests, include at least four families and at least one family absent from lesson sources. No near-duplicate split leakage. Three pairs per case yield 48 scheduled trials, not necessarily 48 model requests. Keep all failed trials; an intentional rerun is a new complete versioned run with the original retained.

## Verification strategy

- Retain real-transport enforcement proofs: explicit first approval, metadata/policy/config change invalidation, shared observation failure, persistent quarantine, successful-observation-before-recovery, stale decisions, unchanged independent call counts and an unaffected control.
- Test observable failure boundaries: concurrent sessions, stale catalogs, a second process, dirty/freshness gates, cancellation, detector/retrieval errors and audit outage. A generic server without an independent verifier yields local nondispatch evidence, not `verified_blocked`.
- Prove packaging from a fresh virtual environment outside every repository/worktree. Test both the public async API and generic CLI. No `PYTHONPATH` workaround or editable installation counts as wheel proof.
- Use a bounded compatibility matrix based on actual tests, starting with the reviewed MCP 1.30 integration; avoid an SDK-major migration in this release. Choose and document tested Python/OS support before advertising it.
- Keep credentialless CI separate from opt-in live integration checks. Live checks must use private, sanitized fixtures and record actual provider outcomes without logging secrets. Do not retry expensive evaluations until the outcome looks favorable.
- Maintain requirement-to-evidence references in each handoff. A successful unit suite does not prove a live integration, installability or semantic improvement.

## Weekend execution and cut order

Aim to spend the first day on L1/L2 and evaluation-case design; the second on L3/L4, the minimal L5 page and L6 packaging/demo. This is ambitious even with the existing core. Review estimates after L1: if time runs out, report the exact unfinished gates and ship an explicitly narrower candidate, not a falsely complete library.

Cut visual polish, charts, extra examples and extra supported platforms first. Already deferred: hosting, remote administration, HTTP/OAuth, distributed state, arbitrary-client proxying, registry ingestion and fine-tuning. Do not cut the installed-consumer proof, recovery/invalidation invariants, lesson governance, held-out evaluation or truthful release documentation to produce a longer video.

The earlier sequential plan assigned **L1 only** to the next chat. That execution
order was superseded by the explicit 12 October parallel-completion request;
use the current execution record before starting another development branch.

## Release checklist

These are new-release requirements, not completed checkboxes inferred from the old demo.

- [ ] Public API and generic CLI work from an installed wheel outside the checkout.
- [ ] Identity, ownership, durable fault recovery, migrations, discovery, explicit CLI refresh, per-session freshness and no-replay tests pass.
- [ ] Monitor shuts down cleanly and retains undelivered audit/publication work.
- [ ] Reviewed memory publication, retrieval and revocation are proven with real Senso responses.
- [ ] Original regressions and versioned held-out paired results are available, including failures.
- [ ] Local console uses real state and guarded SDK operations.
- [ ] License, distribution name/version, compatibility, CI and migration documentation are complete.
- [ ] Final artifacts, credential handling and shareable evidence have been reviewed.
- [ ] Demo and video match the released behavior; public package/repository release is deliberate.

The 9 October hackathon deadline and submission workflow are historical. This document does not assert that a submission or video was delivered.
