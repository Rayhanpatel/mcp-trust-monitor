# Handoff: M0 and M1

Branch `feat/m1-enforcement`, based on `main` at `f257116`. Six commits:
1. M0 documents.
2. M1 enforcement boundary.
3. M0 follow-up: ClickHouse smoke test.
4. Fixes from the review of `c53b81c`.
5. Fixes from the review of `13440e0`, plus the runtime provider decision.
6. Recovery fix from the review of `f3afdab`.

Not merged or pushed. Stopped for independent review.

Not part of this review: unfinished, unreviewed M2/M3 local work is paused on `feat/m2-local-detection` at `4271cc1` and was left untouched. It branches from `c53b81c`, so it **contains none of the review fixes** and must be rebased onto this branch before M2 resumes. Its new modules are untested.

## Fix from the review of `f3afdab`: recovery needs fresh evidence

- **The gap.** After an observation failure, an operator could approve the stored, pre-failure observation without any new successful check. Another session would then dispatch using its cached validation.
- **Reproduced before fixing** with the review's sequence over real transport, using a scratch script. Approval with the stored revision and current generation was accepted, the call dispatched, and the server-side received-call count went 0 → 1.
- **Fix, at the trust-store boundary** (`trust_store.py`):
  - Each trust record has a persisted `observation_failed_at` column, migrated in place for older stores. `record_observation_failure` sets it in every state, bumping the generation.
  - `approve`, and therefore restore, raises the new `ObservationRequiredError` while it is set.
  - Only `record_observation` clears it, after a complete, validated `tools/list`. Clearing bumps the generation, records `observation_recovered`, and never changes the state to approved.
  - Unchanged metadata counts as recovery evidence. Changed metadata additionally records `revision_changed`.
  - The CLI refuses with exit 2, and `status` shows the pending requirement.
- **After the fix**, the same sequence is rejected with `ObservationRequiredError`, the call is blocked with `pending_review`, and the server count stays at 0.
- **Tests:**
  - `test_approval_after_a_failure_requires_a_successful_observation`: real transport, with the three failure kinds (duplicate tool names, a `tools/list` server error, startup failure). It runs the review sequence, with B staying blocked and the control usable. After a successful observation of the changed metadata, the premature decision is still rejected as stale. Recovery then works through a baseline observation and explicit approval.
  - `test_recovery_requirement_survives_restart_and_repeated_failures` (real transport):
    - the requirement persists across a client restart and store reopen;
    - the operator CLI `approve` exits 2;
    - unchanged-metadata recovery clears the requirement but leaves calls blocked;
    - a second failure before approval re-arms it;
    - final recovery works.
  - Store unit tests cover restart, recovery with unchanged metadata, the generation bump making earlier decisions stale, re-arming, and quarantine restore gated by the requirement while the server stays quarantined.
  - **Test changed:** `test_observation_failure_invalidates_approval_and_preserves_quarantine` previously expected `StaleDecisionError` for a pre-failure decision. It is now refused earlier with `ObservationRequiredError`. The test asserts that, and also that the same decision is still `StaleDecisionError` after recovery, so the stale-decision coverage is kept.
  - The new tests reference `ObservationRequiredError`, so they cannot import against `f3afdab`. The before-and-after evidence for the gap is the scratch reproduction above.
- SPEC REQ-REV-02, REQ-TRU-04, and the two authorizing rows of the trust-state table now state this rule. The README notes the order to follow: `observe`, then `approve`.

## Fixes from the review of `13440e0`

**1. Observation failures are shared.**
- **The bug.** A failed observation closed only the failing session, so other sessions of the same managed client could dispatch on their cached validation.
- **Reproduced before fixing** with the review's sequence over real transport, using a scratch script. Sessions A and B validated the approved baseline, A's observation failed, and the server switched to `private-content-demand`. B then dispatched: the server-side received-call count went 0 → 1 while the state read `approved`.
- **Fix.** `TrustStore.record_observation_failure` runs one SQLite transaction. It moves `approved` to `pending_review`, bumping the generation so decisions made earlier become stale, and records `observation_failed` with the from and to states. Quarantine and other states are preserved, and an unknown server still gets an audited event.
- **Where it applies.** `ManagedClient` calls it for:
  - launch, transport, and initialization failures in `_open_connection`;
  - `tools/list` failures in `_observe`: RPC errors, invalid or duplicate tool names, page-limit overruns, and store errors.

  The failing session is closed. Every session of the same managed client authorizes against the shared record, so all of them block.
- **Recovery** requires a successful observation of valid metadata, then explicit operator approval.
- **After the fix**, the same sequence is blocked with `pending_review`, and the server count stays at 0.
- **Regression tests** (real stdio transport, server-side counter). Each runs with three failure kinds: `duplicate-tool-names` (rejected by the client), `server-error` (a `tools/list` JSON-RPC error), and `startup-failure` (the server process exits before MCP initialization).
  - `test_observation_failure_in_one_session_blocks_every_session`: the review's two-session sequence. B stays blocked; the control is usable from both sessions; recovery works through valid metadata and approval. All 3 variants failed against the `13440e0` logic and pass now.
  - `test_failed_observation_cannot_leave_a_connection_eligible_for_dispatch`, updated: the first failure raises `ObservationError` and moves the state to `pending_review`. The retry is refused before the server is contacted, so its `tools/list` count is unchanged. It also covers the `private-content-demand` swap, the control, and recovery.
  - `test_failed_reobservation_of_an_open_session_requires_fresh_validation`, which now also asserts `pending_review`.
  - Store unit test `test_observation_failure_invalidates_approval_and_preserves_quarantine`.
- The demo server gained a per-server `fail_startup` marker (`set_startup_failure`) to produce real initialization failures.
- SPEC REQ-REV-02 and the trust-state table were updated in place.

**2. Redaction before truncation.**
- **The bug.** `scripts/smoke_clickhouse.py` truncated results to 80 characters and errors to 200 before redacting, so a secret crossing a cutoff could leak in part.
- **Fix.** Every raw result, HTTP error body, and connection error string is now redacted in full before truncation, `repr`, or formatting. Each printed line is redacted again.
- **Tests.** `test_secrets_crossing_truncation_boundaries_are_fully_redacted` uses synthetic secrets only. It places the password or host 8 characters before the 80 or 200 cutoff, in an unexpected result, an HTTP error body, and a connection error, and asserts that no 6-character fragment of the secret appears. All 6 cases failed against the previous script and pass now.

## Fixes from the review of `c53b81c`

**1. Failed-observation retry bypass.**
- A new connection was cached before its observation succeeded, so a retry reused it without observing again.
- Each session now tracks the revision its own last successful observation recorded. A session validated at an older revision is re-observed before dispatch, and the authoritative check otherwise blocks with `session_not_validated`.
- Regression tests: `test_session_validated_at_an_older_revision_is_revalidated_before_dispatch`, plus the tests above.

**2. Smoke-test false positives.**
- Each ClickHouse check now has an expected value. `SELECT 1`, database existence, read-back, and both `CHECK GRANT` checks must return `'1'`; the version must look like a version number; the DDL and insert must return an empty response.
- Anything else prints `UNEXPECTED`, counts as a failure, and exits 1.
- The tests use a scripted client and injected settings, so no network is used and the real `.env` is never read. They check the script's validation, not ClickHouse.

## Requirements completed

Implemented and tested over real stdio MCP transport:

| ID | Evidence |
| --- | --- |
| REQ-REV-01 | `revision.py`; `tests/test_revision.py` |
| REQ-REV-02 (partial) | Bounded pagination. Connection, initialization, and `tools/list` failures invalidate approval for every session and are audited. Approve and restore are refused until a later successful observation, a requirement that persists across restart and re-arms on another failure. Timeouts from a server that hangs without exiting are not tested |
| REQ-ENF-01 | The gate checks before connecting and again before the transport write. A CLI quarantine blocks an open session. A session dispatches only after its own successful observation of the stored revision. One session's failed observation blocks all sessions |
| REQ-ENF-02 | Unreviewed, pending, quarantined, policy-mismatched, and unknown-tool calls are blocked |
| REQ-ENF-03 | Server-side count unchanged after quarantine; connection closed, including after quarantine by another process |
| REQ-ENF-04 | Control stays callable through quarantine, restart, and observation failures, including from a second session |
| REQ-TRU-01 | First observation is `unreviewed`; the baseline needs explicit approval |
| REQ-TRU-02 | Stale revision and generation approvals rejected, including decisions predating an observation failure or a recovery observation; approval bound to the policy digest |
| REQ-TRU-03 | Change or observation failure moves approved to `pending_review`; reverting does not restore approval |
| REQ-TRU-04 | Quarantine survives restart and store reopen; observations and observation failures never lift it; only `approve --restore` does, and after a failure only once a successful observation has followed it |
| REQ-TRU-05 | Approval is operator-only; the harmless change stays pending until approved. No model path exists yet |
| REQ-TRU-06 | Duplicate approval and duplicate quarantine are no-ops |

Also partial: REQ-AUD-01 (each transition commits with its local event in one SQLite transaction; there is no ClickHouse outbox yet) and REQ-EVAL-01 (cases fixed and structurally checked; no evaluation harness).

## Decisions recorded

- **Runtime model provider: OpenAI.** M3 will use `gpt-6-astra` (`MODEL_NAME`, `OPENAI_API_KEY`) through the official OpenAI Python SDK, the Responses API, and strict Structured Outputs.
  - The schema's recommendation enum is `review` | `quarantine`, so the model cannot express approval.
  - REQ-DEC-03 evidence validation and REQ-DEC-01 hard-deny precedence still apply after the model.
  - Claude Code is the implementation tool only.
  - Recorded in SPEC ("Runtime model provider"), BUILD_PLAN (M3), README, CLAUDE.md, and `.env.example`.
  - No OpenAI dependency or code was added.
- **Observation failures invalidate approval** (above). This replaces the earlier, narrower behavior in which a failed observation kept the approval.
- M0 decisions: one mutable server and one control; enforcement immediately before dispatch; registry ingestion, crawling, hosting, charts, and recovery demos deferred; hard denials cannot be overridden; the model recommends review or quarantine only; the harmless change expects `pending_review`; validation is traceability; six fixed evaluation cases with policy-derived expectations.

## Interpretations for the reviewer to confirm

1. **Autonomous quarantine.** A *validated* quarantine recommendation is applied automatically, because it is restrictive. This is needed for the autonomous-action requirement and M4's "no human decision" exit.
2. **Operator quarantine is server-scoped and fail-closed.** A stale *assessment* is discarded, and the server stays blocked in pending review.
3. **Observing a quarantined server is allowed.** It is explicit and metadata-only; for stdio this launches the process. The call path never launches a blocked server.
4. **Case `private-content-without-address`.** It expects quarantine under POL-001 although the narrower hard-deny condition does not apply. The expectation follows the policy text and was written before any detector or model run.
5. **CLI approval without `--generation`** binds to the revision and policy only. SPEC REQ-TRU-02 allows this.
6. **Scope of shared failure.** A failure blocks every session with the same managed-client ID (`client_id`) and server, across processes sharing the store. A different managed client keeps its own trust records, as specified by trust scoping.

## Changed files

- M0: `docs/SPEC.md`, `docs/BUILD_PLAN.md`, `docs/EVIDENCE.md`, `policies/demo-policy.json`, `fixtures/tool_changes.json`, `CLAUDE.md` (new).
- M1: `pyproject.toml`, `uv.lock`, `mcp_trust_monitor/{__init__,__main__,demo_server,managed_client,policy,revision,trust_store}.py`, `tests/{conftest,test_enforcement,test_fixtures,test_revision,test_trust_store}.py`, `README.md`, `docs/HANDOFF.md`.
- M0 follow-up: `scripts/smoke_clickhouse.py` (new), `.env.example`, `docs/EVIDENCE.md`, `README.md`, `docs/HANDOFF.md`.
- Review of `c53b81c`: `mcp_trust_monitor/{managed_client,demo_server}.py`, `scripts/smoke_clickhouse.py`, `tests/{conftest,test_enforcement}.py`, `tests/test_smoke_clickhouse.py` (new), `docs/{SPEC,EVIDENCE,HANDOFF}.md`.
- Review of `13440e0`: `mcp_trust_monitor/{managed_client,trust_store,demo_server}.py`, `scripts/smoke_clickhouse.py`, `tests/{test_enforcement,test_trust_store,test_smoke_clickhouse}.py`, `docs/{SPEC,BUILD_PLAN,EVIDENCE,HANDOFF}.md`, `README.md`, `CLAUDE.md`, `.env.example`.
- Review of `f3afdab`: `mcp_trust_monitor/{trust_store,__main__}.py`, `tests/{test_enforcement,test_trust_store}.py`, `docs/{SPEC,EVIDENCE,HANDOFF}.md`, `README.md`.

## Commands and results

| Command | Result |
| --- | --- |
| `uv sync --python 3.12` | `mcp` 1.30.0 and `pytest` 9.1.1 on CPython 3.12.7 |
| `uv run pytest` | 58 passed in about 22.6 s, run twice with no failures. The first run after the fix had 1 failure: the outdated assertion described under "Test changed" |
| New tests against the previous code | The 3 two-session variants failed against the `13440e0` client and store, temporarily stashed. The 6 truncation-boundary tests failed against the previous smoke script. Both fixes were restored afterwards |
| `uv run python -m mcp_trust_monitor demo` | Completes. Blocked calls leave `demo/document-lookup` at 2 received calls through quarantine and restart; the control rises to 3 |
| `uv run python scripts/smoke_clickhouse.py`, first run (previous round) | **Failed, exit 1.** `SELECT 1` and `version()` timed out after 60 s, and the third check succeeded after 23 s. The script correctly reported failure. The cause is **unconfirmed**: the timing is consistent with ClickHouse Cloud resuming from idle suspension, but this was not verified. The script was unchanged this round and was not rerun |
| `uv run python scripts/smoke_clickhouse.py`, rerun at 14:20 PDT | **8 of 8 expected values, exit 0** against ClickHouse Cloud 26.6.1.2326. Each request took 191–271 ms. No persistent change |
| Review repro scripts (scratch, real transport) | Shared failure (`13440e0`): before, B dispatched and the server count went 0 → 1; after, B blocked with `pending_review`, count 0. Premature approval (`f3afdab`): before, approval was accepted, the call dispatched, and the count went 0 → 1; after, approval was rejected with `ObservationRequiredError`, the call was blocked, and the count stayed 0 |
| Senso | Authentication reported successful by the user (independent check). Not contacted by this repository. Policy upload and scoped retrieval pending |
| OpenAI | A `gpt-6-astra` Responses API request was reported successful by the user (independent check). No model calls from this repository |
| `.env` | Checked by variable name only: the ClickHouse values, `SENSO_API_KEY`, and `OPENAI_API_KEY` are set, and `SENSO_POLICY_CONTENT_IDS` is empty. Not modified |

## Limitations

- **Transient failures need observation and re-approval.** Any connection, initialization, or `tools/list` failure, including a brief network error, puts an approved server in pending review. An operator must observe it successfully and then approve it again. This is fail-closed by design.
- **What the operator approves after recovery.** The recovering observation may record *changed* metadata, which the operator could then approve explicitly. Until M3, nothing assesses that revision automatically; `status` shows its descriptions. CLI approvals without `--generation` bind to the revision and policy only (REQ-TRU-02).
- **In-flight calls.** A call that another session dispatched before the failure transaction committed may already have run (REQ-ENF-05). The same cross-process window applies to quarantine: the gate reads SQLite and then writes to the transport, and a commit in between lets one call through.
- **Change detection.** A long-lived session sees metadata changes only on `observe()`, on reconnection, or when its validated revision is stale. Polling and freshness (REQ-TRU-07) and `tools/list_changed` notifications are not implemented.
- **Timeouts.** A server that hangs, rather than exiting or erroring, would surface after the 15 s read timeout as an observation failure. This path is untested.
- **ClickHouse first-request timeouts.** The first smoke run timed out on its first two requests. The cause is unconfirmed; idle suspension is the likely explanation, but it was not verified. Before a demo, warm the service with the smoke script, or disable idling, and check the result.
- **Coverage.** Revisions cover name, description, and input schema only. Trust is keyed by logical server name, not endpoint identity.
- **Untried mutation check.** A run with the gate disabled was denied by the session's permission classifier. Positive controls exist, and every review regression test was confirmed to fail on the code it targets.
- **iCloud folder.** The `.venv` files are hidden by iCloud sync, so the package uses a flat layout, server launches set `PYTHONPATH` explicitly, and pytest uses `pythonpath = ["."]`. Run from the repository root.
- **Semgrep packaging.** Semgrep was run with `uvx` and is not yet a project dependency on this branch.

## Remaining work

Follow [BUILD_PLAN.md](BUILD_PLAN.md):
1. Rebase `feat/m2-local-detection` onto this branch.
2. M2: ClickHouse outbox and history; Semgrep hard-deny rules.
3. M3: upload the policy to Senso and fill in `SENSO_POLICY_CONTENT_IDS`; scoped retrieval; OpenAI Responses API assessment with strict Structured Outputs; validator; evaluation report.
4. M4: autonomous loop with freshness.
5. M5: minimal timeline page.
6. M6: recording and submission.
