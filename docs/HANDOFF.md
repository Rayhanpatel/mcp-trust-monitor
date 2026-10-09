# Handoff: M0 and M1

Branch `feat/m1-enforcement`, based on `main` at `f257116`. Four commits:
1. M0 documents.
2. M1 enforcement boundary.
3. M0 follow-up recording the ClickHouse smoke test.
4. Fixes for the two issues found in the independent review of `c53b81c`.

Not merged. Stopped for re-review.

Not part of this review: unfinished, unreviewed M2/M3 local work (Semgrep hard-deny detector, decision combiner, review loop) is paused on the separate branch `feat/m2-local-detection` at `4271cc1`. It branches from `c53b81c`, so it **does not contain the review fixes** and must be rebased onto this branch before M2 resumes. Its new modules are untested.

## Review fixes (review of `c53b81c`)

**1. Failed-observation retry bypass.** `ManagedClient` cached a new connection before its observation succeeded. After a failed observation, a retry reused that connection without observing again and dispatched on the strength of an old persisted approval.
- **Reproduced before fixing** with the review's sequence, using real transport. The retry dispatched even though the server was serving `private-content-demand`; its received-call count went from 0 to 1 while the state still read `approved`. The four new regression tests also failed against the unfixed code.
- **Fix** (`managed_client.py`). Each session tracks the revision its own last successful observation recorded. `_observe` clears it first. Any failure records `observation_failed`, closes the session, and re-raises.
- Before dispatch, the session's validated revision must equal the stored observed revision, or the session is re-observed first. The authoritative check blocks with `session_not_validated` otherwise.
- A changed revision found by that re-observation invalidates the approval through the existing `record_observation` transition.
- **After the fix**, the same sequence is blocked with `pending_review`, and the server count stays at 0.
- **Regression tests** (real stdio transport, server-side received-call counter):
  - `test_failed_observation_cannot_leave_a_connection_eligible_for_dispatch`, run with both a client-rejected response (duplicate tool names) and a server-side `tools/list` error. It covers repeated failing retries, the reviewer's sequence, the control staying usable, and recovery: valid metadata, then explicit approval, then a successful call.
  - `test_failed_reobservation_of_an_open_session_requires_fresh_validation`.
  - `test_session_validated_at_an_older_revision_is_revalidated_before_dispatch`. This covers a related bypass from the same root cause: another client approves B, and the server moves to an unobserved C.
- SPEC REQ-REV-02 and REQ-ENF-01 were tightened in place to state this rule.
- To support these tests, the demo server's override file may now hold a raw tool list, so tests can serve malformed responses.

**2. ClickHouse smoke-test false positives.** `scripts/smoke_clickhouse.py` accepted any answer that wasn't an exception.
- **Fix.** Each check now has an expected value:
  - `SELECT 1`, database existence, read-back, and both `CHECK GRANT` checks must return `'1'`;
  - the version must look like a version number;
  - the DDL and insert statements must return an empty response.

  Anything else prints `UNEXPECTED`, counts as a failure, and makes the exit status 1. All printed lines are sanitized by replacing the host, user, and password with `<redacted>`.
- **Tests.** `tests/test_smoke_clickhouse.py` drives the checks with a scripted client and injected settings, so no network is used and the real `.env` is never read. It covers the passing case, 9 zero-or-unexpected answers each failing with exit 1, sanitization of HTTP and connection errors, and missing settings (exit 2). These tests check the script's validation, not ClickHouse itself.

## Requirements completed

M1 implements and tests these over real stdio MCP transport:

| ID | Evidence |
| --- | --- |
| REQ-REV-01 | `revision.py`; `tests/test_revision.py` |
| REQ-ENF-01 | Gate in `ManagedClient.call_tool` checks before connecting and again before the transport write. A quarantine issued by a separate CLI process blocks an open session. A session dispatches only after its own successful observation of the stored revision (the three review regression tests) |
| REQ-ENF-02 | Unreviewed, pending, quarantined, policy-mismatched, and unknown-tool calls are blocked |
| REQ-ENF-03 | Server-side received-call count unchanged after quarantine; connection closed, including after quarantine by another process |
| REQ-ENF-04 | Control server stays callable before and after restart |
| REQ-TRU-01 | First observation is `unreviewed`; the baseline needs explicit approval |
| REQ-TRU-02 | Stale revision and stale generation approvals rejected; approval bound to the policy digest |
| REQ-TRU-03 | Change moves approved to `pending_review`; reverting does not restore approval; a reconnecting client sees the change before dispatch |
| REQ-TRU-04 | Quarantine survives client restart and store reopen; observation never lifts it; only `approve --restore` does |
| REQ-TRU-05 | Approval is operator-only; the harmless change stays pending until approved. No model path exists yet |
| REQ-TRU-06 | Duplicate approval and duplicate quarantine are no-ops |

Partial: REQ-REV-02 (bounded pagination; a failed or invalid `tools/list` raises `ObservationError`, records `observation_failed`, and leaves no session eligible for dispatch; timeouts are not tested), REQ-AUD-01 (each transition and its local event commit in one SQLite transaction; there is no ClickHouse outbox), and REQ-EVAL-01 (cases fixed and structurally checked; no evaluation harness).

## M0 decisions applied

- One controlled mutable server and one unaffected control. Public registry ingestion (including the saved snapshot), crawling, hosting, charts, and recovery demos deferred.
- Enforcement is located immediately before transport dispatch (REQ-ENF-01).
- Decision authority (REQ-DEC-01, REQ-DEC-02): deterministic hard-deny rules quarantine and cannot be overridden; the model recommends `review` or `quarantine` only; only the operator approves.
- The harmless change now expects `pending_review`, not `allow`. The policy's `benign_changes` text, the fixture, README, demo script, and acceptance criteria no longer claim automatic reapproval.
- Validation is described as traceability, not semantic correctness (REQ-DEC-03).
- Revision guards and restart persistence are test requirements, not demo scenes.
- Policy revision 2 adds a `hard_deny_condition` per rule and a `decision_authority` block. The fixture now holds six fixed evaluation cases with policy-derived expectations (REQ-EVAL-01).

## Interpretations for the reviewer to confirm

These affect product behavior. Each was resolved conservatively and recorded in SPEC.md.

1. **Autonomous quarantine.** "The model may recommend quarantine" is read as: a *validated* quarantine recommendation is applied automatically, because it is restrictive. Without this, the event's autonomous-action requirement and M4's "no human decision" exit condition cannot be met. If quarantine should need operator confirmation, M4 and the demo change.
2. **Operator quarantine is server-scoped and fail-closed.** It applies regardless of revision. A stale *assessment* is discarded, and the server stays blocked in pending review.
3. **Observing a quarantined server is allowed.** It is explicit and metadata-only, so later revisions are still recorded. For a stdio server this launches its process. The call path never launches a blocked server.
4. **Case `private-content-without-address`** expects quarantine under POL-001, but the narrower POL-001 hard-deny condition does not apply, so only the model can reach the expected outcome. The expectation follows the policy text and was written before any detector or model run. Check that this is a legitimate fixed case, not tuning in the model's favor. `benign-policy-mention` is the counterpart that checks that rules do not over-match.
5. **CLI approval without `--generation`** binds to the revision and policy only. SPEC REQ-TRU-02 allows this; programmatic decisions should pass the generation.
6. **Model provider.** `.env.example` now names `ANTHROPIC_API_KEY` and `MODEL_NAME` (default `claude-opus-5-5`, called through the official `anthropic` SDK) instead of the generic `MODEL_API_KEY`. The alternative is AkashML's OpenAI-compatible endpoint, which could add an Akash sponsor contribution; it needs a different adapter and variable names.

## Changed files

- M0: `docs/SPEC.md`, `docs/BUILD_PLAN.md`, `docs/EVIDENCE.md`, `policies/demo-policy.json`, `fixtures/tool_changes.json`, `CLAUDE.md` (new).
- M1: `pyproject.toml`, `uv.lock`, `mcp_trust_monitor/{__init__,__main__,demo_server,managed_client,policy,revision,trust_store}.py`, `tests/{conftest,test_enforcement,test_fixtures,test_revision,test_trust_store}.py`, `README.md`, `docs/HANDOFF.md`.
- M0 follow-up: `scripts/smoke_clickhouse.py` (new), `.env.example`, `docs/EVIDENCE.md`, `README.md`, `docs/HANDOFF.md`.
- Review fixes: `mcp_trust_monitor/managed_client.py`, `mcp_trust_monitor/demo_server.py`, `scripts/smoke_clickhouse.py`, `tests/conftest.py`, `tests/test_enforcement.py`, `tests/test_smoke_clickhouse.py` (new), `docs/SPEC.md`, `docs/EVIDENCE.md`, `docs/HANDOFF.md`.

## Commands and results

| Command | Result |
| --- | --- |
| `uv sync --python 3.12` | Installs `mcp` 1.30.0 and `pytest` 9.1.1 on CPython 3.12.7 |
| `uv run pytest` | After the review fixes: 41 passed in about 10.6 s, repeated 3 times with no failures. Before the fixes, the 4 new enforcement regression tests failed |
| `uv run python -m mcp_trust_monitor demo` | Completes in about 2 s. Blocked calls leave `demo/document-lookup` at 2 received calls through quarantine and restart; the control rises to 3 |
| Manual CLI sequence in README | Run against a scratch state directory. Blocked call exits 3; approving a quarantined server exits 2 with "requires an explicit restore" |
| `uvx --from semgrep==1.180.0 semgrep scan --metrics=off --json --config <smoke rule> <fixture descriptions>` | 2 matches, 0 errors, no login. See [EVIDENCE.md](EVIDENCE.md#integration-smoke-tests) |
| `uv run python scripts/smoke_clickhouse.py` | With value validation (after the review fix): 8 of 8 checks matched their expected values against ClickHouse Cloud 26.6.1.2326. `SELECT 1` returned `'1'`; database existence returned `'1'`; temporary-table insert and read-back returned `'1'`; both `CHECK GRANT` checks returned `'1'`. Exit 0, no persistent change. See [EVIDENCE.md](EVIDENCE.md#integration-smoke-tests) |
| Review repro (scratch script, review sequence, duplicate-tool-names metadata) | Before the fix: the retry dispatched and the server count rose to 1 while the state read `approved`. After: blocked with `pending_review`, server count 0 |
| Senso, model API | Blocked: no `SENSO_API_KEY` or `ANTHROPIC_API_KEY`. Nothing was contacted or mocked |

## Limitations

- **Cross-process window.** The gate reads SQLite, then writes to the transport with no intervening await. A quarantine committed by *another process* inside that window lets one call through; it counts as in flight (REQ-ENF-05). Quarantines in the same process are serialized by the per-server lock.
- **Change detection.** A long-lived session sees metadata changes only on `observe()` or a new connection. Polling and freshness (REQ-TRU-07) and `tools/list_changed` notifications are not implemented.
- **Coverage.** Revisions cover name, description, and input schema only. Trust is keyed by logical server name, not endpoint identity.
- **Untried mutation check.** A run with the gate disabled, to confirm that the enforcement tests then fail, was denied by the session's permission classifier. The tests have positive controls: allowed calls must increment the server-side count. The four review regression tests were confirmed to fail on the unfixed code.
- **Failed observations keep the approval.** A failed observation records `observation_failed` and makes the observing client's session ineligible, but it does not change trust state. Another client whose session already validated the same revision can still dispatch until it observes again. This is the existing change-detection gap, and freshness (REQ-TRU-07) is the planned control. The review asked for invalidation on a *changed* revision, which is implemented. Invalidating on every transient failure would force an operator re-approval after each network error.
- **iCloud folder.** This repository is in an iCloud-synced Desktop, which marks `.venv` files hidden; Python then skips the editable-install `.pth`. Hence the flat package layout, the explicit `PYTHONPATH` for server launches, and `pythonpath = ["."]` for pytest. Run commands from the repository root. The default `runtime/state` SQLite database also sits in the synced folder. Tests and `demo` use temporary directories outside it.
- **Semgrep packaging.** Semgrep was run with `uvx` and is not yet a project dependency.

## Remaining work

Follow [BUILD_PLAN.md](BUILD_PLAN.md): M2 (ClickHouse outbox and history, Semgrep hard-deny rules with offset-based evidence spans), M3 (Senso scoped retrieval, model recommendation, validator, evaluation report), M4 (autonomous poll-detect-quarantine-verify loop with freshness), M5 (minimal timeline page), M6 (recording and submission). ClickHouse is ready for M2. Senso (`SENSO_API_KEY`; the content id comes from uploading the policy) and model (`ANTHROPIC_API_KEY`) credentials are still needed before M3 can claim sponsor usage.
