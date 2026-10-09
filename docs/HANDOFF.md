# Handoff: M0 and M1

Branch `feat/m1-enforcement`, based on `main` at `f257116`. Two commits: M0 (documents) and M1 (enforcement boundary). Not merged. Stopped for review.

## Requirements completed

M1 implements and tests these over real stdio MCP transport:

| ID | Evidence |
| --- | --- |
| REQ-REV-01 | `revision.py`; `tests/test_revision.py` |
| REQ-ENF-01 | Gate in `ManagedClient.call_tool` checks before connecting and again before the transport write; a quarantine issued by a separate CLI process blocks an open session (`test_quarantine_from_another_process_blocks_an_open_session`) |
| REQ-ENF-02 | Unreviewed, pending, quarantined, policy-mismatched, and unknown-tool calls are blocked |
| REQ-ENF-03 | Server-side received-call count unchanged after quarantine; connection closed, including after quarantine by another process |
| REQ-ENF-04 | Control server stays callable before and after restart |
| REQ-TRU-01 | First observation is `unreviewed`; the baseline needs explicit approval |
| REQ-TRU-02 | Stale revision and stale generation approvals rejected; approval bound to the policy digest |
| REQ-TRU-03 | Change moves approved to `pending_review`; reverting does not restore approval; a reconnecting client sees the change before dispatch |
| REQ-TRU-04 | Quarantine survives client restart and store reopen; observation never lifts it; only `approve --restore` does |
| REQ-TRU-05 | Approval is operator-only; the harmless change stays pending until approved. No model path exists yet |
| REQ-TRU-06 | Duplicate approval and duplicate quarantine are no-ops |

Partial: REQ-REV-02 (bounded pagination; failed or invalid `tools/list` raises `ObservationError` without changing state; timeouts are not tested), REQ-AUD-01 (each transition and its local event commit in one SQLite transaction; there is no ClickHouse outbox), and REQ-EVAL-01 (cases fixed and structurally checked; no evaluation harness).

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

## Changed files

- M0: `docs/SPEC.md`, `docs/BUILD_PLAN.md`, `docs/EVIDENCE.md`, `policies/demo-policy.json`, `fixtures/tool_changes.json`, `CLAUDE.md` (new).
- M1: `pyproject.toml`, `uv.lock`, `mcp_trust_monitor/{__init__,__main__,demo_server,managed_client,policy,revision,trust_store}.py`, `tests/{conftest,test_enforcement,test_fixtures,test_revision,test_trust_store}.py`, `README.md`, `docs/HANDOFF.md`.

## Commands and results

| Command | Result |
| --- | --- |
| `uv sync --python 3.12` | Installs `mcp` 1.30.0 and `pytest` 9.1.1 on CPython 3.12.7 |
| `uv run pytest` | 25 passed in about 5.5 s; repeated 4 times with no failures |
| `uv run python -m mcp_trust_monitor demo` | Completes in about 2 s. Blocked calls leave `demo/document-lookup` at 2 received calls through quarantine and restart; the control rises to 3 |
| Manual CLI sequence in README | Run against a scratch state directory. Blocked call exits 3; approving a quarantined server exits 2 with "requires an explicit restore" |
| `uvx --from semgrep==1.180.0 semgrep scan --metrics=off --json --config <smoke rule> <fixture descriptions>` | 2 matches, 0 errors, no login. See [EVIDENCE.md](EVIDENCE.md#integration-smoke-tests) |
| ClickHouse, Senso, model API | Blocked: no credentials configured. Nothing was contacted or mocked |

## Limitations

- **Cross-process window.** The gate reads SQLite, then writes to the transport with no intervening await. A quarantine committed by *another process* inside that window lets one call through; it counts as in flight (REQ-ENF-05). Quarantines in the same process are serialized by the per-server lock.
- **Change detection.** A long-lived session sees metadata changes only on `observe()` or a new connection. Polling and freshness (REQ-TRU-07) and `tools/list_changed` notifications are not implemented.
- **Coverage.** Revisions cover name, description, and input schema only. Trust is keyed by logical server name, not endpoint identity.
- **Untried mutation check.** A run with the gate disabled, to confirm that the enforcement tests then fail, was denied by the session's permission classifier. The tests have positive controls: allowed calls must increment the server-side count.
- **iCloud folder.** This repository is in an iCloud-synced Desktop, which marks `.venv` files hidden; Python then skips the editable-install `.pth`. Hence the flat package layout, the explicit `PYTHONPATH` for server launches, and `pythonpath = ["."]` for pytest. Run commands from the repository root. The default `runtime/state` SQLite database also sits in the synced folder. Tests and `demo` use temporary directories outside it.
- **Semgrep packaging.** Semgrep was run with `uvx` and is not yet a project dependency.

## Remaining work

Follow [BUILD_PLAN.md](BUILD_PLAN.md): M2 (ClickHouse outbox and history, Semgrep hard-deny rules with offset-based evidence spans), M3 (Senso scoped retrieval, model recommendation, validator, evaluation report), M4 (autonomous poll-detect-quarantine-verify loop with freshness), M5 (minimal timeline page), M6 (recording and submission). ClickHouse, Senso, and model credentials are needed before M2 and M3 can claim sponsor usage.
