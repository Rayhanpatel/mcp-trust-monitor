# MCP Trust Monitor

An agent that monitors changes to MCP tool definitions, evaluates them against an explicit policy, and quarantines affected connections in a managed client with evidence for each decision.

**Status: milestone M3, model review with scoped policy.** A managed MCP client binds trust to exact metadata revisions and refuses calls before transport dispatch unless the current revision is explicitly approved. Two controlled local MCP servers exercise it over real stdio transport.

M2 adds:
- an observation history with provenance;
- deterministic hard-deny detection on tool *descriptions* with pinned Semgrep, which quarantines a still-current revision automatically;
- a local outbox delivered to ClickHouse and read back with event-ID deduplication.

M3 adds:
- scoped retrieval of the operator policy from Senso, verified against `policies/demo-policy.json`;
- an OpenAI `gpt-6-astra` assessment with strict Structured Outputs that can only recommend `review` or `quarantine`;
- deterministic validation of that assessment, with validated quarantines applied through the same guarded transition as hard denials.

Polling and the timeline view are not implemented yet; see [the handoff](docs/HANDOFF.md).

## The product

A tool trusted yesterday can advertise different instructions today. MCP Trust Monitor records that change, blocks the tool until the change is reviewed, determines whether it violates the operator's policy, and verifies that a quarantined connection can no longer receive calls through the managed client.

The hackathon demo will show a controlled server changing its description, a deterministic hard-deny match and a model recommendation citing the applicable policy, a blocked call with an unchanged server-side call count, and an unaffected tool that keeps working. A harmless wording change is not quarantined; it stays blocked in pending review until the operator approves it.

## Read first

- [Product and technical specification](docs/SPEC.md): authoritative requirements with stable IDs
- [Build plan and milestones](docs/BUILD_PLAN.md)
- [Evidence provenance, claim limits, and integration status](docs/EVIDENCE.md)
- [Latest milestone handoff](docs/HANDOFF.md)
- [Example policy](policies/demo-policy.json)
- [Fixed evaluation cases](fixtures/tool_changes.json)

## Setup

Requires [uv](https://docs.astral.sh/uv/) and Python 3.10 or newer (uv downloads 3.12 if needed). Run every command from the repository root.

```sh
uv sync --python 3.12
```

## Run

Scripted walkthrough of the enforcement boundary in a fresh temporary state directory. It launches both demo servers over stdio, approves the baselines, holds a harmless change in pending review, rejects a stale approval, quarantines the mutable server, and restarts the client:

```sh
uv run python -m mcp_trust_monitor demo
```

M2 walkthrough: real Semgrep detects a hard-deny condition, the current revision is quarantined, the next call is verified blocked with the server-side count unchanged, the control still works, and the run's events are delivered to ClickHouse and read back with deduplication. It needs `uv` (Semgrep 1.180.0 runs in an isolated `uvx` environment; set `MCP_TRUST_SEMGREP` to override the command) and the ClickHouse values in `.env`:

```sh
uv run python -m mcp_trust_monitor demo-m2
```

M3 walkthrough, which also needs `SENSO_API_KEY`, `SENSO_POLICY_CONTENT_IDS`, and `OPENAI_API_KEY` in `.env` (`MODEL_NAME` defaults to `gpt-6-astra`):

```sh
uv run python -m mcp_trust_monitor senso-upload   # once: uploads the policy, saves its content ID
uv run python -m mcp_trust_monitor demo-m3        # Semgrep finds nothing; the model decides
uv run python -m mcp_trust_monitor evaluate --json runtime/evaluation-m3.json
```

`demo-m2` remains the fallback that needs only Semgrep and ClickHouse.

Manual steps: `review <server> [--model]` runs one hard-deny review, plus the model stage with `--model`, and never approves, and `deliver` sends pending history events to ClickHouse; it exits nonzero while any remain pending.

Manual operation. State persists in `runtime/state/` (ignored by Git):

```sh
uv run python -m mcp_trust_monitor observe demo/document-lookup   # record the current revision: unreviewed
uv run python -m mcp_trust_monitor status                         # show revision and generation
uv run python -m mcp_trust_monitor approve demo/document-lookup --revision <observed revision> --generation <generation>
uv run python -m mcp_trust_monitor call demo/document-lookup lookup_document '{"title": "Annual report"}'
uv run python -m mcp_trust_monitor received demo/document-lookup  # server-side received tools/call count
uv run python -m mcp_trust_monitor quarantine demo/document-lookup --reason "manual test"
uv run python -m mcp_trust_monitor call demo/document-lookup lookup_document '{"title": "Annual report"}'   # BLOCKED, exit 3
uv run python -m mcp_trust_monitor mutate --scenario private-content-demand   # or: mutate --baseline
uv run python -m mcp_trust_monitor approve demo/document-lookup --revision <revision> --restore           # lift quarantine explicitly
```

`call` exits 0 on success, 1 on a tool error, and 3 when blocked before dispatch. A refused decision, such as a stale or quarantined approval, exits 2. After a failed observation, the server stays in pending review, and `approve` (including `--restore`) is refused until `observe` succeeds again. Run `observe`, check `status`, then approve. To start over, delete `runtime/state/`; that is the only way to discard a quarantine without an explicit restore.

## Test

```sh
uv run pytest
```

The enforcement tests in `tests/test_enforcement.py` launch the demo servers as real stdio MCP subprocesses and compare against each server's own received-request log. Trust-store and revision tests run in process.

Integration smoke test. Copy `.env.example` to `.env` and fill in the ClickHouse values first. It prints check results only, never credentials, and makes no persistent change:

```sh
uv run python scripts/smoke_clickhouse.py
```

## What is here

| Path | Purpose |
| --- | --- |
| `mcp_trust_monitor/managed_client.py` | Managed MCP client and its pre-dispatch trust gate |
| `mcp_trust_monitor/trust_store.py` | Persistent, revision-bound trust state (SQLite) |
| `mcp_trust_monitor/revision.py` | Canonical tool and server revision digests |
| `mcp_trust_monitor/demo_server.py` | Controlled mutable server and unaffected control, with received-request logs |
| `mcp_trust_monitor/__main__.py` | Command line and scripted demo |
| `tests/` | Focused behavior tests |
| `scripts/smoke_clickhouse.py` | ClickHouse Cloud connectivity and permission smoke test |
| `rules/hard_deny.yaml` | Semgrep rules implementing the policy's hard-deny conditions on tool descriptions |
| `mcp_trust_monitor/detector.py` | Pinned, isolated Semgrep runner returning policy IDs and exact evidence spans |
| `mcp_trust_monitor/review.py` | Hard-deny review pass (apply only if current) and evidence-based block verification |
| `mcp_trust_monitor/history.py` | Bounded ClickHouse delivery of the local outbox and deduplicated reads |
| `mcp_trust_monitor/senso.py` | Scoped Senso policy upload and retrieval, verified against the policy file |
| `mcp_trust_monitor/assessor.py` | OpenAI Responses API assessor (strict schema, no tools) and the validator |
| `mcp_trust_monitor/model_review.py` | Model stage: retrieve, assess, validate, apply a guarded quarantine |
| `mcp_trust_monitor/evaluate.py` | Fixed-case evaluation against policy-defined expectations |
| `fixtures/tool_changes.json` | Synthetic baseline, control, and fixed evaluation cases |
| `policies/demo-policy.json` | Operator-authored policy with hard-deny conditions and decision authority |
| `tools/registry_probe_prototype.py` | Inherited metadata-discovery experiment; not a hardened collector |
| `data/evidence_manifest.json` | Count and digest of the earlier research snapshot |
| `.env.example` | Exact variable names for ClickHouse, Senso, and the model |

The saved research snapshot contains 35 server records and 287 tool definitions. It is a sample, not a registry census or a malware dataset, and public registry ingestion is deferred. See the evidence notes for provenance.

## Stack

Python with the official MCP SDK for the managed client and demo servers, and SQLite for local trust state and the history outbox. Implemented in M2:
- ClickHouse Cloud for observation and decision history, delivered from the local outbox.
- Local Semgrep 1.180.0, pinned and run in an isolated `uvx` environment, for hard-deny detection on tool descriptions.

- Senso for scoped policy retrieval: explicit content IDs with `require_scoped_ids`, and no organization-wide fallback.
- OpenAI `gpt-6-astra` for bounded recommendations, called through the official OpenAI Python SDK and the Responses API with strict Structured Outputs. The model can recommend review or quarantine, never approval.

Claude Code is used to build the project and is not part of the runtime.

## Troubleshooting

If `ModuleNotFoundError: No module named 'mcp_trust_monitor'` appears when you run from outside the repository root, run from the root instead. In iCloud-synced folders such as an iCloud Desktop, macOS marks the `.venv` files as hidden, and Python skips hidden `.pth` files, so the editable install is not importable from other directories.

## Contribute and push

Work on a feature branch and stop for review at each milestone; see [CLAUDE.md](CLAUDE.md).

```sh
git switch -c feat/<milestone>
git add <changed-files>
git commit -m "Describe the change"
git push -u origin feat/<milestone>
```

Keep credentials, raw research snapshots, and machine-specific configuration out of Git. This project currently has no selected distribution license; choose one before inviting external code reuse.
