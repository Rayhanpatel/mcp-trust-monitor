# MCP Trust Monitor

An agent that monitors changes to MCP tool definitions, evaluates them against an explicit policy, and quarantines affected connections in a managed client with evidence for each decision.

**Status: milestone M1, the enforcement boundary.** A managed MCP client binds trust to exact metadata revisions and refuses calls before transport dispatch unless the current revision is explicitly approved. Two controlled local MCP servers exercise it over real stdio transport. Observation history (ClickHouse), hard-deny detection (Semgrep), scoped policy retrieval (Senso), model review, and the timeline view are not implemented yet; see [the handoff](docs/HANDOFF.md).

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

`call` exits 0 on success, 1 on a tool error, and 3 when blocked before dispatch. A refused decision, such as a stale or quarantined approval, exits 2. To start over, delete `runtime/state/`; that is the only way to discard a quarantine without an explicit restore.

## Test

```sh
uv run pytest
```

The enforcement tests in `tests/test_enforcement.py` launch the demo servers as real stdio MCP subprocesses and compare against each server's own received-request log. Trust-store and revision tests run in process.

## What is here

| Path | Purpose |
| --- | --- |
| `mcp_trust_monitor/managed_client.py` | Managed MCP client and its pre-dispatch trust gate |
| `mcp_trust_monitor/trust_store.py` | Persistent, revision-bound trust state (SQLite) |
| `mcp_trust_monitor/revision.py` | Canonical tool and server revision digests |
| `mcp_trust_monitor/demo_server.py` | Controlled mutable server and unaffected control, with received-request logs |
| `mcp_trust_monitor/__main__.py` | Command line and scripted demo |
| `tests/` | Focused behavior tests |
| `fixtures/tool_changes.json` | Synthetic baseline, control, and fixed evaluation cases |
| `policies/demo-policy.json` | Operator-authored policy with hard-deny conditions and decision authority |
| `tools/registry_probe_prototype.py` | Inherited metadata-discovery experiment; not a hardened collector |
| `data/evidence_manifest.json` | Count and digest of the earlier research snapshot |
| `.env.example` | Placeholders for planned integrations |

The saved research snapshot contains 35 server records and 287 tool definitions. It is a sample, not a registry census or a malware dataset, and public registry ingestion is deferred. See the evidence notes for provenance.

## Stack

Python with the official MCP SDK for the managed client and demo servers, and SQLite for local trust state. Planned: ClickHouse for observation and decision history, local Semgrep for hard-deny detection, Senso for scoped policy retrieval, and a model for bounded recommendations.

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
