# MCP Trust Monitor: submission summary

**The problem.** An AI agent approves an MCP tool once. Later the tool's server changes the tool's description, for example to instruct the agent to send private workspace notes somewhere they shouldn't go. Nothing forces anyone to notice.

**What we built.** A managed MCP client that:
- binds trust to the exact metadata revision an operator approved;
- blocks calls when changed metadata is observed;
- reviews the change against an explicit operator policy;
- quarantines it on a deterministic hard-deny match or a validated model recommendation;
- proves the quarantine works by attempting a real call, which is refused before it is sent while the server's own call count stays unchanged.

Every step is recorded and delivered to ClickHouse.

## How a change is handled

1. **Observe.** `tools/list` metadata is digested into a revision. An observed change moves the tool from `approved` to `pending_review`, so calls are blocked from that observation onward, before any review.
2. **Deterministic check.** Semgrep runs the policy's hard-deny rules on tool descriptions. A match quarantines the revision automatically, and no model output can override it.
3. **Model review.** The operator policy is retrieved from Senso, scoped to its content ID and verified against the policy file. OpenAI `gpt-6-astra` returns `review` or `quarantine` through a strict schema, with no tools and no ability to approve.
4. **Validation.** Deterministic code accepts the recommendation only if its evidence spans appear verbatim in the metadata, its policy IDs exist, its cited sources were actually retrieved, and its revision, generation, and policy context are still current.
5. **Enforcement and verification.** A validated quarantine is applied through a guarded transition. The next call through the managed client is refused before dispatch, and verification requires the server-side received-call count to exist and stay unchanged. The unaffected control server keeps working.
6. **History.** Each transition and its audit event commit together locally. They are delivered to ClickHouse with bounded retries and read back deduplicated by event ID.

## The four integrations

| Integration | Role | Evidence from 9 October 2026 |
| --- | --- | --- |
| **ClickHouse Cloud** | Append-only history of observations, decisions, quarantines, and verification | `demo-m3`: 18 events delivered and read back. `demo-m2`: 17 delivered in about 0.9 s; after a deliberate duplicate resend, 20 raw rows read back as 17 distinct events in about 0.5 s |
| **Semgrep** (1.180.0, pinned, run with `uvx`) | Deterministic hard-deny rules for the two policy rules | On the fixed cases, matches exactly the policy-defined hard-deny IDs, with exact evidence spans |
| **Senso** | Scoped retrieval of the operator policy | The policy was uploaded as a single content ID. Every `demo-m3` and `evaluate` run retrieved the same 4 passages, all from that ID and verified against the policy file; one timed retrieval took 1.2 s |
| **OpenAI** (`gpt-6-astra`, Responses API) | Bounded policy assessment | Validated `quarantine` under POL-001, with an exact span, for a change no rule detects; one timed call took 7.2 s |

## Measured results

- **`demo-m3`** (live, exit 0, twice, at 15:38 and 15:52 PDT). Semgrep found nothing, and the model recommended quarantine with exact evidence. The quarantine was validated and applied, and `verified_blocked` was recorded with server-side count 1 → 1. The control call succeeded. From the observed change to the verified block took 8.4 s, including Semgrep, Senso, and the model.
- **`demo-m2`** (live, exit 0, the fallback). A Semgrep hard-deny match quarantined the revision. From the observed change to the verified block took about 1.3 s.
- **Evaluation of the six fixed cases** (live, one run). All 6 match their policy-defined expected outcomes, and the expectations were never tuned to the results. The harmless, benign-mention, and schema-only changes stay in pending review. The three violations are quarantined, one of them only by the model.
- **Tests.** 142 automated tests pass. The enforcement proofs use real MCP stdio transport and real Semgrep, and the failure-handling tests mock the external services.

## Limitations

- **Controlled synthetic servers.** Every demo and evaluation uses two local synthetic MCP servers, `demo/document-lookup` and `demo/health-check`, and fixture data labeled `synthetic_fixture`. We make no claims about public MCP servers, and found no malware.
- **Protection only through our managed client.** Enforcement happens in this project's client, immediately before transport dispatch. Agents that call MCP servers through other clients are not protected, and a call already dispatched before a quarantine may have executed.
- **A scripted walkthrough, not continuous monitoring.** The demos run each step once. There is no polling loop, background delivery, or monitoring UI.
- **Scan scope.** Semgrep checks tool descriptions only, so a clean scan means only "no hard-deny match in descriptions". Tool behavior is never assessed.
- **No detection guarantee.** Quarantine requires a hard-deny match or a validated model recommendation. A violation that neither catches is not quarantined; it stays blocked in `pending_review` until an operator decides.
- **Model limits.** The model is nondeterministic; the 6/6 evaluation is a single run. Validation proves the evidence is traceable, not that the reasoning is correct.
- **Approval.** Operators can still approve a pending revision without a scan, by explicit, audited action.
- **Verification evidence** relies on the demo servers' own request logs. Third-party servers have no such counter.

## Reproduce

```sh
uv sync --python 3.12
cp .env.example .env        # fill in ClickHouse, Senso, and OpenAI values
uv run python -m mcp_trust_monitor senso-upload
uv run python scripts/smoke_clickhouse.py
uv run python -m mcp_trust_monitor demo-m3
uv run python -m mcp_trust_monitor demo-m2          # fallback: Semgrep and ClickHouse only
mkdir -p runtime && uv run python -m mcp_trust_monitor evaluate --json runtime/evaluation-m3.json
uv run pytest
```

Requirements, evidence, and the milestone history are in [SPEC.md](SPEC.md), [EVIDENCE.md](EVIDENCE.md), and [HANDOFF.md](HANDOFF.md).
