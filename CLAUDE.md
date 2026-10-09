# CLAUDE.md

## Authoritative sources

- `docs/SPEC.md`: the requirements, with stable `REQ-…` IDs. It wins over every other document.
- `docs/BUILD_PLAN.md`: milestone order, exit conditions, and cut order.
- `docs/EVIDENCE.md`: data provenance, claim limits, and integration status.
- `docs/HANDOFF.md`: what the latest milestone completed and what remains.
- `policies/demo-policy.json` and `fixtures/tool_changes.json`: the operator policy and the fixed evaluation cases.

Do not restate the spec elsewhere. Reference requirement IDs in code docstrings, tests, and handoffs.

## Milestone and review workflow

1. Work on a feature branch; never commit to or merge into `main` without review.
2. Implement one milestone at a time, as scoped in the build plan. Do not start the next one.
3. Write focused tests for observable behavior. Use real MCP transport for enforcement proofs; mock-only tests are not proof.
4. Never weaken an acceptance criterion or edit a fixed evaluation case to make a run pass. Surface contradictions that would change product behavior instead of resolving them silently.
5. Run `uv run pytest`, update `docs/HANDOFF.md` (requirement IDs completed, changed files, commands and results, limitations, remaining work), commit, and stop for independent review.

## Rules

- Never print, log, or commit secrets. Report integrations as working only after an actual successful call; label fixture data `synthetic_fixture`.
- The model may recommend review or quarantine but never approves and never overrides a deterministic hard denial.
- Run commands from the repository root: `uv sync`, `uv run pytest`, `uv run python -m mcp_trust_monitor --help`.
