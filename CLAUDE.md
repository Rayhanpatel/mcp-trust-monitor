# Contributor instructions

## Authoritative sources

- `docs/SPEC.md`: requirements with stable `REQ-…` IDs; authoritative on behavior.
- `docs/LIBRARY.md`: public API, ownership, failure modes and compatibility.
- `docs/HANDOFF.md`: reviewed implementation and development handoff.
- `docs/RELEASE_RESULT.md`: current validation and historical-evidence limits.
- `docs/RELEASE_REQUIREMENTS.md`: requirement-to-test mapping.
- `docs/BUILD_PLAN.md`: retained historical development sequence.

Reference requirements in code, tests and handoffs. Do not duplicate or silently
weaken the specification. Work on branches and obtain independent review before
merging into main or publishing artifacts.

## Implementation and verification

- Use explicit local stdio configuration. Keep state outside the installed package
  and outside cloud-synced directories. Preserve user state and frozen evidence.
- Keep public ownership/API contracts stable. CLI and console operations must use
  the owning SDK rather than independent private-table writes.
- Add meaningful tests for observable behavior. Enforcement proofs require real
  transport; mocks alone do not prove nondispatch or server receipt.
- Run `uv sync --locked`, relevant tests, and `uv run pytest`. Node.js is required
  by the console JavaScript checks (`MTM_REQUIRE_NODE=1` in CI).
- Release checks additionally build fresh distributions, install outside the
  checkout, and check the public typing consumer. Follow the pinned workflows.
- For documentation-only changes, check requirement references, links, consistency
  and `git diff --check`; do not claim new runtime validation.

## Trust, memory and evidence

- Never print, log, commit or publish secrets, private approval records or raw
  service identifiers. Synthetic examples are explicitly labeled.
- A model can recommend review or quarantine, never approve a tool or override a
  deterministic hard denial. Enabled adapter failure must not silently weaken a
  required assessment.
- Memory is opt-in and off by default. A human verdict and exact lesson-content
  approval are separate requirements. Only verified, private, locally eligible
  lessons may contribute; restore is not a correctness verdict.
- Preserve frozen evaluation cases and failed results. Do not turn held-out
  expectations into reviewed verdicts or rerun an experiment to improve its score.
- Dispatch means transport handoff and a possible side effect, not proof of server
  receipt. Generic refusals establish local nondispatch; an independent server
  counter is separate evidence.
- The historical demos are `python -m mcp_trust_monitor.historical_demo` and use
  separate state. The generic CLI is `python -m mcp_trust_monitor`.
- OpenAI is the optional runtime reviewer; implementation tools are not runtime
  dependencies. Historical live outcomes do not certify a current service account.
