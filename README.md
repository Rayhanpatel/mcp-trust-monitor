# MCP Trust Monitor

A Python library that keeps MCP tool approval tied to the metadata an operator
reviewed. When the monitor observes changed tool definitions, calls through
the managed client stop until the new revision is reviewed and approved.

**Version 0.2.0a2 is a corrective alpha for local stdio servers.** It provides an
owning async SDK, a CLI, background monitoring, a local operator console, and
decision-record export. Optional Semgrep, OpenAI, Senso and ClickHouse adapters add
policy checks, review recommendations, reviewed precedents and audit delivery.
Memory is off by default.

**Upgrading from 0.2.0a1.** 0.2.0a2 fixes four defects:

- **Launch identity.** A server whose executable symlink was retargeted during
  startup or observation could receive calls under an approval recorded for the
  new target.
- **Detector changes.** A detector-only change did not invalidate approvals or
  selection tokens.
- **Optional descriptions.** A tool without a description failed model review.
- **Export provenance.** Failed assessments exported no returned policy sources.

The first time 0.2.0a2 opens an existing state directory, approved servers return
to pending review once and quarantine is kept. Observe and approve them again. See
the [handoff](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/HANDOFF.md)
and the [compatibility notes](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/LIBRARY.md#persistence-and-compatibility).

## Install

Use Python 3.10 or 3.12 on macOS or Linux. Download the wheel and `SHA256SUMS` from
[the versioned GitHub release](https://github.com/Rayhanpatel/mcp-trust-monitor/releases/tag/v0.2.0a2),
verify its checksum, and install into your application's environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install ./mcp_trust_monitor-0.2.0a2-py3-none-any.whl
.venv/bin/mcp-trust-monitor --help
```

The core library requires no cloud credentials. See the
[library guide](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/LIBRARY.md)
for configuration, CLI commands, optional adapters, ownership and recovery.
Windows and remote MCP transports are outside this release.

## Try the enforcement boundary

The [installed consumer example](https://github.com/Rayhanpatel/mcp-trust-monitor/tree/main/examples)
runs an independently configured synthetic server outside the checkout. It:

1. observes a tool and explicitly approves that revision;
2. completes one protected call;
3. changes the server's metadata;
4. shows the next call blocked, with the server's instrumented call count unchanged.

The example creates its own temporary policy and state. It needs no API key.
Its scripted approval is for a controlled demonstration; a real application must
present the exact revision and generation to its operator before approval.

## Use the SDK

```python
from pathlib import Path
from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor

config = MonitorConfig(
    state_dir=Path("state"),
    policy_path=Path("operator-policy.json"),
    servers={"notes": ServerConfig(
        "notes", "/absolute/path/to/python",
        ("/absolute/path/to/notes_server.py",),
        cwd="/absolute/path/to/server-directory",
    )},
)

async def inspect():
    async with TrustMonitor(config) as monitor:
        observed = await monitor.observe("notes")
        # Display the observed metadata, revision and generation to your operator.
        # Call monitor.approve(...) only after that explicit decision.
        return observed
```

The owning monitor coordinates sessions for one state directory. Protected calls
check approval, current metadata, launch identity, policy and session freshness
before dispatch. A changed definition, failed observation, quarantine or stale
selection blocks dispatch. Calls are never replayed automatically after an
uncertain outcome. See the
[API and lifecycle contract](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/LIBRARY.md#public-api-and-lifecycle).

## What protection means

Only calls made through this library are covered. Observation starts the
configured executable, so configure only processes you are prepared to run.
The library does not sandbox code, verify package integrity, inspect returned
document content, or guarantee that an approved tool behaves safely. An OpenAI
review can recommend review or quarantine; it cannot approve a tool or override a
deterministic hard denial.

Decision-record exports are pseudonymous, not anonymous. Memory requires human
verdicts, exact-content approval, verified private publication and current local
eligibility. It is optional and has no authority to approve calls.

## Learning from reviewed cases (optional Senso memory)

The optional model reviewer can draw on lessons that operators wrote about tool
changes they have already judged. Senso stores the approved lessons privately and
searches them. MCP Trust Monitor decides which lessons count and re-checks
everything Senso returns.

<p align="center">
  <a href="https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/media/senso-learning-loop.mp4"><img src="https://raw.githubusercontent.com/Rayhanpatel/mcp-trust-monitor/main/docs/media/senso-learning-loop.webp" width="800" alt="Animated overview: a changed tool is held for review; an operator records a policy violation, approves the exact lesson text and Senso stores it privately; a later similar change retrieves the lesson after scope and passage checks, and a changed passage is rejected"></a>
</p>

*25-second overview, silent loop.* [Watch the narrated version with sound](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/media/senso-learning-loop.mp4).
It is an animated recreation of the
[offline example](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/examples/learning_loop_offline.py),
with stand-ins for Senso and the model.

```text
 ┌─────────────┐    ┌────────────┐    ┌───────────────────────────────┐
 │ tool change │───▶│ assessment │───▶│ human verdict on the change   │
 └─────────────┘    └────────────┘    └───────────────┬───────────────┘
                          ▲                           ▼
                          │           ┌───────────────────────────────┐
                          │           │ operator-written lesson       │
                          │           └───────────────┬───────────────┘
                          │                           ▼
                          │           ┌───────────────────────────────┐
                          │           │ approval of the exact lesson  │
                          │           │ content (its SHA-256 digest)  │
                          │           └───────────────┬───────────────┘
                          │ later review              ▼
 ┌────────────────────────┴───────┐   ┌───────────────────────────────┐
 │ scoped retrieval of approved   │◀──│ private Senso storage, active │
 │ lessons in a LATER assessment  │   │ only after exact read-back    │
 └────────────────────────────────┘   └───────────────────────────────┘
 Tool approval (approve / restore) is a separate operator
 decision outside this loop.
```

- **The loop:**
  1. An operator records whether a reviewed change actually violated the policy
     (violation, non-violation or uncertain), tied to the exact assessment they
     reviewed.
  2. They write a short lesson and approve its exact text.
  3. Later assessments of other changes can retrieve and cite it.
- **Before a lesson is relied on:**
  - its stored copy must match the approved digest on read-back;
  - it must belong to this monitor's memory scope and the current policy;
  - changed or out-of-scope content fails that assessment;
  - a revoked lesson is excluded at once, and an assessment still using it is
    discarded as stale.
- **Lessons never approve tools.** A changed tool runs again only after an operator
  explicitly approves its new revision, with or without memory. Approving a lesson
  makes its text eligible for retrieval; it does not make the lesson correct.
- **Status:** optional and off by default. In the historical 12 October experiment
  (before later repairs), eight synthetic cases were each run three times per mode.
  Memory-on and memory-off both matched all 24 expected outcomes, so no accuracy
  improvement was shown.

Read the [learning-loop walkthrough](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/SENSO_LEARNING_LOOP.md).
Or run the offline example from a source checkout, with local stand-ins and no keys:
`uv sync --locked`, then `uv run python examples/learning_loop_offline.py`.

## Verification and evidence

The 0.2.0a2 code passed 645 tests on each of Python 3.10/3.12 across local macOS
ARM64 and Linux ARM64, plus installed-wheel, typing and cross-version state checks.
Every repaired defect has regression tests that fail on the 0.2.0a1 code. The
[CI workflow](https://github.com/Rayhanpatel/mcp-trust-monitor/actions/workflows/ci.yml)
checks the release source on hosted Linux AMD64 and macOS ARM64. Exact hosted
results and artifact hashes belong to the release's verification record.

The [release evidence](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/RELEASE_RESULT.md)
distinguishes current runtime checks from older live service experiments. The
historical eight-case memory comparison tied at 24/24 per mode; it did **not**
demonstrate an improvement. Private lesson records, service identifiers and raw
provider data are not included in the public release.

## Develop

```sh
uv sync --locked --python 3.12
uv run pytest -q
uv build
uv run python scripts/check_distribution.py
uv run python tests/typing/check.py
```

Tests use synthetic state and no cloud keys. Detector tests run pinned Semgrep
1.180.0 in an isolated `uvx` environment. Node.js is required for the console's
JavaScript tests; set `MTM_REQUIRE_NODE=1` to make its absence fail the suite.

Read the [specification](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/SPEC.md),
[console guide](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/CONSOLE.md),
and [handoff](https://github.com/Rayhanpatel/mcp-trust-monitor/blob/main/docs/HANDOFF.md)
before changing the trust boundary. Historical scripted demos remain available as
`python -m mcp_trust_monitor.historical_demo`; they use separate demo state and
are not the generic library CLI.

MIT licensed. Report bugs through
[GitHub issues](https://github.com/Rayhanpatel/mcp-trust-monitor/issues).
