# Local operator console

The console runs inside the process that already owns a `TrustMonitor`. It reads
real records and invokes that monitor's guarded operations; it never opens a
second writer. It binds only to `127.0.0.1` and uses no external assets or services.

```python
import asyncio
from mcp_trust_monitor.console import ConsoleServer

# `monitor` is the open TrustMonitor owned by your application.
async with ConsoleServer(monitor) as console:
    print(console.url)  # Local credential: share only with the intended operator.
    await asyncio.Event().wait()
```

The CLI's `mcp-trust-monitor --config C serve` runs this console in the owner. SIGTERM
stops it routinely: the console stops accepting connections, then the owner closes
and reaps its servers; see the CLI section of [LIBRARY.md](LIBRARY.md) for exit codes.

Pass `memory=memory_service` to enable correctness verdicts and lesson review.
Pass `publication_backend=backend` as well to enable explicitly requested private
lesson publication. The service must share this monitor's store and policy.
The console does not create or configure cloud adapters implicitly.

The screen shows configured servers, trust state, covered before/after metadata,
current protected catalog, observation/monitor health, policy and precedent
evidence in recorded events, correctness verdicts, lesson state, local audit
delivery and recorded verification events. Missing evidence is displayed as
unavailable. Synthetic origins remain labeled. A raw metadata view is operator
inspection and never substitutes for the approved catalog.

Approval and restore act only on the state you reviewed (REQ-TRU-02, REQ-UI-02).
The first time the page shows a server, it pins that view as your review: server,
trust state, revision, generation, active decision binding (policy plus detector,
shown as "Active policy"), launch identity and the covered metadata shown. The
five-second refresh updates the status figures but
never this target. When the current state differs, the page lists each difference,
shows the new metadata separately and disables approve and restore until you
choose **Review the current state**, which re-pins to what is now shown. This
includes changes caused by your own actions, such as observing new metadata. The
request carries the pinned `revision`, `generation`, `policy_binding` and
`launch_identity`. The console backend refuses a supplied policy binding or launch
identity that is no longer current, and the SDK refuses a stale revision or
generation. A genuine policy or detector change advances every server's
generation, so an action prepared before it is refused even if the page has not
refreshed yet.
Quarantine is server-scoped. Observe starts the configured
stdio process; this library is not a process sandbox. The page never runs tool
calls to probe protection and never infers `verified_blocked` from a quarantine.

The URL carries a per-run random token in its fragment; requests send it in an
authorization header. Tokens are not saved to browser storage or request logs.
Sensitive reads require authentication. Mutations additionally require the exact
same Origin and a CSRF token obtained through the authenticated state endpoint.
Host headers must match the bound address and port. There is no CORS permission.
The UI renders untrusted text with `textContent`, under a CSP that disallows
inline scripts, framing and external resources. HTTP errors never echo provider
exception text, which might contain credentials.

Correctness verdicts are distinct from approval/restore. A verdict draft is pinned
to one observation: its assessment choices, the displayed observation metadata and
assessment evidence, the verdict and the rationale change together or not at all.
After a newer observation, the page asks you to **Keep this draft** (the earlier
observation and its assessment remain a valid pair) or **Start a new draft for the
latest observation**, which clears the assessment, verdict and rationale. You can
also start a draft for an older observation of the selected server by ID. The
assessment choices come from the store, with the same rule `record_verdict`
applies, not from the evidence timeline, which shows only the latest 200 events:
the snapshot carries `latest_verdict_context` for each server's latest
observation, and the `verdict_context` action (authenticated, same-origin and
CSRF-protected, like every action) returns it for a named observation. Draft lessons
require an operator summary. The exact body and digest are previewed before approval, and
publication is a separate action. Revocation changes local eligibility and cannot
undo already completed calls or restore quarantined tools. An HTTP timeout has an
unknown action outcome: refresh state before deliberately repeating the action.

`tests/test_console.py` verifies the HTTP boundary, owner-thread execution, real
SQLite records, revision/generation protection, digest forwarding and asset
behavior without cloud calls. `tests/test_console_review_binding.py` executes the
shipped `app.js` in a minimal Node DOM harness (`tests/helpers/console_dom_harness.js`,
not a browser engine) against a live console, a real `TrustMonitor`,
`MemoryService` and stdio server. It skips without Node unless
`MTM_REQUIRE_NODE=1` is set. Installed-wheel and live adapter evidence are
separate release checks; this document does not claim them by itself.
