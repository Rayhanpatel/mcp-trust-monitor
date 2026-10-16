# Library guide: 0.2.0a2 corrective alpha candidate

MCP Trust Monitor owns a set of explicitly configured local stdio MCP sessions.
It exposes only approved, fresh tool definitions and checks durable trust again
immediately before a tool request enters the transport. Metadata observation
starts the configured process. This is not a sandbox, a code signature, a proxy
for other clients, or a guarantee that an approved tool behaves safely.

## Install and configure

Build with `uv build`, then install the wheel with pip or uv in the consuming
application's environment. Core installation needs no cloud keys. The `openai`
extra installs the optional model SDK; `semgrep` installs the YAML parser for
rule configuration. The Semgrep executable runs separately through pinned uvx
or an explicitly configured command, avoiding an MCP dependency conflict.

The library uses explicit paths and never discovers a repository `.env` file.
Example JSON for the generic CLI:

```json
{
  "state_dir": "./state",
  "policy_path": "./operator-policy.json",
  "poll_interval": 30,
  "timeout_seconds": 15,
  "servers": [
    {
      "server_id": "public-notes",
      "command": "/absolute/path/to/python",
      "args": ["/absolute/path/to/your_server.py"],
      "cwd": "/absolute/path/to/server-directory",
      "env": {"LOG_LEVEL": "warning"},
      "secret_env": {"API_KEY": "MY_SERVER_API_KEY"}
    }
  ]
}
```

Configuration paths resolve beside the config file:

- relative `state_dir`, `policy_path`, `detector_binding` and server `cwd` values
  are config-relative;
- an omitted or `null` server `cwd` is the config file's own directory;
- relative executable `command` paths containing a native path separator (such as
  `./server` or `bin/server`), plus `.` and `..`, are config-relative even when
  the server's `cwd` names another directory;
- leading `~` in a path, including `command`, expands to the user's home directory;
- executable paths become absolute without dereferencing symlinks, preserving
  virtualenv interpreters such as `.venv/bin/python`; existing absolute paths are retained.

An explicit executable path therefore selects the same process profile and launch
identity from any invoking directory under the same home/environment settings.
A bare executable name such as `python3` retains lookup using the invoking
process's `PATH` when configuration is loaded. Different `PATH` values, or relative
entries in `PATH`, can select different executables; use an absolute or
config-relative command path for an invoking-directory-independent profile.
Arguments are passed literally without shell or tilde expansion, so a relative
argument such as `data.json` is read by the server relative to its `cwd`.
`env` is non-secret configuration. `secret_env` maps a child
variable to an environment reference that the caller supplies; only the reference
name contributes to identity. Do not put secrets in command arguments or plain `env`.
Keep `state_dir` on local storage that is not synced by iCloud or similar services.

The optional `detector_binding` names an operator-authored detector binding JSON
file (format under Optional adapters). Every owner of one state directory, the CLI
and any SDK application alike, must declare the same policy and detector: an owner
that declares a different pair, or none, makes a genuine decision-context change and
returns approvals to pending review (see Public API and lifecycle). Owning commands,
including `quarantine`, refuse to start while the named binding file is missing or
invalid; keep it readable, because removing `detector_binding` to regain control is
itself a change that resets approvals.

**Compatibility (0.2.0a1 repair).** Earlier candidates resolved an omitted `cwd`
and relative executable paths against the invoking directory. Those paths now
resolve beside the config, and a leading `~` in `command` now expands to the user's
home directory. A changed working directory or executable changes launch identity;
existing approvals then fail closed (`launch_identity_changed`, pending review)
until the server is observed again and explicitly re-approved. Absolute executable
paths, bare-name `PATH` lookup, literal arguments and credential-reference names
keep their previous semantics.

The SDK is different: `ServerConfig(cwd=None)` still means the process working
directory at the moment `MonitorConfig` is constructed. Pass an explicit `cwd` when
the server reads relative paths.

## Public API and lifecycle

```python
from pathlib import Path
from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor

config = MonitorConfig(
    state_dir=Path("state"), policy_path=Path("operator-policy.json"),
    servers={"notes": ServerConfig("notes", "/absolute/python", ("/absolute/server.py",))},
)

async def inspect():
    async with TrustMonitor(config) as monitor:
        record = await monitor.observe("notes")
        # Present the exact metadata, revision and generation to the operator.
        # Only after their explicit decision:
        await monitor.approve("notes", revision=record.observed_revision,
                              expected_generation=record.generation, actor="operator")
        entry = monitor.catalog("notes")[0]
        result = await monitor.call_tool("notes", entry.definition["name"], {},
                                         selection=entry.selection)
```

`status`, `catalog`, `events`, and `health` are synchronous snapshots.
`observe`, `approve`, `restore`, `quarantine`, `call_tool`, `observe_and_call`,
`reload_policy`, `review_once`, `start_monitor`, `stop_monitor`, and `aclose` are
async. The caller owns the event loop. `new_session()` creates an independent
transport session within the same owner; it shares durable trust and server
coordination, but must establish its own fresh observation.

Approve and restore decisions name an exact revision and generation. Approvals,
generations and selection tokens are bound to the owner's **decision binding**
(`TrustMonitor.decision_binding`): the policy binding plus the active detector
binding, or `disabled`. The detector part covers its declared policy digest, rules
digest, rule mapping and scanned fields, not the rules file's location. A genuine
change, by `reload_policy` or by reopening the owner, is a different policy file or
a different detector declaration, including enabling or disabling detection. It
advances every server's generation, whatever its state, and records
`decision_context_invalidated`; quarantine stays quarantined and approvals bound to
the old pair return to pending review. Inputs and selection tokens prepared before
the change are then refused (`StaleDecisionError`, `CallBlocked`): read the status
again, review the current state and decide with the new generation. Reloading the
same pair, or reopening with an unchanged policy and equal detector declaration,
changes no generation. `TrustMonitor.policy.binding` still identifies the policy
document alone; lesson scope and assessment contexts use it unchanged.

Catalog entries are immutable and expose only name, description, and inputSchema.
Selection tokens bind server, launch profile, revision, generation, decision
binding and session. A token cannot silently select a replacement. Tokenless
calls use
latest-approved semantics after every other gate passes.

Each session is bound to the launch identity captured immediately before its
process started. If the configured identity changes while that process starts or
is observed (for example, an executable symlink is retargeted), the observation
fails (`observation_failed`) and its metadata is not recorded. A session whose
identity differs from the trust record's never dispatches and contributes no
catalog entries: its calls are refused as `launch_identity_changed`, which
`health()` also reports as its freshness, until a new observation under the
current identity and an explicit approval. The configured path is still the one
launched, so virtualenv interpreter symlinks keep their meaning. Launch identity is
path and configuration identity, not a code signature: a target swapped and
restored while a process starts is not detected.

An ordinary call never launches or refreshes a server. A new process/session
needs `observe_and_call`, which checks persisted approval before launch and
checks all gates again after observing. Session freshness expires after two
poll intervals even when monitoring is stopped. Notifications invalidate session
freshness immediately; polling covers servers that do not notify.

`CallBlocked` means refusal before dispatch. `ToolOutcomeUnknown` means a request
may have taken effect but no definite response was received. No automatic tool
replay occurs. Application cancellation also cannot undo an already sent request.
`DispatchedCallUnrecorded` means the call ran and its `result` is attached, but
the local completion audit could not be committed because storage faulted; do
not replay it. The final authorization and the hand-off of a request to the stdio
transport are one step, so a quarantine or policy reload either precedes the
authorization or follows the request. A server that stops reading its input never
holds the trust lock: the call waits up to `timeout_seconds` and is then refused
as `transport_backpressure` without being sent, and refreshing such a server is
an observation failure. A call on a transport whose server has exited is refused
at once as `transport_closed`.

A `TrustMonitor` that was opened is single-use; create a new instance to own the
state directory again (an object whose open failed may retry). `aclose()` may be
awaited repeatedly or concurrently: every caller waits for the same shutdown. It
closes owned transports before waiting for cancelled work and releases ownership
only after every owned server process has been reaped. A call still in flight when
the owner closes, or when storage faults, is not cancelled: it raises
`ToolOutcomeUnknown` if it was sent, or `CallBlocked` (`client_closed`) if not;
shutdown never waits for the caller's own task.
`ShutdownIncompleteError.ownership_released` says whether cancelled work outlived
`shutdown_timeout` (ownership released, unclean marker kept) or a transport could
not be confirmed closed (ownership kept until a later `aclose()`).

`start_monitor()` is refused with `TrustError` once `aclose()` has begun, and with
`StorageFaultError` after a storage fault; start and stop are serialized.
`stop_monitor()` stops scheduling at once and waits at most `shutdown_timeout` for
the cancelled tasks without depending on them acknowledging cancellation; it raises
`asyncio.TimeoutError` if one is still running, keeps tracking it, and `aclose()`
joins it again and reports `ShutdownIncompleteError` if it remains. A stop followed
by a start resumes monitoring. Neither `aclose()` nor the storage-fault shutdown
waits for cancelled work before closing owned transports, so a review or
application task that ignores cancellation cannot keep a server process alive.
Each transport gets 5 s for the MCP stdio shutdown and 5 s more after
cancellation; one that still has not finished keeps ownership
(`ownership_released=False`). Shutdown cancels each task once.

The monitor coalesces observations per server, so a slow or continuously
notifying server occupies at most one of `max_concurrency` workers; with a single
worker, other servers wait for it. Automatic assessment of an unchanged failed or
stale context backs off from the poll interval and stops after
`review_max_attempts` (default 3); a changed revision, launch identity or policy,
or `reset_review_retries()`, re-arms it, and observation continues meanwhile.
`AssessmentNotReady` means no current session observation exists to assess yet.

## CLI and local console

```sh
mcp-trust-monitor --config config.json observe public-notes
mcp-trust-monitor --config config.json approve public-notes --revision REVISION --generation GENERATION
mcp-trust-monitor --config config.json call public-notes TOOL --refresh --arguments '{}'
mcp-trust-monitor --config config.json status
mcp-trust-monitor --config config.json export > decision-records.json
mcp-trust-monitor --config config.json export --pseudonym-key-file export.key > linked.json
mcp-trust-monitor --config config.json serve
```

`python -m mcp_trust_monitor` runs this same CLI. The historical hackathon walkthroughs are
`python -m mcp_trust_monitor.historical_demo`; it refuses library state and writes only
directories marked `historical-demo-state`, and only while it owns them.

`serve` runs monitoring and the console within the owner process. The printed
loopback URL includes the local per-run token; keep it with the intended operator.
Read-only status/events can coexist with an owner. A different CLI process has no
fresh transport, so its protected catalog is empty. Mutating CLI commands refuse
while another process owns the state directory. The generic JSON CLI intentionally
configures local-only operation; applications explicitly compose cloud adapters
through the SDK. With a `detector_binding`, `review`, `monitor` and `serve` run the
deterministic scan locally through the pinned `uvx` Semgrep 1.180.0 command, which
may download Semgrep on first use; set `MCP_TRUST_SEMGREP` to a verified local
executable for offline operation. Read-only commands do not read the binding file.
`review` prints its result and exits 1 when the detector or assessment failed or
was stale; nothing is approved either way. `call` exits 3 when refused before
dispatch and 4 when the request
was dispatched but its outcome is unknown or unrecorded (`"dispatched": true`).
Dispatched means the request was handed to the stdio transport and may have taken
effect; it is not proof that the server received it. Never retry such a call
blindly. `export` emits the versioned, sanitized decision-record schema described
below.

`monitor` and `serve` treat SIGTERM as a routine stop: monitoring stops, the
console stops accepting connections, owned server processes are reaped and
ownership is released. A clean stop exits 0 and removes the unclean marker, so
approvals survive a restart. If the stop is not clean, the command exits 5,
prints one JSON object on stderr (`error`, `recovery_required`, a fixed
`message`, and `ownership_released` when known) and keeps the unclean marker, so
the next owner runs recovery and approved servers return to pending review. If an
owned transport cannot be confirmed closed, the process keeps ownership and
retries for `shutdown_timeout`, then exits 5 with `ownership_released: false`; only
the process exit then releases the state-directory lock. SIGINT still exits 130.
SIGKILL, and SIGTERM on Windows (unsupported), are unclean exits. Allow about
`2 × shutdown_timeout + 15 s` before escalating to SIGKILL. Any other command
whose close is incomplete also exits 5. If that incomplete close interrupted a
`call`, the exit-5 JSON also carries the call's own classification: `call_error`
(`ToolOutcomeUnknown`, `DispatchedCallUnrecorded` or `CallBlocked`), plus
`dispatched: true` (and the known result on stdout) for a call handed to the
transport, or `reason` for a refusal. Check `dispatched` before retrying. A task
that ignores cancellation cannot keep the process alive: after a bounded teardown
it exits with the classified status. The first SIGINT cancels the running command
so its owner closes as it unwinds; a second one interrupts at once.

## Decision-record export and privacy

`export_decision_records(source, *, pseudonym_key=None)` and the CLI `export`
command read local events and observations only. The CLI opens the database
read-only and never takes ownership, so the database file is unchanged. Beside a
store that no owner has open, SQLite may leave its coordination files: an empty
`-wal` and a `-shm` index. Raw metadata, arguments, passages, lesson text,
explanations and error messages are omitted. Each record keeps the recommendation, validation, applied
action and dispatch/verification level as separate fields. Policy-source
provenance keeps requested, returned and cited source IDs separate on failed and
stale assessments too: returned IDs are present when scoped policy retrieval
completed and `null` when it did not, and cited IDs exist only for a validated
assessment. A failed attempt with memory enabled reports its memory `enabled`
flag and a `status` of `retrieval_failed` or `not_attempted`. Exported decisions are
not proof of classification correctness or independently verified prevention.
`dispatch_started` and `outcome_unknown` mean a request was handed to the transport
and may have taken effect, not that the server is proven to have received it.

The export is **pseudonymous, not anonymous**:

- **Identifiers are keyed pseudonyms.** Every identifier becomes `pid:` followed by
  the hex HMAC-SHA256 of the value. This covers server, client, actor, tool, policy
  and rule, Senso content, model, response and run identifiers, and the library's
  own event, observation, call, verdict and lesson IDs. No shape is exempt: a
  UUID-shaped server ID is pseudonymized like any other. `policy_binding_digest`
  and `review_context_digest` are keyed the same way, because the strings they
  stand for embed such identifiers.
- **Default scope: one export.** Each export draws a fresh random 32-byte key that
  is never stored or printed. Identifiers and links (`links`, `observation_id`,
  call IDs) resolve within that export. Two exports of the same records share no
  pseudonyms, and a guessed identifier cannot be confirmed without the key.
- **Optional operator key.** `pseudonym_key` (bytes) or the CLI's
  `--pseudonym-key-file PATH` (the file's exact bytes, read-only) must contain at
  least 32 bytes. With the same key, the same stored records produce identical
  `records` and `observations`, so pseudonyms link across that operator's exports;
  a different key gives unrelated pseudonyms. Generate it randomly, for example `head -c 32 /dev/urandom > export.key`,
  and keep it private (`chmod 600`). Anyone holding the key can confirm guessed
  identifiers. The export contains pseudonyms of predictable values, such as
  library actor names, so a short or guessable key can be tested offline.
- **No key material is exported.** The `pseudonymization` envelope records only
  `method` (`hmac-sha256`), `scope` (`export` or `operator_key`) and a random
  `export_id` that is not derived from the key. There is no key fingerprint or
  verifier, so the export does not say which operator key was used; track that
  yourself.
- **Retained values.** Recorded SHA-256 content digests are retained for
  traceability: metadata revisions, launch identities, and policy, rules and lesson
  digests. Anyone holding candidate content, such as tool metadata, a policy file
  or a launch profile (command, arguments, working directory, non-secret
  environment and secret reference names), can confirm a guess against them. These
  digests, and timestamps, generations, versions, token counts and the number and
  order of events, can also link exports made under different keys.

**Compatibility.** Schema version 2 replaces version 1's unsalted
`id:sha256:` identifiers and verbatim UUIDs with `pid:` pseudonyms and adds the
`pseudonymization` envelope. Record fields are otherwise unchanged. Every
identifier value changes, so version 2 identifiers do not match version 1 values.
Consumers that compared exported IDs with raw store IDs, or across default exports,
must instead resolve links within one export, or use an operator key for joins
across exports.

## Optional adapters and memory

`DetectorBinding` binds a rules file's exact digest and actual rule inventory to
the policy digest. Unknown, omitted, or incompatible rule mappings are rejected
even when a scan would find no match. Activating a different binding is a genuine
decision-context change (see Public API and lifecycle). A custom detector object
must declare a string `rules_digest`; one that does not is refused before
activation. `OpenAIReviewer` retrieves verified scoped
Senso policy and validates strict model output; models can only review or request
quarantine. A tool whose optional description is absent is reviewed normally; its
description adds no text to the bounded precedent query, while a description of
any other non-string type fails the attempt. `ClickHouseSink` sends local outbox
batches outside enforcement locks.
Disabled integrations are reported as disabled. Adapter failures do not approve
changed metadata, and cannot erase a locally committed quarantine.

`examples/reviewed_monitor.py` composes the model, scoped Senso retrieval, optional
history and console. Supply `--config` and `--env-file` explicitly. Enable history
with `--clickhouse`; enable reviewed memory with `--memory --capability-evidence
PROBE.json`. Deterministic scanning needs a binding: the config's
`detector_binding`, or `--detector-binding BINDING.json`, which replaces it; with
neither, it is reported disabled. Declare it in the config when the CLI also owns
the same state, so both declare the same pair. The binding JSON has `rules_path`
(relative to that binding file), `policy_digest`, `rules_digest`, `rule_mapping`
(Semgrep rule IDs to policy IDs) and optional `scanned_fields`. This is an
explicit operator
declaration and is validated against the actual policy and rule inventory.

`MemoryService` shares the monitor's store and policy. Its explicit lifecycle is
`record_verdict → draft_lesson → preview → approve_lesson → publish`. Uncertain
verdicts cannot produce eligible lessons. Approvals bind exact sanitized body
digests. `SensoMemoryBackend` requires successful capability evidence. A lesson
becomes active only after private publication, processing and exact body/version
read-back. Unknown upload outcomes remain inactive and are never blindly retried;
`reconcile` names the candidate node explicitly. `revoke_lesson` immediately
removes local eligibility without lifting any quarantine.

Memory is opt-in. An enabled integrity or retrieval failure fails that assessment;
there is no silent policy-only fallback. Empty valid retrieval is recorded as no
precedent contribution. Policy sources and precedent citations remain separate.
Snapshots are checked across network work and within the final decision transaction.

## Persistence and compatibility

One process owns mutation and dispatch per state directory. An unclean owner
marker survives crashes and storage failures; reopening invalidates prior approval
for every client ID stored in that directory, not only the one reopening it, and
requires valid observation plus explicit approval/restore. Quarantine and
observation-failure prerequisites survive migration and recovery. A future schema
is refused before database or owner-marker mutation. Read-only access never migrates.
The current schema is version 4, which adds the per-client record of the last
activated policy; upgrading from version 3 happens atomically on the first owning
open. Binaries that support only version 3 (including the earlier `6e21602` and
`8f74a74` candidates) refuse an upgraded store, so keep a backup if you may need
them.

**Compatibility (0.2.0a2 corrective candidate).** Earlier releases, including the
published 0.2.0a1, bound approvals to the policy alone and did not record which
detector was active. The first owning open by 0.2.0a2 therefore counts as a genuine
decision-context change, with or without a detector: approved servers return to
pending review, every generation advances and quarantine is preserved. Observe,
review and approve again; later opens with the same policy and detector change
nothing. The store schema stays 4. An earlier binary can still open the state, but
its policy-only binding never equals a 0.2.0a2 decision binding, so it also returns
0.2.0a2 approvals to pending review: decisions made by either version fail closed
under the other. Selection tokens and console intents from before the upgrade are
stale.

Back up a stopped owner's complete state directory before an upgrade. Older
binaries must use separate state; restoring a compatible backup is the downgrade
path. Never edit `user_version` to make a database look older.

The integration is pinned to MCP Python SDK 1.30.x and local stdio. Local
verification covers macOS ARM64 and Linux ARM64 on Python 3.10/3.12. Hosted CI
runs Linux AMD64 and macOS ARM64 on those Python versions; exact successful runs
and final artifact hashes are recorded with the GitHub release. See
[RELEASE_RESULT.md](RELEASE_RESULT.md) for evidence scope.

Windows is not supported by the current POSIX owner lock. Remote transports,
OAuth, multiple writer processes, hosted accounts and distributed enforcement are
outside this release. The distribution is MIT licensed and explicitly alpha.
The historical cloud experiment does not establish broad model accuracy, content
filtering, arbitrary executable safety or current service availability.
