# Core integration contract

The public lifecycle is `async with TrustMonitor(MonitorConfig(...)) as monitor`.
Configuration explicitly supplies state, policy and local stdio launch profiles. It
performs no import-time I/O and no automatic credential discovery. `secret_env`
maps child environment names to caller environment reference names; identity stores
only those reference names. Plain `env` values are declared non-secret configuration.
Do not put secrets in executable arguments. Launch identity is a canonical digest
of resolved executable, arguments, cwd, non-secret environment and references. It
is not a binary signature.

SDK operations: async observe, approve, restore, quarantine, call_tool,
observe_and_call, reload_policy, review_once, start_monitor, stop_monitor, aclose;
synchronous status, catalog, events, health. `new_session` constructs another
transport session sharing the same owning store and per-server locks. It launches
nothing. Catalog entries expose covered fields only, are recursively immutable,
and provide `as_dict()` for serialization. Selection tokens bind server, launch
identity, revision, generation, policy and backing session. Tokenless calls use the
latest currently approved revision after all gates pass.

Ordinary SDK calls never establish a transport. `observe_and_call` is the explicit
refresh path; its precheck rejects non-approved state before launch. Session
freshness is two poll intervals even when the monitor is stopped. Notifications
increment a dirty epoch synchronously and enqueue bounded, coalesced refresh work.
A stream wrapper on tested MCP 1.30 coordinates final authorization and enqueue
under the server lock, releasing it before response waiting. No call replay occurs.
Ambiguous failure raises ToolOutcomeUnknown; cancellation stays CancelledError and
is audited as outcome_unknown. Legacy ManagedClient keeps its historical implicit
refresh behavior unless strict=True; TrustMonitor always uses strict mode.

TrustStore schema 3 migrates supported older stores atomically. Newer versions are
refused read-only before mutation. An exclusive state-directory owner writes and
fsyncs owner.unclean before constructing/migrating the store. An old marker causes
atomic conservative recovery for every existing trust record; quarantine persists,
and every record requires observation followed by explicit approval/restore.
Storage faults latch across all sessions; clean shutdown is required to remove the
marker. `TrustStore.open_readonly` never migrates or writes markers. Its records
are operator inspection, never an off-process protected catalog.

TrustStore.atomic() yields a guarded SQLite connection with Row results and nested
SAVEPOINTs. The guard latches SQL failures as StorageFaultError. Memory tables can
use this transaction without touching private trust tables.
emit_event_in_transaction(db, server_id, event_type, actor, detail) returns a stable
event ID and enqueues its audit payload in that transaction; server_id=None uses
the reserved @memory event scope (no synthetic trust record is created).

ManagedClient.apply_hard_deny accepts context_guard: () -> str | None, checked
inside the transaction under shared server coordination. The matching
record_assessment_if_current operation takes server_id, revision, generation,
policy_context, active_policy_context, detail, actor and optional context_guard;
it returns AssessmentOutcome(status='recorded'|'stale', event_id, reason).

Optional detector is a DetectorBinding with exact policy/rules digests, rule map
and scanned fields. JSON rules need no parser; YAML rules need optional PyYAML.
Optional reviewer must be an async callable (monitor, server_id). It must use
validated evidence and guarded client operations; the SDK does not grant arbitrary
unvalidated model output authority. Optional async history sink receives the store;
a synchronous sink receives pending payload rows in a worker and must return only
after durable delivery. Disabling adapters is reported as disabled.

`catalog_revision` and `wait_for_catalog_change(after_revision, timeout=None)`
provide coalesced invalidation hints, including freshness expiry. Fetch the catalog
again after a wakeup; change tokens grant no authority. Monitoring refreshes each
already-live session independently, without launching unused manual sessions.
Guarded quarantine closes all strict sessions sharing this owner.

Before review I/O, capture `assessment_context(server_id)`; include
`assessment_stale_reason(context)` in the guarded completion callback. It binds
the trust context plus backing session and dirty epoch, so notification followed
by an identical refresh cannot silently reuse an earlier assessment. Hard-deny
quarantine closes transports and returns `assessment='skipped_hard_deny'`; the
optional model is not invoked or implicitly given a newly reopened transport.

SDK-owned stores also verify that persisted covered metadata hashes to its stored
revision before exposing it. Legacy direct TrustStore users retain their existing
state-machine interface; the strict digest check is enabled by the facade. The
built-in scanner has cooperative cancellation that reaps its process group before
monitor stop returns, and verifies the actual scanned rules digest against its
declared binding. Rule paths and mappings are frozen at configuration creation.

Focused proof includes real stdio catalog/selection/freshness, shared session
quarantine, independent observation while a reviewer awaits, notification epochs,
lost-response/no-replay, launch identity including executable symlink changes,
second-owner/future-schema refusal, interrupted migration, failed marker durability,
unclean recovery, invalid metadata digest, store faults, and scanner shutdown.
The latest combined core/lifecycle/detector selection passed 46 tests offline.
Root integration owns packaging, external consumer, console, memory and live gates.
