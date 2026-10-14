# Reviewed memory library

`MemoryService` uses the already-owned `TrustStore`. It does not open a second
connection, configure a model, read credentials, or contact a service at import.
All local memory changes, registry revisions, audit records and delivery outbox
rows commit in one store transaction. The owner-wide storage fault latch applies
to memory operations. Close the owner and recover through `TrustMonitor`; a
memory operation cannot independently repair or reopen its store.

## Operator workflow

1. Record an observation and an accepted assessment with exact server, metadata
   revision, generation and policy context.
2. `record_verdict` requires those IDs, a human actor, rationale, and one of
   `violation`, `non_violation`, or `uncertain`. Trust approval or restoration
   never supplies a verdict. Replacing a verdict requires its explicit ID and
   atomically revokes every derived lesson.
3. `draft_lesson` accepts an operator-authored summary and known policy rule IDs.
   Uncertain, superseded, old-policy and configured held-out revisions cannot
   supply lessons. The evaluation runner must provide its frozen held-out
   revisions and its near-duplicate validator; generic library code has no
   implicit knowledge of a particular evaluation corpus.
4. `preview` returns the exact immutable body and SHA-256 digest. `approve_lesson`
   requires that digest and a reviewer. Each new version has a distinct lesson
   ID and needs independent review. Creating a version does not silently revoke
   an older version; explicitly revoke obsolete versions.
5. `publish` uploads the approved body once and activates only after completion
   and exact full-body/version read-back. `reject_lesson` applies to drafts;
   `revoke_lesson` invalidates eligible or pending content locally before any
   remote cleanup. The library records orphan identifiers rather than claiming
   that revocation deleted a remote copy.

The body is bounded to 8192 characters and the summary to 2000. Summaries reject
control/invisible characters, addresses, obvious secret-like tokens, role tags,
and common instruction syntax. The operator sees the exact body before approval.
This heuristic is an additional guard, not proof that arbitrary text is safe or
free of secrets. Metadata and model explanations are never automatically copied
into lessons. Actor/rationale values stay local; audit events use stable IDs and
do not duplicate their free text.

## Publication recovery

The visible states are `draft`, `approved`, `publishing`,
`uploaded_unverified`, `active`, `publication_indeterminate`,
`publication_failed`, `rejected`, and `revoked`.

`publishing` and its stable operation ID commit before upload. A timeout,
cancellation, malformed receipt or transport failure may mean the write happened:
the operation becomes `publication_indeterminate` and cannot automatically retry.
After process interruption, explicitly publishing a stranded `publishing` record
marks it indeterminate without uploading. A known receipt is durable as
`uploaded_unverified`; a later explicit `publish` resumes bounded processing and
read-back without uploading again. A read-back integrity failure stays inactive.

`reconcile` requires an operator-supplied node ID and exact read-back containing
the unique approved lesson ID/version/body. It rejects changed bodies and local
state changes. Reconciliation then resumes verification, never upload.
`abandon` records the unresolved possible orphan and leaves the lesson inactive.
Publication changes recheck local operation identity and source eligibility;
revocation/supersession during remote I/O cannot later activate a lesson.

## Backend and retrieval

`MemoryBackend` normalizes `upload_raw`, `node`, `node_content`, and
`search_context`. Upload adapters must not retry. A backend must have explicit
`capability_verified=True` and nonempty `capability_evidence`, set by trusted
configuration after a real private-content/version/read-back/scoping probe.
The fake backend in tests is not evidence of remote service capability.

Memory defaults off. `retrieve(enabled=False)` supplies no historical context.
Enabled retrieval snapshots the owner, scope, policy, registry revision and all
eligible immutable lesson versions before I/O. Empty eligible sets make no
remote call. Nonempty searches send explicit eligible IDs and a bounded top-k;
they never widen to the organization. An empty valid result is permitted.

Every returned passage must name an eligible content ID and be a whitespace-
normalized substring of the approved body. The latest full remote body and its
numeric/normalized version are re-read and must match the approved digest and
activation version. An opaque search `source_version_id` is retained separately;
it is not silently equated to a numeric content version. Each remote boundary
rechecks the local snapshot. Integrity or service failures raise; enabled memory
never silently falls back to policy-only mode.

The default bounds are 100 eligible lessons, top-k 3 (maximum 20), 2000 query
characters and 20 seconds per adapter operation. Publication polls at most 100
times; its default is 20 polls. Applications may set narrower limits.

## Model integration and application

`memory.assessment` provides `memory_input`, `memory_schema`,
`MEMORY_INSTRUCTIONS`, and `validate_memory_assessment`. Configure the additive
`OpenAIAssessor` input/schema/instructions hooks explicitly. Its baseline defaults
are unchanged. Model calls have no tools and can output only `review` or
`quarantine`. Metadata is limited to 100 tools and 65536 serialized characters;
precedents to 20 passages and 32768 serialized characters. Oversize input is
rejected rather than truncating evidence or changing its offsets.

Policy `source_content_ids` and historical `precedent_ids` are separate. The
validator accepts only actually returned lesson IDs; eligible-but-unretrieved
IDs are invalid. Quarantine still requires a known policy rule and an exact span
of current metadata. Historical evidence cannot replace either. The prompt marks
historical examples as untrusted data; it is not an injection-immunity claim.

After model completion call `assert_current(retrieved.snapshot)`, and pass
`context_guard=lambda: memory.guard(retrieved.snapshot)` into the managed
client's `record_assessment_if_current` or `apply_hard_deny`. The latter check runs
inside the shared transaction under the managed-client dispatch lock. Both
`review` and `quarantine` outcomes need this check. Never salvage stale output by
discarding citations. Root orchestration records requested, returned and actually
cited IDs plus response identity as distinct audit fields. A model result never
approves a server or weakens a deterministic quarantine.

## Validation scope

Tests exercise real local transactions and outbox records with an injected remote
backend. They cover reference integrity, uncertain verdicts, digest approval,
unsafe summaries, held-out rejection, version review, supersession, upload
ambiguity, resume/reconcile without upload, publication races, source tampering,
policy/scope changes, snapshot guards and separate model citations. Remote
capability and paired live evaluation are separate release evidence. Successful
retrieval/reuse does not imply measured classification improvement.
