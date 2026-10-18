# MCP Trust Monitor alpha release handoff

Version: **0.2.0a2**, a corrective alpha that supersedes 0.2.0a1. The public
release was prepared from the independently reviewed local
runtime and the existing public hackathon history. Private approval records and
raw provider evidence are retained locally and excluded from this public tree.

## Current implementation

The library supports explicitly configured local stdio MCP servers, a single owning
process, approval-bound discovery and calls, shared durable trust across sessions,
background observation, a loopback operator console and pseudonymous audit export.
Optional detector/model/memory/history adapters use the same guarded decision path.
Memory is disabled by default. See [SPEC.md](SPEC.md) for the contract and
[LIBRARY.md](LIBRARY.md) for the supported API and operational boundaries.

## Reviewed repairs

The local repair series independently verified these behaviors before publication:

- Operator actions and verdict drafts remain tied to the context actually reviewed.
- Policy changes invalidate previously prepared approval intents in every state.
- Shutdown joins are bounded, cleanup stays tracked, and repeated shutdown paths
  do not cancel cleanup a second time. Calls are not replayed automatically.
- Start/stop transitions are coordinated; signal handling preserves clean versus
  incomplete shutdown and classified call outcomes.
- Config-relative executable paths and working directories are stable across
  invoking directories; virtualenv executable symlinks retain their meaning.
- Export identifiers use scoped keyed pseudonyms, including UUID-shaped inputs.
- Eligible verdict assessments are independent of the bounded display timeline.

## Corrective alpha repairs (16–17 October 2026)

A post-release review of 0.2.0a1 found four defects. Each was reproduced against
the 0.2.0a1 code with temporary synthetic state before repair, and each has
regression tests that fail on 0.2.0a1 and pass on 0.2.0a2:

- **D1 launch identity.** A session is bound to the launch identity captured
  before its process started. An identity change during startup or observation is
  an observation failure, and a session whose identity differs from the trust
  record never dispatches or appears in the catalog (`launch_identity_changed`).
  Previously, a symlink retargeted during `tools/list`, or an older connected
  session, could receive calls under an approval recorded for the new target.
- **D2 detector binding.** Approvals, generations, selection tokens and console
  intents bind the decision binding: the policy binding plus the detector binding
  (or `disabled`). A detector-only change by reload or reopen is now a genuine
  change; an equal declaration is a no-op. The JSON CLI config's optional
  `detector_binding` lets the CLI and an SDK owner declare the same pair.
- **D3 optional descriptions.** A valid absent tool description no longer fails
  model review before the model runs; non-string descriptions still fail.
- **D4 failure provenance.** Failed and stale assessment exports keep returned
  policy source IDs and memory `enabled`/`status`, still pseudonymized.

A follow-up review (17 October) found that automatic review still keyed its retry
budget on the policy alone. When a different detector was reloaded while the old
detector's scan was still running, that stale scan could use up the new detector's
attempts, so the new detector never ran automatically. The budget now uses the
activated decision binding. A result is not charged if its context was superseded
while it ran, or if its budget was reset meanwhile by a reload or an explicit
reset; a per-server reset epoch covers the case where the key is equal again.

Upgrading a 0.2.0a1 state directory fails closed once: approvals return to pending
review, generations advance and quarantine is preserved. An earlier binary opening
upgraded state also returns 0.2.0a2 approvals to pending review. There is no store
schema change. See [LIBRARY.md](LIBRARY.md) for the compatibility details.

Known limits and follow-ups:
- Launch identity is path and configuration identity, so a target swapped and
  restored during startup is not detected.
- A session refused for a changed identity keeps its blocked process until it is
  observed again or closed.
- The export does not yet carry a separate detector-binding digest.
- Invalid description types are refused only after scoped policy retrieval.

Current store schema is 4; export schema is 2. Older binaries that only support
store schema 3 refuse upgraded stores. Back up a stopped state directory and use
a compatible backup for downgrades.

## Verification

The 0.2.0a2 code passed **645 tests in each of four local runs**: macOS
ARM64 and Linux ARM64 (unprivileged), each on Python 3.10 and 3.12. The 0.2.0a1
code fails the new regression tests for the defect reasons. Installed-wheel,
typing and cross-version state checks passed. An independent review was resolved
to a final verdict of ready. Hosted CI runs on the exact release commit; the
versioned GitHub release links those runs and its `SHA256SUMS`. See
[RELEASE_RESULT.md](RELEASE_RESULT.md) for the exact local results.

The 0.2.0a1 runtime passed **570 tests in each of four local runs**: Python 3.10
and 3.12 on macOS ARM64 and Linux ARM64. Regression tests
reproduce the repaired failures on their pre-fix versions. The installed core-only
consumer, separate-process CLI, public typing, distribution assets and real
filesystem-server version transition also passed.

Hosted CI adds Linux AMD64 and macOS ARM64 on Python 3.10/3.12. The release's
`release-record.json` identifies its exact public commit, hosted runs, artifact
hashes and independent publication review. Use that record and GitHub Actions
status to determine the final release state; local tests alone are not hosted CI.
The PyPI workflow publishes the same reviewed wheel and source archive attached
to the versioned GitHub release after verifying their checksums and source.

[RELEASE_RESULT.md](RELEASE_RESULT.md) distinguishes current checks from historical
live experiments. No frozen comparison was rerun to improve its outcome. The
historical memory comparison found no decision improvement, so memory stays off.

## Development workflow

1. Start a branch from the public repository; keep state and credentials outside
   the source tree and outside cloud-synced directories.
2. Read SPEC, LIBRARY and the requirement map before changing behavior.
3. Add meaningful regression tests for a fix and exercise real stdio transport for
   enforcement claims. Do not weaken expectations to get a passing suite.
4. Run the relevant checks and independent review before merging. Update affected
   documentation and release evidence without calling old live results new tests.
5. Build fresh artifacts from the reviewed commit. Never distribute raw state,
   private approvals, provider identifiers, secrets or development-history exports.

Cloud or model checks use explicit credentials and may incur charges. Existing
historical evidence is not permission to publish a user's lesson content or
change an active quarantine. Human approval of a lesson is separate from approval
of a tool revision, and neither can be supplied by a model.
