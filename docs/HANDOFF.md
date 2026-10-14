# MCP Trust Monitor alpha release handoff

Version: **0.2.0a1**. The public release is prepared from the independently reviewed
local runtime and the existing public hackathon history. Private approval records
and raw provider evidence are retained locally and excluded from this public tree.

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

Current store schema is 4; export schema is 2. Older binaries that only support
store schema 3 refuse upgraded stores. Back up a stopped state directory and use
a compatible backup for downgrades.

## Verification

The independently reviewed runtime passed **570 tests in each of four local
runs**: Python 3.10 and 3.12 on macOS ARM64 and Linux ARM64. Regression tests
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
