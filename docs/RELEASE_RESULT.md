# MCP Trust Monitor alpha verification: 0.2.0a2 and 0.2.0a1

This is a bounded **local stdio Python alpha**. Its public SDK, CLI, monitor,
operator console and optional adapters are implemented. It is not a claim of
production readiness, general prompt-injection protection or arbitrary executable
safety. Runtime behavior and requirements are documented in [LIBRARY.md](LIBRARY.md)
and [SPEC.md](SPEC.md).

## 0.2.0a2 corrective alpha validation (16–17 October 2026)

0.2.0a2 repairs four defects found in 0.2.0a1 and one follow-up scheduling race;
see [HANDOFF.md](HANDOFF.md). These results come from local runs of the 0.2.0a2
code. They are not hosted CI,
and they are not validated by the historical live results or the 0.2.0a1 hosted
runs below.

The full suite ran from a clean git archive of the 0.2.0a2 code, with
`MTM_REQUIRE_NODE=1` and no cloud credential variables present. It passed
**645 tests in each run**:

| Environment | Python | Result |
| --- | --- | --- |
| macOS ARM64 | 3.10.22 | 645 passed, no skips |
| macOS ARM64 | 3.12.7 | 645 passed, no skips |
| Linux ARM64, unprivileged container user | 3.10.22 | 645 passed, no skips |
| Linux ARM64, unprivileged container user | 3.12.15 | 645 passed, no skips |

Before the scheduling follow-up, the repaired code passed 637 tests on the same
four environments.

**Pre-repair reproduction.** Each defect was reproduced against the 0.2.0a1 code,
using temporary synthetic state and real stdio servers that log received calls:

- **D1:** with the configured executable symlink retargeted during the first
  `tools/list`, observation, approval and the call all succeeded, and the call
  reached the old process. With two sessions, the old session's tokenless and
  catalog-token calls reached the old process after the new target was approved.
- **D2:** after a reload with different valid detector rules, the generation stayed
  at 2, approval stayed, the old selection token dispatched (the server log shows
  1 call), and an approval prepared before the reload was accepted.
- **D3:** a tool without a description made the review fail with `TypeError` at the
  retrieval stage, before the local fake model was called.
- **D4:** a model failure after successful policy retrieval exported
  `returned_content_ids: null`.

On 0.2.0a2, from the source tree and from the installed wheel, every one of
these is refused or corrected, and the logs record no unintended call. The 77 tests
in the five new or extended regression files were also run against the 0.2.0a1
library code. 53 fail there for the defect reasons. The other 24 pass on both
versions; they deliberately guard unchanged behavior, such as identical-binding
no-ops, an unchanged virtualenv interpreter symlink, invalid description types
and successful export records.

**Follow-up: review scheduling after a detector reload (17 October).** On the repaired
code before this follow-up, a detector was reloaded while the old detector's scan was still running,
with `review_max_attempts=1`. The new detector scanned 0 times: the stale old scan
used up its budget (`retries_exhausted`), and no automatic review followed. A scan
that had already finished before the reload was unaffected. The six tests in
`tests/test_detector_reload_scheduling.py` fail on that code; two further tests
check prompt rescheduling.
They use a real stdio server and blocked local fake detectors. After the repair:

- the new detector runs automatically, without a manual reset;
- a new hard denial quarantines, and an earlier quarantine is preserved;
- approval invalidation is unchanged;
- the new context keeps its single bounded attempt;
- attempts running across a reload back to the same pair, an equal-declaration
  reload or an explicit reset are not charged to the re-armed budget.

Mutation checks confirmed that reverting either part of the repair fails the tests.
The provided reproduction also passed from the installed wheel.

**Installed artifacts.** A wheel and source archive were built from a clean
archive of the 0.2.0a2 code. The installed wheel was then checked outside the
checkout with core-only dependencies, on Python 3.10 and 3.12. These checks passed:

- public API and packaged resources;
- separate-process CLI;
- custom Semgrep binding, with a real scan;
- launch-identity invalidation;
- keyed pseudonymous export;
- the four defect reproductions above.

The strict typing consumer passed, and its seven invalid uses were rejected.
Artifact checksums are recorded with the local evidence rather than in this tree,
because the source archive contains this file.

**Cross-version state.** One synthetic state directory was owned in turn by the
0.2.0a1 code and the 0.2.0a2 code, over real stdio:

1. Under 0.2.0a1, an approval was created and survived a restart.
2. The first 0.2.0a2 open returned it to pending review. Generations advanced,
   the quarantined server stayed quarantined, and the call was refused until the
   server was re-approved.
3. An unchanged 0.2.0a2 reopen changed nothing.
4. A detector change under 0.2.0a2 reset approval again.
5. 0.2.0a1 then opened the upgraded state without error, returned the 0.2.0a2
   approval to pending review and refused the call. The server log did not move.

The store stayed at schema 4 throughout.

**Independent review.** A separate reviewer examined the combined change in three
rounds, including mutation checks of the new guards. Its findings were resolved
before these runs:

- the CLI can now declare the detector binding;
- the post-initialization identity check has a test;
- the decision binding is now the activated value;
- CLI `review` reports a failed scan with exit 1.

The final verdict was ready. Deferred follow-ups are listed in HANDOFF.md.

Hosted CI on Linux AMD64 and macOS ARM64, Python 3.10/3.12, runs on the exact
release commit. The versioned GitHub release links those runs, and its `SHA256SUMS`
lists the published artifacts; local runs are not a substitute for them.

Not done for 0.2.0a2:

- Windows;
- any live OpenAI, Senso or ClickHouse call;
- reruns of frozen evaluations.

## 0.2.0a1 release validation

The independently reviewed repair snapshot passed **570 tests in each run**:

| Environment | Python | Result |
| --- | --- | --- |
| macOS ARM64 | 3.10.22 | 570 passed, no skips |
| macOS ARM64 | 3.12.7 | 570 passed, no skips |
| Linux ARM64, unprivileged container user | 3.10.22 | 570 passed, no skips |
| Linux ARM64, unprivileged container user | 3.12.15 | 570 passed, no skips |

The initial Linux attempt used an account without a home directory, so the
scanner's cache could not be created: 24 failures and 546 passes on each version.
After correcting that test environment, all tests passed without changing product
code or assertions. The initial logs are retained privately with the successful
runs. The suite includes real stdio, process/signal, concurrency, migration,
recovery, cancellation, privacy and operator-context regressions. Console
JavaScript is exercised in a Node DOM harness; that is not a fresh browser tour.

Independent installed-wheel checks passed outside the checkout with core-only
dependencies: public API, CLI, packaged resources, custom detector configuration,
launch-identity invalidation and pseudonymous export. A strict typing consumer
passed; seven deliberately invalid uses were rejected. This does not mean all
internal implementation modules are strictly typed.

A new core-only installation also passed a scripted integration with the official
filesystem MCP server using locked package versions `2026.8.31` and `1.0.0`.
Unreviewed, quarantined and stale-selection calls were refused; an unrelated
connector continued working; a metadata change invalidated approval; explicit
approval restored access. These refusals establish local nondispatch. The
third-party server had no independent receipt counter, and its own directory
restrictions are not enforcement supplied by this library. Returned document
content was not inspected or filtered, and no model consumed it.

## Exact public release and hosted CI

The public release tree keeps the reviewed runtime while preparing sanitized
documentation, package metadata and SHA-pinned automation. Private development
history is not pushed. Existing public history is retained.

The hosted workflow runs all tests, builds and checks installed distributions and
public typing on Linux AMD64 and macOS ARM64, each with Python 3.10/3.12. The
versioned GitHub release includes `release-record.json`, identifying the exact
public commit, completed hosted runs, final artifact hashes and independent
publication review. `SHA256SUMS` contains the wheel and source-archive checksums.
Those records establish the final publication state; this document does not
substitute a local test result for a hosted run.

GitHub and PyPI publication are separate. The manual PyPI workflow accepts only
verified assets from the reviewed GitHub release and requires a configured PyPI
Trusted Publisher. An absent PyPI project must never be described as published.

## Historical live service experiment

The following results describe the retained **12 October 2026 runtime before the
subsequent correctness repairs**. They are functional historical evidence, not
live validation of the published runtime or current service accounts. The release
did not contact OpenAI, Senso or ClickHouse to repeat them.

The corrected opaque-ID comparison used eight fixed synthetic cases, three
interleaved pairs per case, two modes and three active privately approved lessons:
**48 scheduled attempts**, zero automatic retries.

| Measurement | Memory off | Memory on |
| --- | ---: | ---: |
| Expected model-only outcomes | 24/24 | 24/24 |
| Expected combined outcomes | 24/24 | 24/24 |
| Trials receiving precedents | 0 | 24 |
| Trials citing precedents | 0 | 7 |
| Median end-to-end elapsed time | 10.02 s | 13.63 s |
| Total tokens | 39,880 | 54,164 |

**No decision improvement was demonstrated. Memory remains disabled by default.**
Eight repeated cases are not 48 independent cases; these results do not establish
broad accuracy, statistical significance or general latency/cost behavior.

The original run exposed readable case labels to the model and is retained as
functional evidence only. A corrected preflight failed all scheduled attempts
before service calls; its failure was retained. The succeeding opaque-ID run reused
the same eight cases, disclosed explicitly, without changing fixed expectations.
Results from different lesson snapshots are not pooled.

The separate historical integrity rehearsal revoked one retrieved lesson after a
provider response completed and before local application. That response was
rejected as stale, the next search excluded the lesson, and existing quarantines
were preserved. It did not prove revocation during an in-flight network request.
The historical audit read-back found 931 local event IDs across nine runs and zero
pending outbox rows at that snapshot; this does not imply universal exactly-once
delivery.

The historical source verdicts and exact lesson bodies were approved for private
Senso publication. They remain private, along with raw provider IDs and state.
Recovery verified 31 checks across 19 distinct files against pre-existing retained
manifests, including
comparison, revocation and audit evidence. Private local evidence retains failed
runs and the original review reports; the public release includes aggregate
claims and their limits rather than the raw records. The allowlisted
[historical aggregate summary](HISTORICAL_EVIDENCE.json) contains the recovered
measurements, retained failures and verification limits.

## Supported scope and operational limits

- Local stdio and the MCP Python SDK 1.30.x integration; one owning writer process.
- Python 3.10/3.12 on the recorded macOS/Linux architectures. Windows, HTTP/OAuth,
  distributed ownership and arbitrary-client proxying are outside this alpha.
- Observation launches the configured process. Approval of metadata is not a
  sandbox, code signature, content filter or guarantee of safe tool behavior.
- Store schema 4 and export schema 2; follow the backup/downgrade guidance.
- Optional model recommendations can review or quarantine, never approve.
- An incomplete shutdown may leave user work pending until process exit; outcomes
  and recovery markers report that state. No automatic tool replay occurs.

A consumer should validate its own server, policy and deployment. Publishing this
alpha does not make the historical cloud experiment a new release benchmark.
