# MCP Trust Monitor 0.2.0a1 — alpha verification

This is a bounded **local stdio Python alpha**. Its public SDK, CLI, monitor,
operator console and optional adapters are implemented. It is not a claim of
production readiness, general prompt-injection protection or arbitrary executable
safety. Runtime behavior and requirements are documented in [LIBRARY.md](LIBRARY.md)
and [SPEC.md](SPEC.md).

## Current runtime validation

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
