# MCP Trust Monitor build plan

Build one complete enforcement loop before expanding the interface or coverage. Time boxes below are estimates from the start of implementation, not a promise that the current event window is sufficient.

## Current state

- [x] Dedicated repository, specification, demo policy, and synthetic scenarios.
- [x] Existing metadata probe copied and labeled as a prototype.
- [x] Saved research sample counted and preserved locally with a digest manifest.
- [ ] Managed client and controlled MCP servers.
- [ ] Observation history and revision comparison.
- [ ] Semgrep, Senso, and model review integration.
- [ ] Quarantine enforcement and verification.
- [ ] Timeline interface, video, and submission.

## Implementation sequence

| Time box | Deliverable | Exit condition |
| --- | --- | --- |
| 20 minutes | Verify ClickHouse, scoped Senso retrieval, model access, and local Semgrep | One actual success response per integration; identify blockers immediately |
| 40 minutes | Controlled servers, managed client, persistent trust states | Allowed call succeeds; manual test quarantine blocks dispatch; control server stays usable |
| 30 minutes | Import, fingerprint, and store observations | Baseline and changed fixture revisions appear in ClickHouse with origin labels |
| 45 minutes | Candidate rules, retrieval, assessment, validator | Changed revision produces a grounded valid decision; malformed or stale output cannot approve |
| 30 minutes | Complete autonomous loop | Fixture mutation leads to quarantine and verified blocked call without a human decision |
| 20 minutes | Minimal timeline and measured results | One screen shows change, source, decision, action, and verification |
| 25 minutes | Record and prepare submission | Shareable video, reviewer-accessible repository, sponsor evidence, concise writeup |

The estimate totals 3 hours 30 minutes and excludes unexpected integration failures. Protect recording and submission time. The workspace deadline is 4:30 PM Pacific on 9 October 2026; target submission at 4:15 PM. Recalculate available time when implementation starts.

## First implementation task

Create the local demo server and the client dispatch boundary. Consume `fixtures/tool_changes.json`, explicitly approve the baseline, and prove a quarantined server cannot receive another call through the client. This is the project's hardest product claim; establish it before building the dashboard.

Then connect actual metadata polling and model assessment to that working boundary. The first end-to-end run should use only the synthetic server and the unaffected control. Public registry expansion can wait.

## Focused verification

Automate behavior checks for the enforcement boundary:

1. An approved baseline is callable.
2. A detected revision change invalidates prior approval before another dispatch.
3. A stale review result cannot authorize a newer revision.
4. Quarantine survives restart and prevents any increment of the server's call counter.
5. The unaffected server remains usable.
6. A harmless edit becomes callable after approval.
7. Retrieval, model, and scan failures cannot produce a clean verdict.
8. Retried actions do not create repeated side effects; delayed audit delivery remains visible.

Test these invariants rather than reproducing internal implementation details. Integration checks must exercise actual sponsor services; fixture-only runs remain labeled fixture-only.

## Cut order

Cut optional hosting, live registry expansion, materialized views, charts, polish, and multiple policy families first. Keep one real Semgrep rule, scoped Senso policy retrieval, actual ClickHouse history, and the autonomous enforcement loop.

Do not describe an unimplemented integration as sponsor usage. If an integration is blocked, choose and implement another eligible sponsor contribution or report the eligibility gap. Do not spend submission time on extra integrations after the core requirements work.

## Two minute demo

- 0:00–0:15: State the trust-change problem and show the sample size with its label.
- 0:15–0:35: Show an approved tool call, then mutate the controlled server's description.
- 0:35–1:10: Show the detected diff, Semgrep evidence, Senso policy reference, and agent decision.
- 1:10–1:35: Retry through the managed client; show blocked dispatch and unchanged server counter. Call the unaffected tool successfully.
- 1:35–1:50: Show the harmless-change control and the measured timeline in ClickHouse.
- 1:50–2:00: State the protection boundary and name the working sponsor integrations.

## Submission checklist

- [ ] Working autonomous action and verification captured on video.
- [ ] Three eligible sponsor tools actually used and evidenced.
- [ ] Fixture, imported, and live data clearly labeled.
- [ ] No claims of malware discovery or universal protection.
- [ ] Repository accessible to reviewers; a private remote alone is insufficient.
- [ ] Video link works for a reviewer outside the account.
- [ ] Team names, contact details, project description, and tools listed.
- [ ] No credentials, venue details, or unrelated personal files published.
- [ ] Submission sent before the deadline.
