# MCP Trust Monitor build plan

Build one complete enforcement loop before expanding the interface or coverage. Requirements and their IDs live in [SPEC.md](SPEC.md); this plan sequences them. Time boxes are estimates, not a promise that the event window is sufficient.

## Milestones and review gates

Each milestone is implemented on a feature branch, ends with `docs/HANDOFF.md` and a commit, and stops for independent review before the next one starts. Do not merge into `main` without review.

| Milestone | Deliverable | Requirements | Exit condition | Estimate |
| --- | --- | --- | --- | --- |
| M0 | Reconciled docs, requirement IDs, `CLAUDE.md`, integration smoke tests | — | Docs agree; each integration has an actual success or a recorded blocker | 20 min |
| M1 | Controlled mutable server and control, managed client, persistent revision-bound trust store | REQ-REV-01, REQ-ENF-01–04, REQ-TRU-01–06 | Over real MCP transport: approved baseline callable; quarantine blocks before dispatch with unchanged server count; control callable; quarantine survives restart; stale decisions rejected | 40 min |
| M2 | Observation history and hard-deny detection | REQ-REV-02–03, REQ-DEC-01, REQ-AUD-01–02 | Changed fixture revision recorded in ClickHouse through the outbox; a real Semgrep hard-deny match quarantines `private-content-demand` | 35 min |
| M3 | Scoped Senso retrieval, OpenAI `gpt-6-astra` recommendation (Responses API, strict Structured Outputs), validator, evaluation | REQ-SRC-01, REQ-DEC-02–05, REQ-EVAL-01–02 | Every fixed case produces a validated or rejected recommendation; failures stay pending review; results reported against expectations | 45 min |
| M4 | Autonomous loop | REQ-TRU-07, REQ-ENF-05 | Mutation leads to quarantine and a verified blocked call with no human decision | 25 min |
| M5 | Minimal timeline page | REQ-UI-01 | One screen shows change, source, decision, action, and verification | 20 min |
| M6 | Recording and submission | — | Video, reviewer-accessible repository, sponsor evidence, concise writeup | 25 min |

The workspace deadline is 4:30 PM Pacific on 9 October 2026; target submission at 4:15 PM. Recalculate available time at each review gate and apply the cut order below.

## Focused verification

Automate behavior checks; test invariants, not internal details. Integration checks must exercise actual sponsor services; fixture-only runs stay labeled fixture-only.

| Check | Requirements | Milestone |
| --- | --- | --- |
| An explicitly approved baseline is callable; an observed but unapproved one is not | REQ-TRU-01, REQ-ENF-02 | M1 |
| Quarantine blocks the next call before dispatch; the server-side received-call count is unchanged | REQ-ENF-01, REQ-ENF-03 | M1 |
| The unaffected control stays callable | REQ-ENF-04 | M1 |
| Quarantine survives client restart | REQ-TRU-04 | M1 |
| A revision change invalidates approval before the next dispatch; a stale decision cannot authorize the newer revision | REQ-TRU-02, REQ-TRU-03 | M1 |
| A harmless edit stays pending review until explicit operator approval | REQ-TRU-05 | M1, M3 |
| A hard-deny match quarantines regardless of model output | REQ-DEC-01 | M2, M3 |
| Retrieval, model, and scan failures cannot produce approval | REQ-DEC-04 | M3 |
| Retried actions do not repeat side effects; delayed audit delivery stays visible | REQ-TRU-06, REQ-AUD-01 | M1, M2 |

## Cut order

Cut first: optional hosting, public registry ingestion, broad crawling, charts, polish, elaborate recovery demonstrations, and multiple policy families. Keep one real Semgrep hard-deny rule, scoped Senso policy retrieval, actual ClickHouse history, and the autonomous enforcement loop.

Do not describe an unimplemented integration as sponsor usage. If an integration is blocked, choose and implement another eligible sponsor contribution or report the eligibility gap. Do not spend submission time on extra integrations after the core requirements work.

## Two minute demo

- 0:00–0:15: State the trust-change problem.
- 0:15–0:35: Show an approved tool call, then mutate the controlled server's description.
- 0:35–1:10: Show the detected diff, the Semgrep hard-deny evidence, the Senso policy reference, and the model's recommendation.
- 1:10–1:35: Retry through the managed client; show the blocked dispatch and unchanged server count. Call the unaffected tool successfully.
- 1:35–1:50: Show the measured timeline in ClickHouse. Optionally show a harmless change held in pending review.
- 1:50–2:00: State the protection boundary and name the working sponsor integrations.

## Submission checklist

Status at the M3 freeze (9 October 2026). M4 and M5 were not built; see `docs/SUBMISSION.md`.

- [ ] Working autonomous action and verification captured on video. Recording is in progress in `../mtm-record`, which must first be updated to the frozen commit.
- [x] Three eligible sponsor tools actually used and evidenced: ClickHouse, Semgrep, and Senso, plus OpenAI. See `docs/EVIDENCE.md`.
- [x] Fixture and live data clearly labeled: all demo and evaluation data is `synthetic_fixture`.
- [x] No claims of malware discovery, universal protection, or automatic safe reapproval. `docs/SUBMISSION.md` states the limits.
- [ ] Repository accessible to reviewers; a private remote alone is insufficient. The feature branches are not yet pushed or merged.
- [ ] Video link works for a reviewer outside the account.
- [ ] Team names, contact details, project description, and tools listed.
- [x] No credentials in commits. Verified on 9 October 2026: the full history of `feat/m3-review` contains none of the ClickHouse host or password, the Senso key, or the OpenAI key. Recheck after any new commit, and review venue or personal files before publishing.
- [ ] Submission sent before the deadline.
