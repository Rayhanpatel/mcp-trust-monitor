# Evidence and provenance

## Saved research snapshot

The earlier workspace research produced an array of **35 server records containing 287 tool definitions**. These counts were recomputed from the saved JSON during repository setup on 9 October 2026. The original file was copied into ignored local storage at `data/local/registry_snapshot.json`.

The tracked [manifest](../data/evidence_manifest.json) contains the original byte digest, record count, tool count, and field inventory. Its verification date records when the file was checked, not when each server was contacted. The raw snapshot does not contain per-record observation timestamps or a full log of attempted endpoints.

Earlier notes report 120 endpoints probed out of 208 discovered and collection in under a minute. Those timings and attempted-endpoint counts are not independently established by this snapshot. Do not present them as newly measured results. The saved array contains selected successful tool listings and is not a representative sample of the entire registry.

The raw data is kept outside Git because it is third-party metadata collected for research, may contain unexpected material, and has not received a field-by-field publication review. A clone has the manifest and synthetic scenarios, not the raw snapshot. The synthetic fixtures suffice for the planned reproducible demo.

## Interpretation

Some collected descriptions contain strong instructions about when an agent should call a tool. That wording can conflict with a configured operator policy. It does not establish malicious intent, successful prompt injection, or data exfiltration.

The advertising example discussed in the workspace includes sponsored-content disclosure requirements and shopper preferences. Do not label it hidden malware. Use controlled synthetic inputs to demonstrate a definite policy violation.

Do not reuse the earlier false-positive counts, population prevalence, or “passes every scanner” claim without a reproducible evaluation and labeled ground truth.

## Prototype status

`tools/registry_probe_prototype.py` is copied from the workspace discovery experiment. It uses the Python standard library and performs MCP initialization followed by metadata listing. It has not been rerun against the live registry during repository setup.

Before making it the application collector, address incomplete tool-list pagination, response validation, SSE parsing, bounded registry pagination, endpoint validation and redirect behavior, response-size limits, and rate limits. Keep explicitly configured local demo endpoints separate from public discovery. Never execute arbitrary stdio commands from a downloaded config.

The prototype's actual JSON output contains one record per attempted endpoint, with nested tools. The historical sample has only `server`, `url`, and `tools`; it is not byte-for-byte output of the current prototype format.

## Prior art and event context

- [Snyk Agent Scan](https://github.com/snyk/agent-scan) documents MCP inspection and periodic background monitoring. Ongoing MCP monitoring is not a new category.
- [Strix](https://github.com/usestrix/strix) documents exploit validation, patch generation, and CI integration. A generic scan-and-fix claim is insufficient differentiation for the alternative idea.
- [Event website](https://tokensand.com/cyberhack) was inaccessible during the comparison. The parent workspace's `EVENT_CONTEXT.md` is the captured source for the three-sponsor rule, agent requirement, submission artifacts, and 4:30 PM Pacific deadline. Confirm current instructions before submitting.

The project specification proposes behavior; it is not evidence that those capabilities are implemented. Demonstrate each capability with an actual run before including it in a submission claim.

## Integration smoke tests

Run on 9 October 2026 during M0. Semgrep and ClickHouse were exercised against the real tools; nothing below is mocked.

| Integration | Result | Detail |
| --- | --- | --- |
| Semgrep (local) | Working | Semgrep 1.180.0 run ephemerally with `uvx`, no login. A throwaway custom `generic`-language rule scanned the fixture descriptions: 2 matches, 0 errors. When logged out, `extra.lines` is the literal string `requires login`; exact evidence spans must be sliced from the scanned bytes using `start.offset` and `end.offset`, which was verified. Not installed globally. |
| ClickHouse Cloud | Working | `uv run python scripts/smoke_clickhouse.py` (HTTPS interface, credentials from `.env`): 8 of 8 checks passed against server 26.6.1.2326. After review, each check also validates the returned value; the rerun matched every expected value. A later run failed: its first two requests timed out at 60 s, the third succeeded after 23 s, and it exited 1. The cause is unconfirmed; idle suspension is the likely explanation but was not verified. An immediate rerun matched all 8 expected values. `SELECT 1`; database `mcp_trust_monitor` exists; a session-scoped temporary table accepted a `JSONEachRow` insert and returned it; `CHECK GRANT` confirms `CREATE TABLE` and `INSERT` on the database. Each request took about 190–310 ms. No persistent table was created. The application does not write to ClickHouse yet (M2). |
| Senso | Working in the application (M3) | On 9 October 2026 the repository authenticated to organization "MCP Trust Monitor". It uploaded only `policies/demo-policy.json`: content ID `44916d1c-a5db-4e68-96d8-9d6afa1b8784`, processed in 14.1 s and saved in the ignored `.env`. A scoped `POST /org/search/context` with `require_scoped_ids: true` returned 4 passages, all from that ID and all verified against the policy file. Senso's edge rejects urllib's default user agent (Cloudflare 1010), so the client sends its own. |
| Model API (OpenAI) | Working in the application (M3) | The repository calls `gpt-6-astra` through the official `openai` SDK (2.54.0) and the Responses API, with strict Structured Outputs and no tools. Live `demo-m3` and `evaluate` runs on 9 October 2026 returned validated assessments; see HANDOFF. |

### Application use (M2, 9 October 2026, 15:17 PDT)

- **Semgrep.** `demo-m2` ran the repository's hard-deny rules with Semgrep 1.180.0, verified by `--version` and pinned in an isolated `uvx` environment, on the mutated synthetic tool description. It reported POL-001 and POL-002 with exact evidence spans (`description[61:150]` and `[214:251]`).
- **Fixed cases.** All six fixed evaluation cases produce exactly their `expected_hard_deny_policy_ids` under real Semgrep (`tests/test_detector.py`).
- **ClickHouse.** The same run delivered 17 outbox events for run `demo-m2-cc76dd40-…` to `mcp_trust_monitor.trust_history` in 897 ms. It then resent 3 of them with the same event IDs and read back 20 raw rows, but 17 distinct event IDs, in 525 ms.
- All data in this run was `synthetic_fixture`.

Blocked integrations do not block the local enforcement milestone (M1). Rerun each check against the actual service before claiming it.
