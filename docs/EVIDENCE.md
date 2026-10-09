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

Run on 9 October 2026 during M0. Only Semgrep was exercised; nothing below is mocked.

| Integration | Result | Detail |
| --- | --- | --- |
| Semgrep (local) | Working | Semgrep 1.180.0 run ephemerally with `uvx`, no login. A throwaway custom `generic`-language rule scanned the fixture descriptions: 2 matches, 0 errors. When logged out, `extra.lines` is the literal string `requires login`; exact evidence spans must be sliced from the scanned bytes using `start.offset` and `end.offset`, which was verified. Not installed globally. |
| ClickHouse | Blocked | No `CLICKHOUSE_*` credentials in the environment or any `.env` file. Not contacted. |
| Senso | Blocked | No `SENSO_API_KEY` or policy content IDs, and the `senso` CLI is not installed. Not contacted. |
| Model API | Blocked | No `MODEL_API_KEY` or provider key configured. The coding assistant's own session is not an application credential. Not contacted. |

Blocked integrations do not block the local enforcement milestone (M1). Rerun each check against the actual service before claiming it.
