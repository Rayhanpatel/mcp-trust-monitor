# MCP Trust Monitor

An agent that monitors changes to MCP tool definitions, evaluates them against an explicit policy, and quarantines affected connections in a managed client with evidence for each decision.

**Status: specification and repository scaffold.** The repository includes an inherited discovery prototype and synthetic demo inputs. The monitoring agent, integrations, enforcement client, and dashboard are not implemented yet.

## The product

A tool trusted yesterday can advertise different instructions today. MCP Trust Monitor records that change, determines whether it violates the operator's policy, and verifies that a quarantined connection can no longer receive calls through the managed client.

The hackathon demo will show a controlled server changing its description, an agent citing the applicable policy, a blocked call, and an unaffected tool continuing to work. A harmless wording change will remain allowed after review.

## Read first

- [Product and technical specification](docs/SPEC.md)
- [Build plan and acceptance checklist](docs/BUILD_PLAN.md)
- [Evidence provenance and claim limits](docs/EVIDENCE.md)
- [Example policy](policies/demo-policy.json)
- [Synthetic demo scenarios](fixtures/tool_changes.json)

## What is here

| Path | Purpose |
| --- | --- |
| `tools/registry_probe_prototype.py` | Existing Python metadata-discovery experiment; not a hardened collector |
| `fixtures/tool_changes.json` | Synthetic baseline, harmless edit, policy violation, and unaffected tool |
| `policies/demo-policy.json` | Operator-authored policy used by the planned demo |
| `data/evidence_manifest.json` | Count and digest of the earlier research snapshot |
| `data/local/` | Ignored local research data; not included in Git |
| `.env.example` | Placeholders for planned integrations |

The saved research snapshot contains 35 server records and 287 tool definitions. It is a sample, not a registry census or a malware dataset. The raw snapshot is kept locally; see the evidence notes for provenance and limitations.

## Proposed stack

Python service and controlled MCP client, ClickHouse for observation and decision history, local Semgrep for candidate detection, Senso for scoped policy retrieval, and a model for evidence-based assessment. A minimal web view will display the timeline and enforcement outcome.

There is no application start command yet. Build the verified enforcement loop before the dashboard. The first complete milestone is in [the build plan](docs/BUILD_PLAN.md).

## Contribute and push

After cloning, create a branch and commit changes normally:

```sh
git switch -c feat/trust-loop
git add <changed-files>
git commit -m "Implement managed client trust checks"
git push -u origin feat/trust-loop
```

Keep credentials, raw research snapshots, and machine-specific configuration out of Git. This project currently has no selected distribution license; choose one before inviting external code reuse.
