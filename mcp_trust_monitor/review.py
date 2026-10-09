"""One hard-deny review pass: observe, scan, apply if current, verify (M2).

`review_server` observes the server's current metadata, scans its tool descriptions
with the deterministic detector, and applies a match only if the assessed revision,
generation, and policy context are all still current at apply time. The policy
context is the client's policy binding plus the digest of the hard-deny rules that
were actually scanned; the context at apply time is read from disk. A stale result
is recorded and not applied; a new assessment is then obtained from a fresh
observation, a bounded number of times. No match, a detector failure, or exhausted
attempts leave the server blocked in pending review: nothing here approves
(REQ-DEC-01, REQ-DEC-04). There is no model assessment or polling in this milestone.

`verify_blocked` attempts a call through `ManagedClient.call_tool`, the same path
used for normal calls. It records `verified_blocked` only with evidence: the call was
refused before dispatch because of quarantine, the record is still quarantined at
the generation the quarantine was applied, the client wrote nothing to the
transport, and the server-side received-call count exists and did not change
(REQ-AUD-02). Anything else is recorded as `verification_failed`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Sequence

from .detector import (DEFAULT_RULES, DetectorError, DetectorResult, rules_digest_of,
                       scan_tools)
from .managed_client import CallBlocked, ManagedClient
from .policy import load_policy, policy_rule_ids
from .trust_store import HardDenyOutcome, TrustState

Scanner = Callable[[Sequence[Mapping[str, Any]]], DetectorResult]
REVIEWABLE = (TrustState.UNREVIEWED, TrustState.PENDING_REVIEW)
SCANNED_FIELDS = ("description",)


def policy_context(policy_binding: str, rules_digest: str) -> str:
    return f"{policy_binding}|hard-deny-rules={rules_digest}"


def active_policy_context(policy_path: Path, rules_path: Path) -> str:
    """The policy context in force now, read from disk."""
    try:
        rules_digest = rules_digest_of(Path(rules_path).read_bytes())
    except OSError:
        rules_digest = "unreadable"
    return policy_context(load_policy(policy_path).binding, rules_digest)


@dataclass
class ReviewReport:
    server_id: str
    outcome: str  # quarantined | pending_review | detector_failed | stale | skipped
    attempts: int
    revision: str | None = None
    generation: int | None = None
    detection: dict[str, Any] | None = None
    error: str | None = None
    stale: list[str] = field(default_factory=list)
    quarantine: HardDenyOutcome | None = None


async def review_server(
    client: ManagedClient,
    server_id: str,
    *,
    policy_path: Path,
    rules_path: Path = DEFAULT_RULES,
    scanner: Scanner | None = None,
    max_attempts: int = 3,
    before_apply: Callable[[], Awaitable[None]] | None = None,
    actor: str = "hard-deny-detector",
) -> ReviewReport:
    known = policy_rule_ids(policy_path)
    scan = scanner or (lambda tools: scan_tools(tools, rules_path=rules_path,
                                                known_policy_ids=known))
    report = ReviewReport(server_id, "stale", 0)
    for attempt in range(1, max_attempts + 1):
        report.attempts = attempt
        record = await client.observe(server_id)
        report.revision, report.generation = record.observed_revision, record.generation
        if record.state not in REVIEWABLE:
            report.outcome = "skipped" if record.state is TrustState.APPROVED else "quarantined"
            return report
        assessed = {"assessed_revision": record.observed_revision,
                    "assessed_generation": record.generation,
                    "scanned_fields": list(SCANNED_FIELDS)}
        try:
            result = await asyncio.to_thread(scan, record.observed_tools)
        except DetectorError as exc:
            report.outcome, report.error = "detector_failed", str(exc)[:500]
            client.store.record_event(server_id, "detector_failed", actor=actor,
                                      detail={**assessed, "error": report.error,
                                              "outcome": "pending_review"})
            return report
        context = policy_context(client.policy_revision, result.rules_digest)
        report.detection = {**result.as_dict(), "scanned_fields": list(SCANNED_FIELDS)}
        if not result.matches:
            # Absence of a match never approves; the change waits for operator review.
            client.store.record_event(server_id, "hard_deny_scan_clean", actor=actor,
                                      detail={**assessed, **report.detection,
                                              "policy_context": context,
                                              "outcome": "pending_review"})
            report.outcome = "pending_review"
            return report
        if before_apply is not None:
            await before_apply()  # test hook: lets tests change state between scan and apply
        outcome = await client.apply_hard_deny(
            server_id, revision=record.observed_revision, generation=record.generation,
            policy_context=context,
            active_policy_context=lambda: active_policy_context(policy_path, rules_path),
            detection=report.detection)
        if outcome.status in ("applied", "already_quarantined"):
            report.outcome, report.quarantine = "quarantined", outcome
            return report
        report.stale.append(outcome.reason or "stale")
    return report  # every attempt went stale: still blocked, still pending review


async def verify_blocked(
    client: ManagedClient,
    server_id: str,
    tool: str,
    arguments: dict[str, Any],
    received_count: Callable[[], int],
    *,
    quarantine: HardDenyOutcome,
    actor: str = "verifier",
) -> dict[str, Any]:
    """Record `verified_blocked` only with complete evidence; otherwise `verification_failed`."""
    applied_generation = quarantine.record.generation if quarantine.record else None
    detail: dict[str, Any] = {
        "tool": tool, "dispatch_path": "ManagedClient.call_tool",
        "quarantine_applied_event_id": quarantine.applied_event_id,
        "quarantine_requested_event_id": quarantine.requested_event_id,
        "applied_generation": applied_generation,
    }
    problems: list[str] = []
    if quarantine.status != "applied" or quarantine.applied_event_id is None:
        problems.append(f"no applied quarantine to verify ({quarantine.status})")

    def counter() -> int | None:
        try:
            value = received_count()
        except Exception as exc:  # the evidence source itself failed
            problems.append(f"server-side counter unavailable: {type(exc).__name__}")
            return None
        return value if isinstance(value, int) else None

    before = counter()
    dispatched_before = client.dispatch_count(server_id)
    reason = None
    try:
        await client.call_tool(server_id, tool, arguments)
    except CallBlocked as blocked:
        reason = blocked.reason
    after = counter()
    record = client.store.get(server_id)
    detail.update({
        "blocked_reason": reason, "received_before": before, "received_after": after,
        "client_dispatches_before": dispatched_before,
        "client_dispatches_after": client.dispatch_count(server_id),
        "state_after": record.state.value if record else None,
        "generation_after": record.generation if record else None,
    })
    if reason != TrustState.QUARANTINED.value:
        problems.append(f"block reason was {reason!r}, not quarantined")
    if before is None or after is None:
        problems.append("server-side received-call count missing")
    elif after != before:
        problems.append("server-side received-call count changed")
    if detail["client_dispatches_after"] != dispatched_before:
        problems.append("client wrote a tools/call to the transport")
    if (record is None or record.state is not TrustState.QUARANTINED
            or record.generation != applied_generation):
        problems.append("record is no longer quarantined at the applied generation")
    detail["verified"] = not problems
    detail["problems"] = problems
    client.store.record_event(server_id, "verified_blocked" if not problems
                              else "verification_failed", actor=actor, detail=detail)
    return detail
