"""M2 hard-deny review over real stdio MCP transport with real Semgrep.

REQ-DEC-01, REQ-DEC-04, REQ-AUD-02, REQ-TRU-02. The server-side received-call
counter comes from the demo server's own request log.
"""

from __future__ import annotations

import shutil

import pytest

from mcp_trust_monitor.managed_client import CallBlocked, ObservationError
from mcp_trust_monitor.review import review_server, verify_blocked
from mcp_trust_monitor.trust_store import HardDenyOutcome, TrustState

from conftest import CONTROL, LOOKUP, POLICY_PATH, REPO_ROOT, observe_and_approve

pytestmark = pytest.mark.anyio

ARGS = {"title": "Annual report"}


def event_types(client, server_id=LOOKUP) -> list[str]:
    return [event["event_type"] for event in client.store.events(server_id)]


async def approved_then_changed(env, client, scenario="private-content-demand"):
    await observe_and_approve(client, LOOKUP)
    await observe_and_approve(client, CONTROL)
    assert not (await client.call_tool(LOOKUP, "lookup_document", ARGS)).isError
    env.mutate(scenario)
    changed = await client.observe(LOOKUP)
    assert changed.state is TrustState.PENDING_REVIEW
    return changed


async def test_hard_deny_quarantines_current_revision_and_block_is_verified(env):
    async with env.client() as client:
        changed = await approved_then_changed(env, client)
        report = await review_server(client, LOOKUP, policy_path=POLICY_PATH)

        assert report.outcome == "quarantined"
        assert report.detection["policy_ids"] == ["POL-001", "POL-002"]
        assert report.detection["scanned_fields"] == ["description"]
        quarantine = report.quarantine
        assert quarantine.status == "applied"
        assert quarantine.record.observed_revision == changed.observed_revision
        types = event_types(client)
        assert types.index("quarantine_requested") < types.index("quarantine_applied")
        applied = next(e for e in client.store.events(LOOKUP)
                       if e["event_type"] == "quarantine_applied")
        assert applied["event_id"] == quarantine.applied_event_id
        assert applied["detail"]["quarantine_requested_event_id"] == quarantine.requested_event_id
        assert "verified_blocked" not in types  # not until there is evidence

        verification = await verify_blocked(client, LOOKUP, "lookup_document", ARGS,
                                            lambda: env.received_calls(LOOKUP),
                                            quarantine=quarantine)
        assert verification["verified"] and verification["problems"] == []
        assert verification["blocked_reason"] == "quarantined"
        assert verification["received_before"] == verification["received_after"] == 1
        verified = next(e for e in client.store.events(LOOKUP)
                        if e["event_type"] == "verified_blocked")
        assert verified["detail"]["quarantine_applied_event_id"] == quarantine.applied_event_id

        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "quarantined"
        assert not (await client.call_tool(CONTROL, "health_check")).isError
    assert env.received_calls(LOOKUP) == 1
    assert env.received_calls(CONTROL) == 1


async def test_stale_result_after_revision_change_is_recorded_not_applied(env):
    async with env.client() as client:
        await approved_then_changed(env, client)

        async def change_revision():
            env.mutate("policy-override-only")
            await client.observe(LOOKUP)

        report = await review_server(client, LOOKUP, policy_path=POLICY_PATH,
                                     max_attempts=1, before_apply=change_revision)
        assert report.outcome == "stale" and report.quarantine is None
        assert report.stale[0].startswith("revision is now")
        record = client.store.get(LOOKUP)
        assert record.state is TrustState.PENDING_REVIEW
        types = event_types(client)
        assert "assessment_stale" in types and "quarantine_requested" not in types

        # A current assessment is obtained separately and applies to the new revision.
        current = await review_server(client, LOOKUP, policy_path=POLICY_PATH)
        assert current.outcome == "quarantined"
        assert current.quarantine.record.observed_revision == record.observed_revision
        assert current.detection["policy_ids"] == ["POL-002"]
    assert env.received_calls(LOOKUP) == 1


async def test_stale_result_after_generation_only_change_is_not_applied(env):
    """Same revision, but an observation failure and recovery bumped the generation."""
    async with env.client() as client:
        changed = await approved_then_changed(env, client)
        definition = env.fixture["baseline"] | {
            "description": next(c["replacement_description"] for c in env.fixture["scenarios"]
                                if c["id"] == "private-content-demand")}

        async def fail_and_recover_same_revision():
            env.serve_raw([definition, definition | {"description": "duplicate"}])
            with pytest.raises(ObservationError):
                await client.observe(LOOKUP)
            env.serve_raw(definition)
            recovered = await client.observe(LOOKUP)
            assert recovered.observed_revision == changed.observed_revision
            assert recovered.generation > changed.generation

        report = await review_server(client, LOOKUP, policy_path=POLICY_PATH,
                                     max_attempts=1, before_apply=fail_and_recover_same_revision)
        assert report.outcome == "stale"
        assert report.stale[0].startswith("generation is now")
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW
        assert "quarantine_applied" not in event_types(client)

        current = await review_server(client, LOOKUP, policy_path=POLICY_PATH)
        assert current.outcome == "quarantined"


async def test_stale_result_after_policy_context_change_is_not_applied(env, tmp_path):
    rules = tmp_path / "hard_deny.yaml"
    shutil.copy(REPO_ROOT / "rules" / "hard_deny.yaml", rules)
    async with env.client() as client:
        await approved_then_changed(env, client)

        async def edit_rules():
            rules.write_text(rules.read_text() + "\n# operator edited the rules\n")

        report = await review_server(client, LOOKUP, policy_path=POLICY_PATH, rules_path=rules,
                                     max_attempts=1, before_apply=edit_rules)
        assert report.outcome == "stale"
        assert report.stale[0] == "active policy revision changed"
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW

        current = await review_server(client, LOOKUP, policy_path=POLICY_PATH, rules_path=rules)
        assert current.outcome == "quarantined"


async def test_detector_failure_leaves_change_blocked_and_unapproved(env, monkeypatch):
    async with env.client() as client:
        await approved_then_changed(env, client)
        monkeypatch.setenv("MCP_TRUST_SEMGREP", "/nonexistent/semgrep")
        report = await review_server(client, LOOKUP, policy_path=POLICY_PATH)
        assert report.outcome == "detector_failed"
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW
        assert "detector_failed" in event_types(client)
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
    assert env.received_calls(LOOKUP) == 1


async def test_clean_scan_never_approves(env):
    async with env.client() as client:
        await approved_then_changed(env, client, scenario="harmless-wording-change")
        report = await review_server(client, LOOKUP, policy_path=POLICY_PATH)
        assert report.outcome == "pending_review" and report.detection["policy_ids"] == []
        assert "hard_deny_scan_clean" in event_types(client)
        with pytest.raises(CallBlocked):
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
    assert env.received_calls(LOOKUP) == 1


async def test_verification_without_applied_quarantine_is_never_recorded_as_verified(env):
    async with env.client() as client:
        changed = await approved_then_changed(env, client)
        stale = HardDenyOutcome("stale", changed, "revision is now elsewhere")
        detail = await verify_blocked(client, LOOKUP, "lookup_document", ARGS,
                                      lambda: env.received_calls(LOOKUP), quarantine=stale)
        assert not detail["verified"]
        assert detail["blocked_reason"] == "pending_review"
        types = event_types(client)
        assert "verification_failed" in types and "verified_blocked" not in types
