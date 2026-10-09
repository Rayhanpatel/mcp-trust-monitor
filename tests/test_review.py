"""M2 hard-deny review over real stdio MCP transport with real Semgrep.

REQ-DEC-01, REQ-DEC-04, REQ-AUD-02, REQ-TRU-02. The server-side received-call
counter comes from the demo server's own request log.
"""

from __future__ import annotations

import shutil

import pytest

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.managed_client import CallBlocked, ObservationError
from mcp_trust_monitor.review import review_server, verify_blocked
from mcp_trust_monitor.trust_store import HardDenyOutcome, TrustState

from conftest import CONTROL, LOOKUP, POLICY_PATH, REPO_ROOT, observe_and_approve

pytestmark = pytest.mark.anyio

ARGS = {"title": "Annual report"}


def strict_counter(env, server_id=LOOKUP):
    """The evidence counter demo-m2 uses: raises instead of reading missing data as 0."""
    return demo.received_call_counter(env.state_dir, server_id)


def request_log(env, server_id=LOOKUP):
    return demo.server_dir(env.state_dir, server_id) / "received.jsonl"


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
                                            strict_counter(env), quarantine=quarantine)
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


async def quarantined_lookup(env, client, *, call_first: bool = True):
    await observe_and_approve(client, LOOKUP)
    if call_first:
        assert not (await client.call_tool(LOOKUP, "lookup_document", ARGS)).isError
    env.mutate("private-content-demand")
    await client.observe(LOOKUP)
    report = await review_server(client, LOOKUP, policy_path=POLICY_PATH)
    assert report.outcome == "quarantined"
    return report.quarantine


def assert_failed_not_verified(client, detail):
    assert detail["verified"] is False
    assert any(p.startswith("server-side counter unavailable") for p in detail["problems"])
    types = event_types(client)
    assert "verification_failed" in types and "verified_blocked" not in types


async def test_missing_evidence_before_verification_is_verification_failed(env):
    """Regression (review of a54affb): a missing request log must never read as 0 calls."""
    async with env.client() as client:
        quarantine = await quarantined_lookup(env, client)
        request_log(env).unlink()
        detail = await verify_blocked(client, LOOKUP, "lookup_document", ARGS,
                                      strict_counter(env), quarantine=quarantine)
        assert detail["received_before"] is None and detail["received_after"] is None
        assert detail["blocked_reason"] == "quarantined"  # the block itself still happened
        assert_failed_not_verified(client, detail)


async def test_evidence_disappearing_between_reads_is_verification_failed(env):
    async with env.client() as client:
        quarantine = await quarantined_lookup(env, client)
        strict = strict_counter(env)

        def read_then_lose_evidence():
            value = strict()
            if request_log(env).exists():
                request_log(env).unlink()
            return value

        detail = await verify_blocked(client, LOOKUP, "lookup_document", ARGS,
                                      read_then_lose_evidence, quarantine=quarantine)
        assert detail["received_before"] == 1 and detail["received_after"] is None
        assert_failed_not_verified(client, detail)


async def test_valid_zero_evidence_still_verifies(env):
    """Control: a started server that received no calls is a real zero, not missing."""
    async with env.client() as client:
        quarantine = await quarantined_lookup(env, client, call_first=False)
        assert request_log(env).exists()
        detail = await verify_blocked(client, LOOKUP, "lookup_document", ARGS,
                                      strict_counter(env), quarantine=quarantine)
        assert detail["verified"] and detail["problems"] == []
        assert detail["received_before"] == detail["received_after"] == 0
        assert "verified_blocked" in event_types(client)


@pytest.mark.parametrize("content", ["not json\n", '["a list"]\n', '{"no_method": 1}\n',
                                     '{"method": 7}\n'],
                         ids=["not-json", "not-object", "no-method", "method-not-string"])
def test_strict_counter_rejects_malformed_logs(tmp_path, content):
    log = demo.server_dir(tmp_path, LOOKUP) / "received.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text('{"method": "tools/call"}\n' + content)
    with pytest.raises(demo.EvidenceUnavailable):
        demo.received_call_count(tmp_path, LOOKUP)


def test_strict_counter_distinguishes_zero_from_missing_and_unreadable(tmp_path):
    with pytest.raises(demo.EvidenceUnavailable):
        demo.received_call_count(tmp_path, LOOKUP)  # missing
    log = demo.server_dir(tmp_path, LOOKUP) / "received.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text("")
    assert demo.received_call_count(tmp_path, LOOKUP) == 0  # present and empty: real zero
    log.write_text('{"method": "tools/list"}\n{"method": "tools/call"}\n')
    assert demo.received_call_count(tmp_path, LOOKUP) == 1
    log.unlink()
    log.mkdir()  # unreadable as a file
    with pytest.raises(demo.EvidenceUnavailable):
        demo.received_call_count(tmp_path, LOOKUP)
