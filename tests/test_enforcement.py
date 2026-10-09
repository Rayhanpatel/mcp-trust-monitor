"""M1 enforcement boundary over real stdio MCP transport.

Each test launches the controlled demo servers as subprocesses. The server-side
received-call count comes from the server process's own request log, so it is
independent of the client's bookkeeping.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.managed_client import CallBlocked, ObservationError
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.trust_store import ObservationRequiredError, StaleDecisionError, TrustState

from conftest import CONTROL, FIXTURE_PATH, LOOKUP, observe_and_approve

pytestmark = pytest.mark.anyio

ARGS = {"title": "Annual report"}


async def test_explicitly_approved_baseline_is_callable(env):
    """REQ-TRU-01, REQ-ENF-02: observation alone does not authorize; explicit approval does."""
    async with env.client() as client:
        observed = await client.observe(LOOKUP)
        assert observed.state is TrustState.UNREVIEWED
        assert observed.observed_revision == server_revision([env.fixture["baseline"]])

        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "unreviewed"
        assert env.received_calls(LOOKUP) == 0

        await client.approve(LOOKUP, revision=observed.observed_revision,
                             expected_generation=observed.generation, actor="test-operator")
        result = await client.call_tool(LOOKUP, "lookup_document", ARGS)

    assert not result.isError
    assert result.structuredContent["title"] == "Annual report"
    assert env.received_calls(LOOKUP) == 1


async def test_quarantine_blocks_next_call_before_dispatch_and_control_stays_callable(env):
    """REQ-ENF-01, REQ-ENF-03, REQ-ENF-04"""
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        await observe_and_approve(client, CONTROL)
        await client.call_tool(LOOKUP, "lookup_document", ARGS)
        await client.call_tool(CONTROL, "health_check")
        assert env.received_calls(LOOKUP) == 1
        assert env.received_calls(CONTROL) == 1

        await client.quarantine(LOOKUP, actor="test-operator", reason="test")
        assert not client.is_connected(LOOKUP)  # connection closed, cached tools dropped
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "quarantined"
        assert client.dispatch_count(LOOKUP) == 1
        assert env.received_calls(LOOKUP) == 1

        result = await client.call_tool(CONTROL, "health_check")
        assert not result.isError
        assert env.received_calls(CONTROL) == 2

    blocked_events = [e for e in client.store.events(LOOKUP) if e["event_type"] == "call_blocked"]
    assert blocked_events[-1]["detail"] == {"tool": "lookup_document", "reason": "quarantined"}


async def test_quarantine_from_another_process_blocks_an_open_session(env):
    """REQ-ENF-01: the gate reads persisted state at dispatch, not a cached decision.

    The connection stays open and the server process stays alive, so the block can
    only come from the trust check.
    """
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert client.is_connected(LOOKUP)

        subprocess.run(
            [sys.executable, "-m", "mcp_trust_monitor", "--state-dir", str(env.state_dir),
             "--fixture", str(FIXTURE_PATH), "quarantine", LOOKUP, "--reason", "cli test"],
            check=True, capture_output=True,
        )

        assert client.is_connected(LOOKUP)
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "quarantined"
        assert env.received_calls(LOOKUP) == 1
        assert not client.is_connected(LOOKUP)  # the detected quarantine closes the session


async def test_quarantine_survives_client_restart(env):
    """REQ-TRU-04, REQ-ENF-03, REQ-ENF-04"""
    async with env.client() as first:
        await observe_and_approve(first, LOOKUP)
        await observe_and_approve(first, CONTROL)
        await first.call_tool(LOOKUP, "lookup_document", ARGS)
        await first.quarantine(LOOKUP, actor="test-operator", reason="test")
    first.store.close()
    lists_before = env.received_lists(LOOKUP)

    async with env.client() as second:
        assert second.store.get(LOOKUP).state is TrustState.QUARANTINED
        with pytest.raises(CallBlocked):
            await second.call_tool(LOOKUP, "lookup_document", ARGS)
        # The call path did not even launch the quarantined server.
        assert env.received_lists(LOOKUP) == lists_before

        # Re-observing the unchanged baseline does not lift quarantine.
        assert (await second.observe(LOOKUP)).state is TrustState.QUARANTINED
        with pytest.raises(CallBlocked):
            await second.call_tool(LOOKUP, "lookup_document", ARGS)

        assert not (await second.call_tool(CONTROL, "health_check")).isError

    assert env.received_calls(LOOKUP) == 1
    assert env.received_calls(CONTROL) == 1


async def test_changed_revision_needs_new_explicit_approval_and_stale_decisions_fail(env):
    """REQ-TRU-02, REQ-TRU-03, REQ-TRU-05"""
    async with env.client() as client:
        baseline = await observe_and_approve(client, LOOKUP)
        await client.call_tool(LOOKUP, "lookup_document", ARGS)

        env.mutate("harmless-wording-change")
        changed = await client.observe(LOOKUP)
        assert changed.observed_revision != baseline.observed_revision
        assert changed.state is TrustState.PENDING_REVIEW

        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"

        with pytest.raises(StaleDecisionError):  # approval of the superseded revision
            await client.approve(LOOKUP, revision=baseline.observed_revision,
                                 expected_generation=None, actor="stale-replay")
        with pytest.raises(StaleDecisionError):  # current revision, outdated generation
            await client.approve(LOOKUP, revision=changed.observed_revision,
                                 expected_generation=baseline.generation, actor="stale-replay")
        with pytest.raises(CallBlocked):
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert env.received_calls(LOOKUP) == 1

        await client.approve(LOOKUP, revision=changed.observed_revision,
                             expected_generation=changed.generation, actor="test-operator")
        assert not (await client.call_tool(LOOKUP, "lookup_document", ARGS)).isError
        assert env.received_calls(LOOKUP) == 2


async def test_reverting_metadata_does_not_silently_restore_approval(env):
    """REQ-TRU-03: approval invalidated by a change stays invalid after a revert."""
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        env.mutate("private-content-demand")
        await client.observe(LOOKUP)
        env.restore_baseline()
        reverted = await client.observe(LOOKUP)
        assert reverted.state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
    assert env.received_calls(LOOKUP) == 0


async def test_new_connection_observes_changed_metadata_before_dispatch(env):
    """REQ-ENF-01, REQ-TRU-03: a reconnecting client cannot call a changed tool."""
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
    env.mutate("private-content-demand")

    async with env.client() as client:
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
    assert env.received_calls(LOOKUP) == 0


async def test_policy_revision_change_blocks_until_reapproved(env, tmp_path):
    """REQ-TRU-02: approval is bound to the policy revision it was made under."""
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        await client.call_tool(LOOKUP, "lookup_document", ARGS)

    edited = json.loads(env.policy_path.read_text())
    edited["revision"] = "test-edit"
    edited_path = tmp_path / "edited-policy.json"
    edited_path.write_text(json.dumps(edited))

    async with env.client(policy_path=edited_path) as client:
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "policy_revision_changed"
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW
    assert env.received_calls(LOOKUP) == 1


async def test_tool_absent_from_approved_revision_is_blocked(env):
    """REQ-ENF-02"""
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "delete_everything", {})
        assert blocked.value.reason == "tool_not_in_approved_revision"
    assert env.received_calls(LOOKUP) == 0


MALFORMED_METADATA = {
    # A valid MCP response that the client must reject (REQ-REV-01, REQ-REV-02).
    "duplicate-tool-names": lambda fx: [fx["baseline"],
                                        {**fx["baseline"], "description": "Shadow definition."}],
    # Metadata the server cannot even serialize, so tools/list returns a JSON-RPC error.
    "server-error": lambda fx: {**fx["baseline"], "inputSchema": "not-a-schema"},
}
# Observation failures: two tools/list failures, plus a server process that exits
# before MCP initialization (a connection/initialization failure).
OBSERVATION_FAILURES = (*sorted(MALFORMED_METADATA), "startup-failure")


def induce_observation_failure(env, kind: str) -> None:
    if kind == "startup-failure":
        demo.set_startup_failure(env.state_dir, LOOKUP, True)
    else:
        env.serve_raw(MALFORMED_METADATA[kind](env.fixture))


def clear_observation_failure(env) -> None:
    demo.set_startup_failure(env.state_dir, LOOKUP, False)
    env.restore_baseline()


@pytest.mark.parametrize("failure", OBSERVATION_FAILURES)
async def test_failed_observation_cannot_leave_a_connection_eligible_for_dispatch(env, failure):
    """Regression (review of c53b81c): a failed observation must not let a retry dispatch.

    REQ-REV-02, REQ-ENF-01, REQ-TRU-03. Sequence from the review: approve the baseline,
    close the client, make observation fail, fail a call_tool, swap in the
    private-content-demand fixture, and retry on the same client.
    """
    async with env.client() as first:
        baseline = await observe_and_approve(first, LOOKUP)
        await observe_and_approve(first, CONTROL)
        await first.call_tool(LOOKUP, "lookup_document", ARGS)
    assert env.received_calls(LOOKUP) == 1

    induce_observation_failure(env, failure)
    async with env.client() as client:
        with pytest.raises(ObservationError):
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert not client.is_connected(LOOKUP)
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW

        # The failure invalidated approval, so a retry is refused without contacting the server.
        lists_before = env.received_lists(LOOKUP)
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
        assert env.received_lists(LOOKUP) == lists_before
        assert env.received_calls(LOOKUP) == 1

        clear_observation_failure(env)
        env.mutate("private-content-demand")
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW
        assert env.received_calls(LOOKUP) == 1

        # The unaffected control stays usable on the same client.
        assert not (await client.call_tool(CONTROL, "health_check")).isError

        # Recovery needs valid metadata and an explicit approval; reverting alone is not enough.
        env.restore_baseline()
        recovered = await client.observe(LOOKUP)
        assert recovered.observed_revision == baseline.observed_revision
        assert recovered.state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        await client.approve(LOOKUP, revision=recovered.observed_revision,
                             expected_generation=recovered.generation, actor="test-operator")
        assert not (await client.call_tool(LOOKUP, "lookup_document", ARGS)).isError

    assert env.received_calls(LOOKUP) == 2
    assert env.received_calls(CONTROL) == 1
    failures = [e for e in client.store.events(LOOKUP) if e["event_type"] == "observation_failed"]
    assert [(e["from_state"], e["to_state"]) for e in failures] == [("approved", "pending_review")]


@pytest.mark.parametrize("failure", OBSERVATION_FAILURES)
async def test_observation_failure_in_one_session_blocks_every_session(env, failure):
    """Regression (review of 13440e0): an observation failure is shared, not per session.

    REQ-REV-02, REQ-ENF-01. Independent reproduction from the review: sessions A and B
    validate the approved baseline; A's observation fails; the server switches to
    private-content-demand; B must not dispatch on its cached validation.
    """
    async with env.client() as a, env.client() as b:
        baseline = await observe_and_approve(a, LOOKUP)
        await observe_and_approve(a, CONTROL)
        assert (await b.observe(LOOKUP)).state is TrustState.APPROVED
        assert b.is_connected(LOOKUP)

        induce_observation_failure(env, failure)
        if failure == "startup-failure":
            await a.aclose()  # A must open a new connection, which fails to start
        with pytest.raises(ObservationError):
            await a.observe(LOOKUP)
        assert a.store.get(LOOKUP).state is TrustState.PENDING_REVIEW

        clear_observation_failure(env)
        env.mutate("private-content-demand")
        with pytest.raises(CallBlocked) as blocked:
            await b.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
        assert env.received_calls(LOOKUP) == 0

        # The unaffected control stays usable from both sessions.
        assert not (await a.call_tool(CONTROL, "health_check")).isError
        assert not (await b.call_tool(CONTROL, "health_check")).isError

        # Recovery: valid metadata is observed, and only explicit approval re-enables calls.
        env.restore_baseline()
        recovered = await b.observe(LOOKUP)
        assert recovered.observed_revision == baseline.observed_revision
        assert recovered.state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await a.call_tool(LOOKUP, "lookup_document", ARGS)
        await b.approve(LOOKUP, revision=recovered.observed_revision,
                        expected_generation=recovered.generation, actor="test-operator")
        assert not (await a.call_tool(LOOKUP, "lookup_document", ARGS)).isError
        assert not (await b.call_tool(LOOKUP, "lookup_document", ARGS)).isError

    assert env.received_calls(LOOKUP) == 2
    assert env.received_calls(CONTROL) == 2


@pytest.mark.parametrize("failure", OBSERVATION_FAILURES)
async def test_approval_after_a_failure_requires_a_successful_observation(env, failure):
    """Regression (review of f3afdab): no approval on stale evidence after a failure.

    REQ-REV-02, REQ-TRU-02. Review sequence: A and B validate the approved baseline;
    A's observation fails; the server switches to private-content-demand; the operator
    approves through B with the stored revision and current generation, without a
    successful observation in between.
    """
    async with env.client() as a, env.client() as b:
        baseline = await observe_and_approve(a, LOOKUP)
        await observe_and_approve(a, CONTROL)
        await b.observe(LOOKUP)

        induce_observation_failure(env, failure)
        if failure == "startup-failure":
            await a.aclose()
        with pytest.raises(ObservationError):
            await a.observe(LOOKUP)
        failed = b.store.get(LOOKUP)
        assert failed.state is TrustState.PENDING_REVIEW
        assert failed.observation_failed_at is not None

        clear_observation_failure(env)
        env.mutate("private-content-demand")
        with pytest.raises(ObservationRequiredError):
            await b.approve(LOOKUP, revision=failed.observed_revision,
                            expected_generation=failed.generation, actor="premature-operator")
        with pytest.raises(CallBlocked) as blocked:
            await b.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
        assert env.received_calls(LOOKUP) == 0
        assert not (await b.call_tool(CONTROL, "health_check")).isError

        # A successful observation is recovery evidence; here it records the changed metadata.
        changed = await b.observe(LOOKUP)
        assert changed.observation_failed_at is None
        assert changed.observed_revision != baseline.observed_revision
        assert changed.state is TrustState.PENDING_REVIEW
        with pytest.raises(StaleDecisionError):  # the premature decision stays unusable
            await b.approve(LOOKUP, revision=failed.observed_revision,
                            expected_generation=failed.generation, actor="premature-operator")

        env.restore_baseline()
        recovered = await b.observe(LOOKUP)
        assert recovered.observed_revision == baseline.observed_revision
        assert recovered.state is TrustState.PENDING_REVIEW
        await b.approve(LOOKUP, revision=recovered.observed_revision,
                        expected_generation=recovered.generation, actor="test-operator")
        assert not (await a.call_tool(LOOKUP, "lookup_document", ARGS)).isError
    assert env.received_calls(LOOKUP) == 1


async def test_recovery_requirement_survives_restart_and_repeated_failures(env):
    """REQ-REV-02, REQ-TRU-04: the requirement is persisted, and a new failure re-arms it."""
    duplicate = MALFORMED_METADATA["duplicate-tool-names"](env.fixture)
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        env.serve_raw(duplicate)
        with pytest.raises(ObservationError):
            await client.observe(LOOKUP)
    client.store.close()

    async with env.client() as restarted:
        record = restarted.store.get(LOOKUP)
        assert record.observation_failed_at is not None
        with pytest.raises(ObservationRequiredError):
            await restarted.approve(LOOKUP, revision=record.observed_revision,
                                    expected_generation=record.generation, actor="test-operator")
        cli = subprocess.run(
            [sys.executable, "-m", "mcp_trust_monitor", "--state-dir", str(env.state_dir),
             "--fixture", str(FIXTURE_PATH), "approve", LOOKUP,
             "--revision", record.observed_revision],
            capture_output=True, text=True)
        assert cli.returncode == 2
        assert "observe it successfully" in cli.stderr

        # Unchanged metadata counts as recovery evidence but does not restore approval.
        env.restore_baseline()
        recovered = await restarted.observe(LOOKUP)
        assert recovered.observed_revision == record.observed_revision
        assert recovered.observation_failed_at is None
        assert recovered.state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await restarted.call_tool(LOOKUP, "lookup_document", ARGS)

        # Another failure before approval re-arms the requirement.
        env.serve_raw(duplicate)
        with pytest.raises(ObservationError):
            await restarted.observe(LOOKUP)
        again = restarted.store.get(LOOKUP)
        with pytest.raises(ObservationRequiredError):
            await restarted.approve(LOOKUP, revision=again.observed_revision,
                                    expected_generation=again.generation, actor="test-operator")

        env.restore_baseline()
        final = await restarted.observe(LOOKUP)
        await restarted.approve(LOOKUP, revision=final.observed_revision,
                                expected_generation=final.generation, actor="test-operator")
        assert not (await restarted.call_tool(LOOKUP, "lookup_document", ARGS)).isError
    assert env.received_calls(LOOKUP) == 1


async def test_failed_reobservation_of_an_open_session_requires_fresh_validation(env):
    """REQ-REV-02, REQ-ENF-01: a validated session loses eligibility when re-observation fails."""
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert client.is_connected(LOOKUP)

        env.serve_raw(MALFORMED_METADATA["duplicate-tool-names"](env.fixture))
        with pytest.raises(ObservationError):
            await client.observe(LOOKUP)
        assert not client.is_connected(LOOKUP)
        assert client.store.get(LOOKUP).state is TrustState.PENDING_REVIEW

        env.mutate("private-content-demand")
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
    assert env.received_calls(LOOKUP) == 1


async def test_session_validated_at_an_older_revision_is_revalidated_before_dispatch(env):
    """REQ-ENF-01, REQ-TRU-02: a session is bound to the revision it last validated.

    Another client approves revision B. The server then moves to revision C, which
    nobody has observed. The first client's session, validated at A, must re-observe
    before dispatch instead of trusting the persisted approval of B.
    """
    async with env.client() as client:
        await observe_and_approve(client, LOOKUP)
        await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert client.is_connected(LOOKUP)

        env.mutate("harmless-wording-change")
        async with env.client() as other:
            approved_b = await observe_and_approve(other, LOOKUP)
        assert approved_b.state is TrustState.APPROVED

        env.mutate("private-content-demand")
        with pytest.raises(CallBlocked) as blocked:
            await client.call_tool(LOOKUP, "lookup_document", ARGS)
        assert blocked.value.reason == "pending_review"
    assert env.received_calls(LOOKUP) == 1


def test_cli_demo_walkthrough_runs():
    """The README run command completes and shows the blocked call with an unchanged count."""
    completed = subprocess.run([sys.executable, "-m", "mcp_trust_monitor", "demo"],
                               check=True, capture_output=True, text=True, timeout=120)
    out = completed.stdout
    assert "BLOCKED before dispatch (quarantined)" in out
    assert "stale approval of the old revision rejected" in out
    tail = out.split("[5] restart the managed client")[1]
    assert f"received tools/call count for {LOOKUP}: 2" in tail
    assert f"received tools/call count for {CONTROL}: 3" in tail
