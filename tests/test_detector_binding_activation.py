"""A detector change is a genuine decision-context change (REQ-DEC-06, REQ-TRU-02/03).

Corrective-alpha defect 2: reloading (or reopening with) different valid detector rules
under unchanged policy content used to keep approval, generation and selection tokens,
because only the policy document was bound. Approvals, generations, selection tokens
and console intents now bind the effective policy/detector pair. These tests use the
public SDK and a real stdio server, and count the server's own call log as independent
received-call evidence.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor
from mcp_trust_monitor.console import ConsoleBackend
from mcp_trust_monitor.detector import rules_digest_of
from mcp_trust_monitor.managed_client import CallBlocked
from mcp_trust_monitor.policy import DetectorBinding, load_policy
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.trust_store import StaleDecisionError, TrustState, TrustStore

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tests" / "helpers" / "monitored_server.py"
POLICY = ROOT / "policies" / "demo-policy.json"
SERVER = "detector/test"
OTHER = "detector/other"


def rules_file(path: Path, *, variant: str = "a", extra_rule: bool = False) -> Path:
    rules = [{"id": "r1", "message": f"variant {variant}", "metadata": {"policy_id": "POL-001"}},
             {"id": "r2", "message": f"variant {variant}", "metadata": {"policy_id": "POL-002"}}]
    if extra_rule:
        rules.append({"id": "r3", "message": f"variant {variant}", "metadata": {"policy_id": "POL-001"}})
    path.write_text(json.dumps({"rules": rules}))
    return path


def binding(rules: Path) -> DetectorBinding:
    mapping = {rule["id"]: rule["metadata"]["policy_id"]
               for rule in json.loads(rules.read_text())["rules"]}
    return DetectorBinding(rules, load_policy(POLICY).digest, rules_digest_of(rules.read_bytes()),
                           mapping)


def environment(tmp_path: Path, detector=None):
    definition = tmp_path / "definition.json"
    definition.write_text("{}")
    calls = tmp_path / "calls.jsonl"
    policy = tmp_path / "policy.json"
    policy.write_bytes(POLICY.read_bytes())
    profile = ServerConfig(SERVER, sys.executable, (str(HELPER), str(definition), str(calls)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", policy, {SERVER: profile},
                           poll_interval=60, timeout_seconds=30, detector=detector)
    return config, definition, calls


def call_count(calls: Path) -> int:
    return len(calls.read_text().splitlines()) if calls.exists() else 0


async def prepare(monitor, state: str, definition: Path):
    """Bring the server to `state` and return the operator's prepared intent."""
    record = await monitor.observe(SERVER)
    if state in {"pending_review", "approved", "quarantined"}:
        await monitor.approve(SERVER, revision=record.observed_revision,
                              expected_generation=record.generation, actor="initial")
    if state == "pending_review":
        definition.write_text(json.dumps({"description": "Updated local effect needing approval."}))
        await monitor.observe(SERVER)
    if state == "quarantined":
        await monitor.quarantine(SERVER, actor="operator", reason="review required")
    prepared = monitor.status(SERVER)
    assert prepared.state.value == state
    return prepared


async def act(monitor, prepared, actor="prepared-before-detector-change"):
    action = monitor.restore if prepared.state is TrustState.QUARANTINED else monitor.approve
    return await action(SERVER, revision=prepared.observed_revision,
                        expected_generation=prepared.generation, actor=actor)


def invalidations(monitor):
    return [event for event in monitor.events(SERVER)
            if event["event_type"] == "decision_context_invalidated"]


async def assert_invalidated(monitor, prepared, calls, *, token=None):
    """The detector change advanced the generation, kept the state (except approval),
    and every input prepared before it is refused without reaching the server."""
    after = monitor.status(SERVER)
    assert after.generation > prepared.generation
    expected = TrustState.PENDING_REVIEW if prepared.state is TrustState.APPROVED else prepared.state
    assert after.state is expected  # Quarantine and other states are preserved.
    if prepared.state is not TrustState.APPROVED:
        event, = invalidations(monitor)
        assert event["generation"] == after.generation
        assert event["from_state"] == event["to_state"] == prepared.state.value
    with pytest.raises(StaleDecisionError):
        await act(monitor, prepared)
    assert monitor.status(SERVER).generation == after.generation
    assert monitor.status(SERVER).state is expected
    with pytest.raises(CallBlocked):
        await monitor.call_tool(SERVER, "effect")
    if token is not None:
        with pytest.raises(CallBlocked):
            await monitor.call_tool(SERVER, "effect", selection=token)
    assert call_count(calls) == 0
    return after


async def redecide(monitor, after, calls, *, stale_token=None):
    """A decision against the current generation, under the new pair, authorizes again;
    a selection token issued before the change still selects nothing."""
    if after.state is TrustState.QUARANTINED:
        await monitor.restore(SERVER, revision=after.observed_revision,
                              expected_generation=after.generation, actor="re-reviewed")
    else:
        await monitor.approve(SERVER, revision=after.observed_revision,
                              expected_generation=after.generation, actor="re-reviewed")
    await monitor.observe(SERVER)
    if stale_token is not None:
        with pytest.raises(CallBlocked) as refused:
            await monitor.call_tool(SERVER, "effect", selection=stale_token)
        assert refused.value.reason == "stale_selection"
        assert call_count(calls) == 0
    entry, = monitor.catalog(SERVER)
    response = await monitor.call_tool(SERVER, "effect", selection=entry.selection)
    assert not response.isError
    assert call_count(calls) == 1


@pytest.mark.parametrize("state", ["unreviewed", "pending_review", "quarantined", "approved"])
@pytest.mark.parametrize("change", ["rules_content", "rule_inventory"])
async def test_reload_with_different_detector_rules_invalidates_prepared_decisions(tmp_path, state, change):
    first = binding(rules_file(tmp_path / "rules-a.json"))
    config, definition, calls = environment(tmp_path, first)
    second = binding(rules_file(tmp_path / "rules-b.json", variant="b",
                                extra_rule=change == "rule_inventory"))
    assert second.rules_digest != first.rules_digest
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, state, definition)
        token = monitor.catalog(SERVER)[0].selection if state == "approved" else None
        policy = monitor.policy
        await monitor.reload_policy(config.policy_path, second)
        assert monitor.policy == policy  # The policy document itself did not change.
        assert monitor.detector_binding == second
        after = await assert_invalidated(monitor, prepared, calls, token=token)
        await redecide(monitor, after, calls, stale_token=token)


async def test_reload_with_an_identical_detector_binding_is_a_no_op(tmp_path):
    first = binding(rules_file(tmp_path / "rules-a.json"))
    config, definition, calls = environment(tmp_path, first)
    copy = tmp_path / "copy" / "rules-a.json"
    copy.parent.mkdir()
    copy.write_bytes(first.rules_path.read_bytes())
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, "approved", definition)
        token = monitor.catalog(SERVER)[0].selection
        await monitor.reload_policy(config.policy_path)          # keeps the active detector
        await monitor.reload_policy(config.policy_path, first)   # the same object
        await monitor.reload_policy(config.policy_path, binding(copy))  # equal content elsewhere
        current = monitor.status(SERVER)
        assert (current.generation, current.state) == (prepared.generation, TrustState.APPROVED)
        assert invalidations(monitor) == []
        response = await monitor.call_tool(SERVER, "effect", selection=token)
        assert not response.isError
    assert call_count(calls) == 1


@pytest.mark.parametrize("state", ["unreviewed", "pending_review", "quarantined", "approved"])
@pytest.mark.parametrize("transition", ["changed", "enabled", "disabled"])
async def test_reopen_with_a_different_detector_is_a_genuine_change(tmp_path, state, transition):
    first = None if transition == "enabled" else binding(rules_file(tmp_path / "rules-a.json"))
    second = (None if transition == "disabled" else
              binding(rules_file(tmp_path / "rules-b.json", variant="b")))
    config, definition, calls = environment(tmp_path, first)
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, state, definition)
    async with TrustMonitor(replace(config, detector=second)) as monitor:
        await monitor.observe(SERVER)
        after = await assert_invalidated(monitor, prepared, calls)
        await redecide(monitor, after, calls)
        settled = monitor.status(SERVER).generation
    async with TrustMonitor(replace(config, detector=second)) as monitor:  # unchanged reopen
        current = monitor.status(SERVER)
        assert (current.state, current.generation) == (TrustState.APPROVED, settled)


async def test_reopen_with_an_identical_detector_keeps_approval_and_generation(tmp_path):
    first = binding(rules_file(tmp_path / "rules-a.json"))
    config, definition, calls = environment(tmp_path, first)
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, "approved", definition)
    equal = binding(rules_file(tmp_path / "elsewhere.json"))  # same bytes, other path
    for detector in (first, equal):
        async with TrustMonitor(replace(config, detector=detector)) as monitor:
            current = monitor.status(SERVER)
            assert (current.generation, current.state) == (prepared.generation, TrustState.APPROVED)
            assert invalidations(monitor) == []
            response = await monitor.observe_and_call(SERVER, "effect")
            assert not response.isError
    assert call_count(calls) == 2


async def test_detector_change_is_atomic_with_every_session(tmp_path):
    """Selections and approvals of every session of the owner use the new pair at once."""
    first = binding(rules_file(tmp_path / "rules-a.json"))
    config, definition, calls = environment(tmp_path, first)
    second = binding(rules_file(tmp_path / "rules-b.json", variant="b"))
    async with TrustMonitor(config) as monitor:
        await prepare(monitor, "approved", definition)
        other = monitor.new_session()
        await other.observe(SERVER)
        token = other.catalog(SERVER)[0].selection
        await monitor.reload_policy(config.policy_path, second)
        assert other.catalog(SERVER) == ()
        with pytest.raises(CallBlocked):
            await other.call_tool(SERVER, "effect", selection=token)
        with pytest.raises(CallBlocked):
            await other.call_tool(SERVER, "effect")
        after = monitor.status(SERVER)
        await monitor.approve(SERVER, revision=after.observed_revision,
                              expected_generation=after.generation, actor="re-reviewed")
        with pytest.raises(CallBlocked) as refused:
            await other.call_tool(SERVER, "effect", selection=token)
        assert refused.value.reason == "stale_selection"
        await other.observe(SERVER)
        entry, = other.catalog(SERVER)
        assert entry.selection.policy_binding == monitor.decision_binding
        assert entry.selection.policy_binding != token.policy_binding
        assert not (await other.call_tool(SERVER, "effect", selection=entry.selection)).isError
    assert call_count(calls) == 1


async def test_console_intent_prepared_before_a_detector_change_is_refused(tmp_path):
    first = binding(rules_file(tmp_path / "rules-a.json"))
    config, definition, calls = environment(tmp_path, first)
    second = binding(rules_file(tmp_path / "rules-b.json", variant="b"))
    async with TrustMonitor(config) as monitor:
        console = ConsoleBackend(monitor)
        await monitor.observe(SERVER)
        snapshot = await console.snapshot()
        server, = [item for item in snapshot["servers"] if item["server_id"] == SERVER]
        intent = {"action": "approve", "actor": "console-operator", "server_id": SERVER,
                  "revision": server["observed_revision"], "generation": server["generation"],
                  "policy_binding": snapshot["policy_binding"],
                  "launch_identity": server["launch_identity"]}
        await monitor.reload_policy(config.policy_path, second)
        with pytest.raises(StaleDecisionError):
            await console.action(intent)
        assert monitor.status(SERVER).state is TrustState.UNREVIEWED
        current = await console.snapshot()
        assert current["policy_binding"] != intent["policy_binding"]
        server, = [item for item in current["servers"] if item["server_id"] == SERVER]
        fresh = {**intent, "generation": server["generation"],
                 "policy_binding": current["policy_binding"]}
        await console.action(fresh)
        assert monitor.status(SERVER).state is TrustState.APPROVED
        assert not (await monitor.call_tool(SERVER, "effect")).isError
    assert call_count(calls) == 1


def pre_repair_store(path: Path, policy_binding: str, identities: dict[str, str]) -> dict[str, int]:
    """A state directory as 0.2.0a1 leaves it: activations and approvals bound to the
    policy binding alone, one approved and one quarantined server."""
    store = TrustStore(path, client_id="default")
    tools = ({"name": "effect", "description": "A local test effect.", "inputSchema": {"type": "object"}},)
    revision = server_revision(tools)
    try:
        store.invalidate_policy(policy_binding)
        for server_id in (SERVER, OTHER):
            store.record_observation(server_id, revision, tools,
                                     provenance={"launch_identity": identities[server_id]})
            store.approve(server_id, revision=revision, policy_revision=policy_binding,
                          expected_generation=store.get(server_id).generation, actor="0.2.0a1")
        store.quarantine(OTHER, actor="operator", reason="kept across upgrade")
        store.invalidate_policy(policy_binding)  # the next owner open marks every record
        return {sid: store.get(sid).generation for sid in (SERVER, OTHER)}
    finally:
        store.close()


@pytest.mark.parametrize("with_detector", [False, True])
async def test_upgrade_from_a_policy_only_binding_fails_closed_once(tmp_path, with_detector):
    """Stores written before the repair do not record which detector was active, so the
    first activation by the repaired owner is a genuine change: approvals return to
    pending review, quarantine stays, and later unchanged reopens change nothing."""
    detector = binding(rules_file(tmp_path / "rules-a.json")) if with_detector else None
    config, definition, calls = environment(tmp_path, detector)
    other = ServerConfig(OTHER, sys.executable, (str(HELPER), str(definition), str(calls)),
                         origin="synthetic_fixture")
    config = replace(config, servers={**config.servers, OTHER: other})
    database = config.state_dir / "trust.sqlite3"
    before = pre_repair_store(database, load_policy(config.policy_path).binding,
                              {sid: profile.launch_identity for sid, profile in config.servers.items()})
    async with TrustMonitor(config) as monitor:
        approved, quarantined = monitor.status(SERVER), monitor.status(OTHER)
        assert approved.state is TrustState.PENDING_REVIEW
        assert quarantined.state is TrustState.QUARANTINED
        assert approved.generation > before[SERVER] and quarantined.generation > before[OTHER]
        with pytest.raises(CallBlocked):
            await monitor.observe_and_call(SERVER, "effect")
        await monitor.approve(SERVER, revision=approved.observed_revision,
                              expected_generation=approved.generation, actor="re-reviewed")
        assert monitor.status(SERVER).approved_policy_revision == monitor.decision_binding
        assert not (await monitor.observe_and_call(SERVER, "effect")).isError
        settled = {sid: monitor.status(sid).generation for sid in (SERVER, OTHER)}
    async with TrustMonitor(config) as monitor:
        assert {sid: monitor.status(sid).generation for sid in (SERVER, OTHER)} == settled
        assert monitor.status(SERVER).state is TrustState.APPROVED
        assert monitor.status(OTHER).state is TrustState.QUARANTINED
    db = sqlite3.connect(database)
    try:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4  # no schema change
    finally:
        db.close()
    assert call_count(calls) == 1


async def test_policy_only_binding_written_after_the_repair_is_refused(tmp_path):
    """A pre-repair binary that writes an approval bound to the policy alone into a
    repaired store never authorizes under the repaired owner (mixed-version safety)."""
    config, definition, calls = environment(tmp_path)
    async with TrustMonitor(config) as monitor:
        record = await monitor.observe(SERVER)
        await monitor.approve(SERVER, revision=record.observed_revision,
                              expected_generation=record.generation, actor="operator")
        policy_only = monitor.policy.binding
        assert monitor.decision_binding != policy_only
    store = TrustStore(config.state_dir / "trust.sqlite3", client_id="default")
    try:
        store.invalidate_policy(policy_only)  # what 0.2.0a1 does when it opens the store
        current = store.get(SERVER)
        assert current.state is TrustState.PENDING_REVIEW
        store.record_observation(SERVER, current.observed_revision, current.observed_tools)
        store.approve(SERVER, revision=current.observed_revision, policy_revision=policy_only,
                      expected_generation=store.get(SERVER).generation, actor="0.2.0a1")
    finally:
        store.close()
    async with TrustMonitor(config) as monitor:
        assert monitor.status(SERVER).state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await monitor.observe_and_call(SERVER, "effect")
    assert call_count(calls) == 0
