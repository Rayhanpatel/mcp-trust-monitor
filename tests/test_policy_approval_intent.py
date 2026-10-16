"""Approval intent prepared under one policy never authorizes under another (REQ-TRU-02/03).

Batch 2 review finding R2: on a genuine policy change only approved records used to
advance their generation, so approve/restore inputs prepared before the change were
accepted afterwards for unreviewed, pending and quarantined servers, and each allowed
a real tool call. These tests use the public SDK and a real stdio server, and count
the server's own call log to prove that nothing dispatched under a stale intent.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor
from mcp_trust_monitor.managed_client import CallBlocked
from mcp_trust_monitor.trust_store import StaleDecisionError, TrustState, TrustStore

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tests" / "helpers" / "monitored_server.py"
SERVER = "intent/test"


def environment(tmp_path: Path, policy_revision: str = "1"):
    definition = tmp_path / "definition.json"
    definition.write_text("{}")
    calls = tmp_path / "calls.jsonl"
    policy = write_policy(tmp_path / "policy-a.json", policy_revision)
    profile = ServerConfig(SERVER, sys.executable, (str(HELPER), str(definition), str(calls)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", policy, {SERVER: profile},
                           poll_interval=60, timeout_seconds=30)
    return config, definition, calls


def write_policy(path: Path, revision: str, extra: str = "") -> Path:
    document = json.loads((ROOT / "policies" / "demo-policy.json").read_text())
    document["revision"] = revision
    document["rules"][0]["requirement"] += extra
    path.write_text(json.dumps(document))
    return path


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


async def act(monitor, prepared, actor="prepared-before-policy-change"):
    action = monitor.restore if prepared.state is TrustState.QUARANTINED else monitor.approve
    return await action(SERVER, revision=prepared.observed_revision,
                        expected_generation=prepared.generation, actor=actor)


def decision_events(monitor):
    return [event for event in monitor.events(SERVER)
            if event["event_type"] == "decision_context_invalidated"]


@pytest.mark.parametrize("state", ["unreviewed", "pending_review", "quarantined", "approved"])
async def test_policy_reload_makes_every_prepared_intent_stale(tmp_path, state):
    config, definition, calls = environment(tmp_path)
    changed = write_policy(tmp_path / "policy-b.json", "new-policy",
                           " Additional operator review is required.")
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, state, definition)
        before = monitor.decision_binding
        await monitor.reload_policy(changed)
        assert monitor.decision_binding != before
        after = monitor.status(SERVER)
        assert after.generation > prepared.generation
        expected = TrustState.PENDING_REVIEW if state == "approved" else prepared.state
        assert after.state is expected  # Quarantine and other states are preserved.
        if state != "approved":
            event, = decision_events(monitor)
            assert event["generation"] == after.generation
            assert event["from_state"] == event["to_state"] == state
            assert event["detail"]["previous_policy_binding"] == before
            assert event["detail"]["policy_binding"] == monitor.decision_binding
        with pytest.raises(StaleDecisionError):
            await act(monitor, prepared)
        assert monitor.status(SERVER).generation == after.generation
        assert monitor.status(SERVER).state is expected
        with pytest.raises(CallBlocked):
            await monitor.call_tool(SERVER, "effect")
        assert call_count(calls) == 0
        # A decision made against the current generation, under the new policy, works.
        if state == "quarantined":
            granted = await monitor.restore(SERVER, revision=after.observed_revision,
                                            expected_generation=after.generation, actor="re-reviewed")
            await monitor.observe(SERVER)
        else:
            granted = await monitor.approve(SERVER, revision=after.observed_revision,
                                            expected_generation=after.generation, actor="re-reviewed")
        assert granted.approved_policy_revision == monitor.decision_binding
        response = await monitor.call_tool(SERVER, "effect")
        assert not response.isError
        assert call_count(calls) == 1


@pytest.mark.parametrize("state", ["unreviewed", "pending_review", "quarantined"])
async def test_reloading_the_same_binding_is_a_no_op(tmp_path, state):
    config, definition, calls = environment(tmp_path)
    same = tmp_path / "same-policy.json"
    same.write_bytes(Path(config.policy_path).read_bytes())
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, state, definition)
        await monitor.reload_policy(config.policy_path)
        await monitor.reload_policy(same)
        assert monitor.status(SERVER).generation == prepared.generation
        assert monitor.status(SERVER).state is prepared.state
        assert decision_events(monitor) == []
        await act(monitor, prepared, actor="unchanged-policy")
        assert monitor.status(SERVER).state is TrustState.APPROVED
    assert call_count(calls) == 0


async def test_reopen_with_unchanged_policy_keeps_generations(tmp_path):
    config, definition, _ = environment(tmp_path)
    async with TrustMonitor(config) as monitor:
        # The record is created after this lifetime's activation, so its first
        # per-server activation marker is written on the next open.
        prepared = await prepare(monitor, "unreviewed", definition)
    for _ in range(2):
        async with TrustMonitor(config) as monitor:
            assert monitor.status(SERVER).generation == prepared.generation
            assert decision_events(monitor) == []
            assert [event["detail"]["policy_binding"] for event in monitor.events(SERVER)
                    if event["event_type"] == "policy_reloaded"] == [monitor.decision_binding]
    async with TrustMonitor(config) as monitor:
        await monitor.observe(SERVER)
        await act(monitor, prepared, actor="unchanged-policy-reopen")
        assert monitor.status(SERVER).state is TrustState.APPROVED


@pytest.mark.parametrize("state", ["unreviewed", "pending_review", "quarantined"])
async def test_reopen_with_a_different_policy_is_a_genuine_change(tmp_path, state):
    config, definition, calls = environment(tmp_path)
    async with TrustMonitor(config) as monitor:
        prepared = await prepare(monitor, state, definition)
        original = monitor.decision_binding
    other = write_policy(tmp_path / "policy-b.json", "reopened-policy", " Reopened under B.")
    changed = MonitorConfig(config.state_dir, other, config.servers,
                            poll_interval=60, timeout_seconds=30)
    async with TrustMonitor(changed) as monitor:
        assert monitor.decision_binding != original
        after = monitor.status(SERVER)
        assert after.generation > prepared.generation
        assert after.state is prepared.state
        event, = decision_events(monitor)
        assert event["detail"]["previous_policy_binding"] == original
        await monitor.observe(SERVER)
        with pytest.raises(StaleDecisionError):
            await act(monitor, prepared)
        assert monitor.status(SERVER).state is prepared.state
        with pytest.raises(CallBlocked):
            await monitor.call_tool(SERVER, "effect")
    assert call_count(calls) == 0


async def test_returning_to_an_earlier_policy_is_also_a_change(tmp_path):
    config, definition, calls = environment(tmp_path)
    changed = write_policy(tmp_path / "policy-b.json", "b", " B.")
    async with TrustMonitor(config) as monitor:
        await prepare(monitor, "unreviewed", definition)
        await monitor.reload_policy(changed)
        prepared = monitor.status(SERVER)
        await monitor.reload_policy(config.policy_path)
        assert monitor.status(SERVER).generation == prepared.generation + 1
        with pytest.raises(StaleDecisionError):
            await act(monitor, prepared)
    assert call_count(calls) == 0


def legacy_store(path: Path, *, marker: str | None):
    """A store as written before activations were recorded (only per-server markers)."""
    store = TrustStore(path)
    tools = ({"name": "effect", "description": "A local test effect.", "inputSchema": {"type": "object"}},)
    from mcp_trust_monitor.revision import server_revision
    store.record_observation(SERVER, server_revision(tools), tools)
    if marker is not None:
        with store.atomic():
            store._insert_event(server_id=SERVER, event_type="policy_reloaded", actor="owner",
                                detail={"policy_binding": marker})
    store.close()
    db = sqlite3.connect(path)
    db.execute("DELETE FROM policy_activations")
    db.commit()
    db.close()


@pytest.mark.parametrize("marker,binding,bumped", [
    ("policy@1#a", "policy@1#a", False),  # Unchanged against the last marker.
    ("policy@1#a", "policy@2#b", True),   # Changed against the last marker.
    (None, "policy@1#a", True),           # Records but no recorded activation: fail closed.
])
def test_stores_without_recorded_activation_use_markers_or_fail_closed(tmp_path, marker, binding, bumped):
    path = tmp_path / "trust.sqlite3"
    legacy_store(path, marker=marker)
    store = TrustStore(path)
    try:
        generation = store.get(SERVER).generation
        store.invalidate_policy(binding)
        assert store.get(SERVER).generation == generation + int(bumped)
        assert store.get(SERVER).state is TrustState.UNREVIEWED
        store.invalidate_policy(binding)
        assert store.get(SERVER).generation == generation + int(bumped)
    finally:
        store.close()


def test_first_activation_of_an_empty_store_changes_nothing(tmp_path):
    store = TrustStore(tmp_path / "trust.sqlite3")
    try:
        store.invalidate_policy("policy@1#a")
        assert store.events() == []
        store.invalidate_policy("policy@1#a")
        assert store.events() == []
    finally:
        store.close()


def schema_three_store(path: Path) -> None:
    """A store exactly as schema 3 left it: no activation table, version stamp 3."""
    legacy_store(path, marker="policy@1#a")
    db = sqlite3.connect(path)
    db.execute("DROP TABLE policy_activations")
    db.execute("PRAGMA user_version = 3")
    db.commit()
    db.close()


def test_schema_three_store_upgrades_to_four_atomically(tmp_path, monkeypatch):
    """Independent review F1: the activation table carries authorization meaning, so it is
    a versioned migration (REQ-LIB-05), not an unversioned additive table."""
    from mcp_trust_monitor import trust_store as module
    path = tmp_path / "trust.sqlite3"
    schema_three_store(path)
    read = TrustStore.open_readonly(path)  # a read-only snapshot never migrates
    read.close()
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 3
    db.close()
    execute = module._GuardedConnection.execute

    def interrupted(self, sql, *args, **kwargs):
        if "CREATE TABLE IF NOT EXISTS policy_activations" in sql:
            raise RuntimeError("migration interrupted")
        return execute(self, sql, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(module._GuardedConnection, "execute", interrupted)
        with pytest.raises(RuntimeError):
            TrustStore(path)
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == 3
    assert not db.execute("SELECT name FROM sqlite_master WHERE name='policy_activations'").fetchone()
    db.close()
    TrustStore(path).close()  # retried migration succeeds
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA user_version").fetchone()[0] == module.SCHEMA_VERSION == 4
    assert db.execute("SELECT name FROM sqlite_master WHERE name='policy_activations'").fetchone()
    db.close()


async def test_a_schema_three_binary_refuses_an_upgraded_store(tmp_path, monkeypatch):
    """An older binary must not open the store and activate a policy without recording
    it; with version 4 stamped, a binary that supports only version 3 refuses first."""
    from mcp_trust_monitor import trust_store as module
    config, definition, calls = environment(tmp_path)
    async with TrustMonitor(config) as monitor:
        await monitor.observe(SERVER)
    database = config.state_dir / "trust.sqlite3"
    before = database.read_bytes()
    monkeypatch.setattr(module, "SCHEMA_VERSION", 3)  # what 6e21602 and 8f74a74 support
    with pytest.raises(module.SchemaCompatibilityError):
        async with TrustMonitor(config):
            pass
    assert database.read_bytes() == before
    assert not (config.state_dir / "owner.unclean").exists()


async def test_an_activation_marker_without_a_recorded_activation_counts_as_a_change(tmp_path):
    """Independent review F1 scenario: a writer that marks records but does not record
    activations (as a schema-3 binary would) activates policy B; reopening with A must
    still stale decisions prepared while B was active."""
    config, definition, calls = environment(tmp_path)
    async with TrustMonitor(config) as monitor:
        await monitor.observe(SERVER)
    store = TrustStore(config.state_dir / "trust.sqlite3", client_id=config.client_id)
    with store.atomic():
        store._insert_event(server_id=SERVER, event_type="policy_reloaded", actor="owner",
                            detail={"policy_binding": "older-writer-policy@B#sha256:" + "9" * 64})
    prepared = store.get(SERVER)
    store.close()
    async with TrustMonitor(config) as monitor:  # reopen with A
        assert monitor.status(SERVER).generation > prepared.generation
        with pytest.raises(StaleDecisionError):
            await act(monitor, prepared)
        with pytest.raises(CallBlocked):
            await monitor.observe_and_call(SERVER, "effect")
    assert call_count(calls) == 0
