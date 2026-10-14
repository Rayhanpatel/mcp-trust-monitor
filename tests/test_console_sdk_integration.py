"""Independent SDK/console checks against a separately configured real stdio server."""
from __future__ import annotations

import asyncio
from dataclasses import replace
from http.client import HTTPConnection
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_trust_monitor.config import MonitorConfig, ServerConfig
from mcp_trust_monitor.console import ConsoleBackend, ConsoleServer
from mcp_trust_monitor.managed_client import CallBlocked, ObservationError
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.trust_store import TrustStore, TrustState

pytestmark = pytest.mark.anyio
SERVER = "independent/console-notes"


def external_configuration(tmp_path, **overrides):
    external = tmp_path / "external-consumer"
    external.mkdir()
    source = Path(__file__).resolve().parents[1] / "examples" / "external_stdio_server.py"
    script = external / "server.py"
    shutil.copyfile(source, script)
    definition = external / "tool.json"
    definition.write_text(json.dumps({"name": "echo_note", "description": "Echo public text.",
        "title": "Uncovered tool title", "annotations": {"readOnlyHint": True},
        "outputSchema": {"type": "object", "properties": {"uncovered": {"type": "string"}}},
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}))
    policy = external / "policy.json"
    policy.write_text(json.dumps({"policy_id": "independent-policy", "revision": "1",
        "rules": [{"id": "IND-001", "requirement": "Echo only caller-supplied public text."}]}))
    calls = external / "calls.jsonl"
    profile = ServerConfig(SERVER, sys.executable,
        (str(script), "--definition", str(definition), "--calls", str(calls)),
        origin="synthetic_fixture", **overrides)
    config = MonitorConfig(tmp_path / "owned-state", policy, {SERVER: profile})
    return config, definition, calls


async def http(console, method="GET", payload=None, *, authenticate=True):
    def send():
        connection = HTTPConnection(console.host, console.port, timeout=5)
        headers = {"Origin": console.origin}
        if authenticate:
            headers["Authorization"] = "Bearer " + console.token
        if payload is not None:
            headers["Content-Type"] = "application/json"
            headers["X-CSRF-Token"] = console.csrf_token
        body = json.dumps(payload) if payload is not None else None
        connection.request(method, "/api/action" if payload is not None else "/api/state",
                           body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result
    return await asyncio.to_thread(send)


async def test_real_sdk_console_actions_keep_catalog_and_generation_guards(tmp_path):
    config, definition, calls = external_configuration(tmp_path)
    async with TrustMonitor(config) as monitor:
        async with ConsoleServer(monitor) as console:
            assert (await http(console, authenticate=False))[0] == 401
            status, _ = await http(console, "POST", {"action": "observe", "actor": "operator",
                                                      "server_id": SERVER})
            assert status == 200
            observed = monitor.status(SERVER)
            _, raw = await http(console)
            shown = raw["result"]["servers"][0]
            assert shown["catalog"] == []
            assert shown["origin"] == "synthetic_fixture"
            assert shown["latest_observation"]["observation_id"]
            approval = {"action": "approve", "actor": "console-operator", "server_id": SERVER,
                        "revision": observed.observed_revision, "generation": observed.generation}
            assert (await http(console, "POST", approval))[0] == 200
            _, raw = await http(console)
            entry, = raw["result"]["servers"][0]["catalog"]
            assert set(entry["definition"]) == {"name", "description", "inputSchema"}
            assert entry["selection"]["session_id"]
            assert any(event["event_type"] == "approved" and event["actor"] == "console-operator"
                       for event in monitor.events(SERVER))
            tool = json.loads(definition.read_text())
            tool["description"] = '<script>untrusted description</script> Changed wording.'
            definition.write_text(json.dumps(tool))
            await monitor.observe(SERVER)
            assert (await http(console, "POST", approval))[0] == 409
            _, raw = await http(console)
            shown = raw["result"]["servers"][0]
            assert shown["catalog"] == []
            assert shown["state"] == "pending_review"
            assert "<script>" in shown["observed_tools"][0]["description"]
            assert calls.read_text() == ""  # Observation and approval sent no tools/call.


async def test_selection_from_another_live_session_cannot_dispatch(tmp_path):
    config, _, calls = external_configuration(tmp_path)
    async with TrustMonitor(config) as monitor:
        observed = await monitor.observe(SERVER)
        await monitor.approve(SERVER, revision=observed.observed_revision,
                              expected_generation=observed.generation, actor="operator")
        token = monitor.catalog(SERVER)[0].selection
        second = monitor.new_session()
        await second.observe(SERVER)
        with pytest.raises(CallBlocked, match="stale_selection_session"):
            await second.call_tool(SERVER, "echo_note", {"text": "blocked"}, selection=token)
        assert calls.read_text() == ""
        await monitor.call_tool(SERVER, "echo_note", {"text": "allowed"}, selection=token)
        assert len(calls.read_text().splitlines()) == 1


async def test_launch_profile_remains_bound_when_host_changes_directory(tmp_path, monkeypatch):
    original = tmp_path / "original-cwd"
    changed = tmp_path / "changed-cwd"
    original.mkdir()
    changed.mkdir()
    monkeypatch.chdir(original)
    config, _, _ = external_configuration(tmp_path)
    identity = config.servers[SERVER].launch_identity
    async with TrustMonitor(config) as monitor:
        observed = await monitor.observe(SERVER)
        await monitor.approve(SERVER, revision=observed.observed_revision,
                              expected_generation=observed.generation, actor="operator")
        monkeypatch.chdir(changed)
        assert config.servers[SERVER].launch_identity == identity
        refreshed = await monitor.observe(SERVER)
        assert refreshed.launch_identity == identity
        assert refreshed.state is TrustState.APPROVED
        assert monitor.catalog(SERVER)


async def test_missing_secret_reference_finishes_and_records_observation_failure(tmp_path, monkeypatch):
    monkeypatch.delenv("MTM_TEST_NONEXISTENT_SECRET", raising=False)
    config, _, _ = external_configuration(tmp_path,
        secret_env={"UPSTREAM_KEY": "MTM_TEST_NONEXISTENT_SECRET"})
    async with TrustMonitor(config) as monitor:
        with pytest.raises(ObservationError):
            await asyncio.wait_for(monitor.observe(SERVER), timeout=1)
        assert any(event["event_type"] == "observation_failed" for event in monitor.events(SERVER))
        assert monitor.catalog(SERVER) == ()


async def test_slow_model_does_not_delay_observation_invalidation(tmp_path):
    started, release = asyncio.Event(), asyncio.Event()

    async def slow_review(monitor, server_id):
        started.set()
        await release.wait()

    config, definition, calls = external_configuration(tmp_path)
    config = replace(config, reviewer=slow_review, poll_interval=0.1, max_concurrency=1)
    async with TrustMonitor(config) as monitor:
        await monitor.start_monitor()
        try:
            await asyncio.wait_for(started.wait(), timeout=3)
            observed = monitor.status(SERVER)
            await monitor.approve(SERVER, revision=observed.observed_revision,
                                  expected_generation=observed.generation, actor="operator")
            assert monitor.catalog(SERVER)
            tool = json.loads(definition.read_text())
            tool["description"] = "Changed metadata while review service remains pending."
            definition.write_text(json.dumps(tool))

            async def changed():
                while monitor.status(SERVER).observed_revision == observed.observed_revision:
                    await asyncio.sleep(0.01)

            await asyncio.wait_for(changed(), timeout=1.5)
            assert monitor.status(SERVER).state is TrustState.PENDING_REVIEW
            assert monitor.catalog(SERVER) == ()
            assert calls.read_text() == ""
        finally:
            release.set()


async def test_readonly_operator_snapshot_does_not_acquire_owner_or_mutate_records(tmp_path):
    config, _, _ = external_configuration(tmp_path)
    async with TrustMonitor(config) as monitor:
        observed = await monitor.observe(SERVER)
        marker = (config.state_dir / "owner.unclean").read_bytes()
        event_ids = [event["event_id"] for event in monitor.events()]
        reader = TrustStore.open_readonly(config.state_dir / "trust.sqlite3", config.client_id)
        try:
            assert reader.get(SERVER).observed_revision == observed.observed_revision
            assert len(reader.records()) == 1
        finally:
            reader.close()
        assert (config.state_dir / "owner.unclean").read_bytes() == marker
        assert [event["event_id"] for event in monitor.events()] == event_ids
        assert monitor.status(SERVER).generation == observed.generation


async def test_console_refuses_memory_from_a_different_owner(tmp_path):
    config, _, _ = external_configuration(tmp_path)
    async with TrustMonitor(config) as monitor:
        foreign = TrustStore(tmp_path / "foreign.sqlite3")
        try:
            with pytest.raises(ValueError, match="same|owner|store"):
                ConsoleBackend(monitor, memory=SimpleNamespace(store=foreign))
        finally:
            foreign.close()
