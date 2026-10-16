"""Real-stdio regressions: transport backpressure and policy reload at the final gate.

REQ-ENF-05: the final authorization and the hand-off of a tools/call to the transport
are one step relative to quarantine, invalidation and policy reload, and waiting for a
server that stops draining stdin never holds the trust lock. REQ-ENF-04/REQ-MON-01:
one wedged server cannot starve monitoring of unrelated servers. REQ-ENF-08: a call
refused while waiting for the transport was never handed to it and is not replayed.
"""
import asyncio
import json
import sys
import time
from pathlib import Path

import pytest
from anyio.streams.memory import MemoryObjectSendStream

from conftest import POLICY_PATH
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import (CallBlocked, ObservationError, ServerConfig,
                                              ToolOutcomeUnknown)
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.trust_store import TrustState

pytestmark = pytest.mark.anyio

HELPERS = Path(__file__).parent / "helpers"
BLOB = "x" * 2_000_000  # Far larger than any operating-system pipe buffer.


def stalling(tmp_path, server_id="stall"):
    log = tmp_path / f"{server_id}.calls"
    profile = ServerConfig(server_id, sys.executable,
                           (str(HELPERS / "stalling_server.py"), str(log)),
                           origin="synthetic_fixture")
    return profile, log


def monitored(tmp_path, server_id, **settings):
    stem = server_id.replace("/", "__")
    path = tmp_path / f"{stem}.json"
    path.write_text(json.dumps(settings))
    log = tmp_path / f"{stem}.jsonl"
    profile = ServerConfig(server_id, sys.executable,
                           (str(HELPERS / "monitored_server.py"), str(path), str(log)),
                           origin="synthetic_fixture")
    return profile, log


def lines(log):
    return len(log.read_text().splitlines()) if log.exists() else 0


async def approve(monitor, server_id):
    record = await monitor.observe(server_id)
    return await monitor.approve(server_id, revision=record.observed_revision,
                                 expected_generation=record.generation, actor="operator")


async def until(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError("condition did not become true")
        await asyncio.sleep(0.01)


async def call_when_validated(monitor, server_id, seconds=5.0):
    """Call once the session is validated. A monitor refresh briefly invalidates the
    session it refreshes; retry a refusal only for that reason, never after dispatch."""
    end = time.monotonic() + seconds
    while True:
        await until(lambda: monitor.catalog(server_id), seconds)
        try:
            return await monitor.call_tool(server_id, "effect", {})
        except CallBlocked as blocked:
            if blocked.reason != "session_not_validated" or time.monotonic() > end:
                raise


class _Counter:
    count = 0


def sample_freshness(monitor, server_id, seconds=4.0):
    """Sample a server's catalog and session freshness while other work runs."""
    empty, stale = _Counter(), _Counter()

    async def run():
        samples = 0
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            samples += 1
            empty.count += not monitor.catalog(server_id)
            stale.count += monitor.health()["servers"][server_id]["freshness"] == "session_stale"
            await asyncio.sleep(0.05)
        return samples

    return asyncio.ensure_future(run()), empty, stale


def events(monitor, server_id, event_type):
    return [event for event in monitor.events(server_id) if event["event_type"] == event_type]


async def wedge(monitor, server_id):
    """Answer one call, then fill the server's unread stdin pipe with a dispatched call."""
    first = await monitor.call_tool(server_id, "effect", {})
    assert not first.isError
    big = asyncio.create_task(monitor.call_tool(server_id, "effect", {"blob": BLOB}))
    await until(lambda: len(events(monitor, server_id, "call_dispatch_started")) == 2)
    return big


async def test_backpressure_never_holds_the_trust_lock_and_quarantine_commits(tmp_path):
    profile, log = stalling(tmp_path)
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"stall": profile},
                           poll_interval=60, timeout_seconds=5, shutdown_timeout=10)
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "stall")
        big = await wedge(monitor, "stall")
        waiting = asyncio.create_task(monitor.call_tool("stall", "effect", {}))
        await asyncio.sleep(0.3)
        assert not waiting.done()
        # The waiting call holds no trust/dispatch lock while the transport is full.
        assert not monitor.client._lock("stall").locked()

        quarantine = asyncio.create_task(
            monitor.quarantine("stall", actor="operator", reason="server stopped reading"))
        await until(lambda: monitor.status("stall").state is TrustState.QUARANTINED, 1.0)
        assert monitor.catalog("stall") == ()

        with pytest.raises(CallBlocked) as refused:
            await asyncio.wait_for(waiting, 10)
        assert refused.value.reason == "quarantined"
        await asyncio.wait_for(quarantine, 10)
        with pytest.raises(ToolOutcomeUnknown):
            await asyncio.wait_for(big, 10)

        # The refused call was never handed to the transport, and nothing was replayed.
        assert len(events(monitor, "stall", "call_dispatch_started")) == 2
        assert lines(log) == 1


async def test_backpressure_wait_is_bounded_and_refused_before_dispatch(tmp_path):
    profile, log = stalling(tmp_path)
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"stall": profile},
                           poll_interval=60, timeout_seconds=2, shutdown_timeout=10)
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "stall")
        big = await wedge(monitor, "stall")
        started = time.monotonic()
        with pytest.raises(CallBlocked) as refused:
            await asyncio.wait_for(monitor.call_tool("stall", "effect", {}), 5)
        assert refused.value.reason == "transport_backpressure"
        assert time.monotonic() - started < 4
        blocked = events(monitor, "stall", "call_blocked")[-1]
        assert blocked["detail"]["reason"] == "transport_backpressure"
        assert blocked["detail"]["local_nondispatch"] is True
        assert len(events(monitor, "stall", "call_dispatch_started")) == 2

        # Metadata traffic is bounded too: refreshing a server that does not drain its
        # input is an observation failure, not an indefinite wait (REQ-REV-02).
        with pytest.raises(ObservationError):
            await asyncio.wait_for(monitor.observe("stall"), 10)
        record = monitor.status("stall")
        assert record.state is TrustState.PENDING_REVIEW
        assert record.observation_failed_at is not None
        with pytest.raises(ToolOutcomeUnknown):
            await asyncio.wait_for(big, 10)
        assert lines(log) == 1


async def test_wedged_server_does_not_starve_monitoring_of_unrelated_server(tmp_path):
    stall, stall_log = stalling(tmp_path)
    quiet, quiet_log = monitored(tmp_path, "quiet")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"stall": stall, "quiet": quiet},
                           poll_interval=1.0, timeout_seconds=3, shutdown_timeout=10,
                           max_concurrency=2)
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "quiet")
        await approve(monitor, "stall")  # last, so its session is fresh for wedge()
        big = await wedge(monitor, "stall")
        waiting = asyncio.create_task(monitor.call_tool("stall", "effect", {}))
        await monitor.start_monitor()
        samples, empty, stale = sample_freshness(monitor, "quiet", seconds=5.0)
        await samples
        # Each observation briefly withdraws a server's own catalog while it refreshes;
        # starvation shows as an expired session and a mostly empty catalog.
        assert stale.count == 0, f"quiet session expired in {stale.count} samples"
        assert empty.count <= samples.result() // 4, (empty.count, samples.result())
        result = await call_when_validated(monitor, "quiet")
        assert not result.isError and lines(quiet_log) == 1
        # The wedged server fails closed: its refresh failed and its calls are refused.
        assert monitor.status("stall").state is not TrustState.APPROVED
        with pytest.raises(CallBlocked):
            await asyncio.wait_for(waiting, 10)
        await monitor.stop_monitor()
        big.cancel()
        await asyncio.gather(big, return_exceptions=True)
        assert lines(stall_log) == 1


async def test_policy_reload_cannot_commit_between_final_gate_and_enqueue(tmp_path, monkeypatch):
    profile, log = monitored(tmp_path, "custom/local")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": profile},
                           poll_interval=60, timeout_seconds=5)
    replacement = tmp_path / "policy-next.json"
    document = json.loads(POLICY_PATH.read_text())
    document["revision"] = "next"
    replacement.write_text(json.dumps(document))
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "custom/local")
        active = monitor.decision_binding
        at_enqueue = []
        original_nowait = MemoryObjectSendStream.send_nowait

        def probe(stream, item):
            root = getattr(getattr(item, "message", None), "root", None)
            if getattr(root, "method", None) == "tools/call":
                record = monitor.status("custom/local")
                at_enqueue.append((record.state, record.approved_policy_revision,
                                   monitor.decision_binding))
            return original_nowait(stream, item)

        monkeypatch.setattr(MemoryObjectSendStream, "send_nowait", probe)
        original_event = monitor.store.record_event
        reloads = []

        def reload_when_dispatch_starts(server_id, event_type, **kwargs):
            original_event(server_id, event_type, **kwargs)
            if event_type == "call_dispatch_started":
                # An operator reload that becomes runnable at the final gate.
                reloads.append(asyncio.ensure_future(monitor.reload_policy(replacement)))

        monkeypatch.setattr(monitor.store, "record_event", reload_when_dispatch_starts)
        result = await monitor.call_tool("custom/local", "effect")
        await asyncio.gather(*reloads)
        assert not result.isError
        # The call entered the transport while its authorization was still current.
        assert at_enqueue == [(TrustState.APPROVED, active, active)]
        assert monitor.decision_binding != active
        assert monitor.status("custom/local").state is TrustState.PENDING_REVIEW
        with pytest.raises(CallBlocked):
            await monitor.call_tool("custom/local", "effect")
        assert lines(log) == 1


async def test_policy_reload_does_not_hold_other_servers_behind_a_slow_observation(tmp_path):
    """Reload activation shares the gate's synchronous boundary instead of locks, so it
    never holds one server's lock while waiting for another (REQ-ENF-04/05)."""
    fast, _ = monitored(tmp_path, "a-fast")
    slow, _ = monitored(tmp_path, "z-slow")
    slow_settings = tmp_path / "z-slow.json"
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"a-fast": fast, "z-slow": slow},
                           poll_interval=60, timeout_seconds=10)
    replacement = tmp_path / "policy-next.json"
    document = json.loads(POLICY_PATH.read_text())
    document["revision"] = "next"
    replacement.write_text(json.dumps(document))
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "a-fast")
        await approve(monitor, "z-slow")
        active = monitor.policy.binding
        slow_settings.write_text(json.dumps({"list_delay": 2}))
        observation = asyncio.create_task(monitor.observe("z-slow"))  # holds z-slow's lock
        await asyncio.sleep(0.3)
        reload = asyncio.create_task(monitor.reload_policy(replacement))
        await asyncio.sleep(0.1)
        started = time.monotonic()
        await asyncio.wait_for(monitor.quarantine("a-fast", actor="operator", reason="test"), 5)
        assert time.monotonic() - started < 1.0
        await asyncio.wait_for(reload, 5)
        await asyncio.wait_for(observation, 10)
        assert monitor.policy.binding != active
        assert monitor.status("a-fast").state is TrustState.QUARANTINED
        assert monitor.status("z-slow").state is TrustState.PENDING_REVIEW


async def test_owner_close_refuses_a_call_still_waiting_for_the_transport(tmp_path):
    profile, log = stalling(tmp_path)
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"stall": profile},
                           poll_interval=60, timeout_seconds=10, shutdown_timeout=10)
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor, "stall")
    big = await wedge(monitor, "stall")
    waiting = asyncio.create_task(monitor.call_tool("stall", "effect", {}))
    await asyncio.sleep(0.3)
    await asyncio.wait_for(monitor.aclose(), 20)
    for task in (waiting, big):
        assert task.done() and not task.cancelled(), "a pending call was cancelled"
    assert isinstance(waiting.exception(), CallBlocked), waiting.exception()
    assert waiting.exception().reason == "client_closed"
    assert isinstance(big.exception(), ToolOutcomeUnknown), big.exception()
    assert lines(log) == 1


async def test_call_on_a_transport_whose_server_exited_is_refused_at_once(tmp_path):
    profile, log = monitored(tmp_path, "custom/local", drop_response=True)
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": profile},
                           poll_interval=60, timeout_seconds=5)
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "custom/local")
        with pytest.raises(ToolOutcomeUnknown):  # the server exits without answering
            await asyncio.wait_for(monitor.call_tool("custom/local", "effect"), 10)
        started = time.monotonic()
        with pytest.raises(CallBlocked) as refused:
            await asyncio.wait_for(monitor.call_tool("custom/local", "effect"), 10)
        assert time.monotonic() - started < 1.0
        assert refused.value.reason in {"transport_closed", "session_refresh_required"}
        assert lines(log) == 1
