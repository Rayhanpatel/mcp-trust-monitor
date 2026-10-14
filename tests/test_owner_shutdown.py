"""Real-stdio regressions for owner shutdown (REQ-MON-03, REQ-LIB-04, REQ-ENF-07).

Ownership of a state directory is released only after every owned transport task has
finished and its subprocess was reaped, even when application cleanup outlasts the
shutdown timeout. Concurrent close calls all wait for the same shutdown. An opened
TrustMonitor object is single-use: re-entering it is refused rather than silently
reusing per-lifetime fault and ownership state. Background review cleanup that ignores
cancellation cannot extend the close, or the storage-fault shutdown, past their bounds.
"""
import asyncio
import contextlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

import mcp_trust_monitor.managed_client as managed_client
from conftest import POLICY_PATH
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import ServerConfig
from mcp_trust_monitor.ownership import OwnershipError
from mcp_trust_monitor.sdk import ShutdownIncompleteError, TrustMonitor
from mcp_trust_monitor.trust_store import TrustError

pytestmark = pytest.mark.anyio

HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"


def setup(tmp_path, shutdown_timeout=10.0, **settings):
    path = tmp_path / "server.json"
    path.write_text(json.dumps(settings))
    log = tmp_path / "calls.jsonl"
    profile = ServerConfig("custom/local", sys.executable, (str(HELPER), str(path), str(log)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": profile},
                           poll_interval=60, timeout_seconds=30, shutdown_timeout=shutdown_timeout)
    return config, log


async def approve(monitor):
    record = await monitor.observe("custom/local")
    await monitor.approve("custom/local", revision=record.observed_revision,
                          expected_generation=record.generation, actor="operator")


async def until(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError("condition did not become true")
        await asyncio.sleep(0.01)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def test_close_with_long_application_cleanup_reaps_process_and_closes_cleanly(tmp_path):
    pidfile = tmp_path / "server.pid"
    config, log = setup(tmp_path, shutdown_timeout=1, call_delay=30, list_started=str(pidfile))
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor)
    pid = int(pidfile.read_text())

    async def application_call():
        try:
            await monitor.call_tool("custom/local", "effect")
        finally:
            await asyncio.sleep(3)  # application cleanup that outlasts shutdown_timeout

    caller = asyncio.create_task(application_call())
    await until(log.exists)
    await asyncio.wait_for(monitor.aclose(), 20)  # the caller's task is not joined
    assert not alive(pid), "owned server process outlived ownership release"
    assert not (config.state_dir / "owner.unclean").exists()
    leftover = [task for task in asyncio.all_tasks()
                if task.get_name().startswith("mcp:") and not task.done()]
    assert leftover == []
    async with TrustMonitor(config):
        pass
    caller.cancel()
    await asyncio.gather(caller, return_exceptions=True)


async def test_close_timeout_reaps_owned_process_before_releasing_ownership(tmp_path):
    """Cancelled work that outlives shutdown_timeout makes the shutdown incomplete, but
    ownership is released only after every owned transport was reaped."""
    from dataclasses import replace
    pidfile = tmp_path / "server.pid"
    config, _ = setup(tmp_path, shutdown_timeout=1, list_started=str(pidfile))
    entered = asyncio.Event()

    async def reviewer(monitor, server_id):
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(3)  # cleanup that outlives shutdown_timeout
            raise

    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    review = asyncio.create_task(monitor.review_once("custom/local"))
    await asyncio.wait_for(entered.wait(), 10)
    pid = int(pidfile.read_text())
    with pytest.raises(Exception) as raised:
        await asyncio.wait_for(monitor.aclose(), 20)
    assert type(raised.value).__name__ == "ShutdownIncompleteError"
    assert raised.value.ownership_released is True
    assert not alive(pid), "owned server process outlived ownership release"
    assert (config.state_dir / "owner.unclean").exists()  # not a clean shutdown
    async with TrustMonitor(config):
        pass
    await asyncio.gather(review, return_exceptions=True)


async def test_concurrent_close_waits_for_the_same_shutdown(tmp_path):
    config, log = setup(tmp_path, call_delay=30)
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor)

    async def application_call():
        try:
            await monitor.call_tool("custom/local", "effect")
        finally:
            await asyncio.sleep(1.5)  # bounded cleanup within shutdown_timeout

    caller = asyncio.create_task(application_call())
    await until(log.exists)
    first = asyncio.create_task(monitor.aclose())
    await asyncio.sleep(0.1)
    await asyncio.wait_for(monitor.aclose(), 20)
    assert first.done(), "a concurrent aclose() returned before the owner was closed"
    await first
    async with TrustMonitor(config):  # ownership is actually released
        pass
    assert not (config.state_dir / "owner.unclean").exists()
    await asyncio.gather(caller, return_exceptions=True)


async def test_opened_monitor_object_is_single_use(tmp_path):
    config, _ = setup(tmp_path)
    monitor = TrustMonitor(config)
    async with monitor:
        await approve(monitor)
    with pytest.raises(TrustError, match="single-use"):
        async with monitor:
            pass
    await monitor.aclose()  # closing again is a no-op
    async with TrustMonitor(config) as fresh:
        assert fresh.status("custom/local") is not None


async def test_ownership_is_retained_while_a_transport_cannot_be_confirmed_closed(tmp_path, monkeypatch):
    config, _ = setup(tmp_path)
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor)
    connection = monitor.client._connections["custom/local"]
    original_close = managed_client._Connection.close

    async def stuck_close(self, *args, **kwargs):
        if self is connection:
            return  # simulate a transport whose shutdown cannot be completed
        return await original_close(self, *args, **kwargs)

    monkeypatch.setattr(managed_client._Connection, "close", stuck_close)
    with pytest.raises(Exception) as raised:
        await asyncio.wait_for(monitor.aclose(), 20)
    assert type(raised.value).__name__ == "ShutdownIncompleteError"
    assert raised.value.ownership_released is False
    with pytest.raises(OwnershipError):
        async with TrustMonitor(config):
            pass
    assert (config.state_dir / "owner.unclean").exists()

    # Once the transport really finishes, a retried close releases ownership.
    monkeypatch.setattr(managed_client._Connection, "close", original_close)
    await original_close(connection)
    await asyncio.wait_for(monitor.aclose(), 20)
    async with TrustMonitor(config):
        pass


async def test_retrying_a_failed_open_does_not_inherit_a_stale_fault_latch(tmp_path):
    """An object whose open failed may be retried; the retry starts a fresh lifetime."""
    import dataclasses
    import sqlite3
    from mcp_trust_monitor.managed_client import trust_db_path
    from mcp_trust_monitor.trust_store import StorageFaultError
    config, _ = setup(tmp_path)
    other = dataclasses.replace(config, client_id="other")
    async with TrustMonitor(other) as monitor:
        await monitor.observe("custom/local")
    (config.state_dir / "owner.unclean").write_text("{}")  # an unclean exit
    database = sqlite3.connect(trust_db_path(config.state_dir))
    database.execute("UPDATE trust_records SET generation = 0 WHERE client_id = 'other'")
    database.commit()

    monitor = TrustMonitor(config)
    with pytest.raises(StorageFaultError):  # directory-wide recovery decodes the record
        async with monitor:
            pass
    database.execute("UPDATE trust_records SET generation = 7 WHERE client_id = 'other'")
    database.commit()
    database.close()

    async with monitor:  # the same object, after the storage was repaired
        await approve(monitor)
        assert monitor.health()["storage_faulted"] is False
    assert not (config.state_dir / "owner.unclean").exists()  # a clean lifetime clears it


async def test_close_settles_an_in_flight_call_without_joining_the_callers_task(tmp_path):
    """Shutdown waits for the in-flight request, never for the application's whole task."""
    from mcp_trust_monitor.managed_client import ToolOutcomeUnknown
    config, log = setup(tmp_path, shutdown_timeout=3, call_delay=30)
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor)
    seen = []

    async def agent_loop():  # a long-lived application task with a call in flight
        try:
            await monitor.call_tool("custom/local", "effect")
        except ToolOutcomeUnknown:
            seen.append("ToolOutcomeUnknown")
        await asyncio.sleep(30)

    agent = asyncio.create_task(agent_loop())
    await until(log.exists)
    started = time.monotonic()
    await asyncio.wait_for(monitor.aclose(), 20)  # no ShutdownIncompleteError
    assert time.monotonic() - started < 2.5
    assert not (config.state_dir / "owner.unclean").exists()
    assert seen == ["ToolOutcomeUnknown"] and not agent.done()
    async with TrustMonitor(config) as reopened:  # a clean close: approval survives
        assert reopened.status("custom/local").state.value == "approved"
    agent.cancel()
    await asyncio.gather(agent, return_exceptions=True)


async def test_storage_fault_while_the_main_task_is_the_caller_does_not_stall_close(tmp_path):
    from mcp_trust_monitor.managed_client import ToolOutcomeUnknown
    from mcp_trust_monitor.trust_store import StorageFaultError
    config, log = setup(tmp_path, shutdown_timeout=3, call_delay=10)
    started = None
    async with TrustMonitor(config) as monitor:
        await approve(monitor)

        async def fault_elsewhere():
            await until(log.exists)
            monitor.store._db.execute("PRAGMA query_only=ON")
            with pytest.raises(StorageFaultError):
                monitor.store.record_event("custom/local", "operator_note", actor="test", detail={})

        helper = asyncio.create_task(fault_elsewhere())
        with pytest.raises(ToolOutcomeUnknown):
            await asyncio.wait_for(monitor.call_tool("custom/local", "effect"), 10)
        await helper
        started = time.monotonic()
    assert time.monotonic() - started < 2.5  # the close did not wait out shutdown_timeout
    assert (config.state_dir / "owner.unclean").exists()  # faulted storage stays unclean


async def test_session_close_does_not_wait_for_the_callers_task(tmp_path):
    from mcp_trust_monitor.managed_client import ToolOutcomeUnknown
    config, log = setup(tmp_path, call_delay=30)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        session = monitor.new_session()
        await session.observe("custom/local")
        outcome = []

        async def worker():
            try:
                await session.call_tool("custom/local", "effect")
            except ToolOutcomeUnknown:
                outcome.append("ToolOutcomeUnknown")
            await asyncio.sleep(30)

        task = asyncio.create_task(worker())
        await until(log.exists)
        await asyncio.wait_for(session.aclose(), 5)
        await until(lambda: outcome == ["ToolOutcomeUnknown"])
        assert not task.done()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def uncooperative_reviewer():
    """A monitor reviewer whose cleanup ignores every cancellation until released.

    `cancellations` counts the cancellations it received; shutdown cancels it once.
    """
    from types import SimpleNamespace
    review = SimpleNamespace(entered=asyncio.Event(), cancelled=asyncio.Event(),
                             release=asyncio.Event(), tasks=[], cancellations=0)

    async def reviewer(monitor, server_id):
        review.tasks.append(asyncio.current_task())
        review.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            review.cancellations += 1
            review.cancelled.set()
            while not review.release.is_set():
                try:
                    await review.release.wait()
                except asyncio.CancelledError:
                    review.cancellations += 1  # keeps cleaning up regardless
            raise

    return reviewer, review


async def release_review(monitor, review):
    review.release.set()
    await asyncio.gather(*review.tasks, return_exceptions=True)
    with contextlib.suppress(Exception):
        await asyncio.wait_for(monitor.aclose(), 30)


async def test_close_is_bounded_when_background_review_cleanup_ignores_cancellation(tmp_path):
    """R3: a monitor-scheduled review that ignores cancellation cannot hold aclose()
    past shutdown_timeout or keep the owned server process alive. The shutdown is
    reported as incomplete with ownership released, and the unclean marker is kept."""
    from dataclasses import replace
    pidfile = tmp_path / "server.pid"
    config, _ = setup(tmp_path, shutdown_timeout=0.5, list_started=str(pidfile))
    reviewer, review = uncooperative_reviewer()
    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    try:
        await approve(monitor)
        await monitor.start_monitor()
        await asyncio.wait_for(review.entered.wait(), 30)
        task = review.tasks[0]
        assert monitor._loop.review_tasks.get("custom/local") is task  # scheduled in background
        pid = int(pidfile.read_text())
        close = asyncio.create_task(monitor.aclose())
        done, _ = await asyncio.wait({close}, timeout=15)
        assert close in done, "aclose() waited for review cleanup that ignores cancellation"
        assert review.cancelled.is_set() and not task.done()
        assert not alive(pid), "the owned server process outlived the bounded shutdown"
        with pytest.raises(ShutdownIncompleteError) as raised:
            close.result()
        assert raised.value.ownership_released is True
        assert review.cancellations == 1
        assert (config.state_dir / "owner.unclean").exists()
        assert task in monitor._unfinished  # still referenced, never dropped
        async with TrustMonitor(config) as reopened:  # ownership was released; recovery ran
            assert reopened.status("custom/local").state.value == "pending_review"
    finally:
        await release_review(monitor, review)


async def test_storage_fault_reaps_the_transport_while_review_cleanup_ignores_cancellation(tmp_path):
    """R3 on the authoritative storage-fault path: the fault shutdown closes the owned
    transport without waiting for the review, and aclose() stays bounded and accurate."""
    from dataclasses import replace
    from mcp_trust_monitor.trust_store import StorageFaultError
    pidfile = tmp_path / "server.pid"
    config, _ = setup(tmp_path, shutdown_timeout=0.5, list_started=str(pidfile))
    reviewer, review = uncooperative_reviewer()
    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    try:
        await approve(monitor)
        await monitor.start_monitor()
        await asyncio.wait_for(review.entered.wait(), 30)
        task = review.tasks[0]
        pid = int(pidfile.read_text())
        monitor.store._db.execute("PRAGMA query_only=ON")
        with pytest.raises(StorageFaultError):
            monitor.store.record_event("custom/local", "operator_note", actor="test", detail={})
        # No aclose() yet: the fault shutdown alone reaps the server process.
        await until(lambda: not alive(pid), 15)
        assert review.cancelled.is_set() and not task.done()
        with pytest.raises(StorageFaultError):
            await monitor.start_monitor()
        close = asyncio.create_task(monitor.aclose())
        done, _ = await asyncio.wait({close}, timeout=15)
        assert close in done, "aclose() waited for review cleanup that ignores cancellation"
        with pytest.raises(ShutdownIncompleteError) as raised:
            close.result()
        assert raised.value.ownership_released is True
        # The fault shutdown cancelled it; the close only joined it again.
        assert review.cancellations == 1
        assert (config.state_dir / "owner.unclean").exists()
        async with TrustMonitor(config) as reopened:
            assert reopened.status("custom/local").state.value == "pending_review"
    finally:
        await release_review(monitor, review)
