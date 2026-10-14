"""Real-stdio regressions: a storage fault after dispatch is not a pre-dispatch refusal.

REQ-ENF-05/REQ-ENF-08: once a tools/call was handed to the transport, a failure to
commit its completion audit must not be reported with the same type as a refusal
before dispatch. A known result is preserved for the caller; an unknown outcome stays
unknown. Storage remains latched (REQ-ENF-07) and nothing is replayed.
"""
import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

import mcp_trust_monitor.managed_client as managed_client
from conftest import POLICY_PATH
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import ServerConfig, ToolOutcomeUnknown, trust_db_path
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.trust_store import StorageFaultError, TrustStore

pytestmark = pytest.mark.anyio

HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"


def setup(tmp_path, timeout_seconds=5, **settings):
    path = tmp_path / "server.json"
    path.write_text(json.dumps(settings))
    log = tmp_path / "calls.jsonl"
    profile = ServerConfig("custom/local", sys.executable, (str(HELPER), str(path), str(log)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": profile},
                           poll_interval=60, timeout_seconds=timeout_seconds)
    return config, log


def calls(log):
    return len(log.read_text().splitlines()) if log.exists() else 0


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


async def test_completed_call_with_failed_completion_audit_keeps_its_result(tmp_path):
    config, log = setup(tmp_path, call_delay=1)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        task = asyncio.create_task(monitor.call_tool("custom/local", "effect"))
        await until(log.exists)  # The server has executed the side effect.
        monitor.store._db.execute("PRAGMA query_only=ON")  # The completion commit will fail.
        with pytest.raises(Exception) as raised:
            await task
        error = raised.value
        unrecorded = getattr(managed_client, "DispatchedCallUnrecorded", None)
        assert unrecorded is not None and isinstance(error, unrecorded), type(error)
        assert not isinstance(error, StorageFaultError)
        assert isinstance(error.__cause__, StorageFaultError)
        assert error.result.isError is False
        assert error.result.content[0].text == "ok"
        assert calls(log) == 1

        # Storage stays latched: the next call is refused before dispatch.
        with pytest.raises(StorageFaultError):
            await monitor.call_tool("custom/local", "effect")
        assert calls(log) == 1


async def test_unknown_outcome_with_failed_completion_audit_stays_unknown(tmp_path):
    config, log = setup(tmp_path, timeout_seconds=3, call_delay=10)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        task = asyncio.create_task(monitor.call_tool("custom/local", "effect"))
        await until(log.exists)
        monitor.store._db.execute("PRAGMA query_only=ON")
        with pytest.raises(Exception) as raised:
            await asyncio.wait_for(task, 20)
        error = raised.value
        assert isinstance(error, ToolOutcomeUnknown), type(error)
        assert not isinstance(error, StorageFaultError)
        causes = []
        cause = error.__cause__
        while cause is not None:
            causes.append(cause)
            cause = cause.__cause__
        assert any(isinstance(item, StorageFaultError) for item in causes)
        assert calls(log) == 1


async def test_storage_fault_elsewhere_reports_an_in_flight_call_as_unknown(tmp_path):
    """A fault latched by another operation shuts sessions down; the caller of a
    dispatched call gets ToolOutcomeUnknown, never a bare cancellation."""
    config, log = setup(tmp_path, call_delay=3)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        task = asyncio.create_task(monitor.call_tool("custom/local", "effect"))
        await until(log.exists)
        monitor.store._db.execute("PRAGMA query_only=ON")
        with pytest.raises(StorageFaultError):  # an unrelated authoritative write fails
            monitor.store.record_event("custom/local", "operator_note", actor="test", detail={})
        done, _ = await asyncio.wait({task}, timeout=10)
        assert done, "in-flight call did not finish"
        assert not task.cancelled(), "in-flight call was cancelled instead of classified"
        assert isinstance(task.exception(), ToolOutcomeUnknown), task.exception()
        assert calls(log) == 1


async def test_owner_close_reports_an_in_flight_call_as_unknown_and_records_it(tmp_path):
    config, log = setup(tmp_path, call_delay=30)
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor)
    task = asyncio.create_task(monitor.call_tool("custom/local", "effect"))
    await until(log.exists)
    await asyncio.wait_for(monitor.aclose(), 20)
    assert task.done() and not task.cancelled(), "in-flight call was cancelled"
    assert isinstance(task.exception(), ToolOutcomeUnknown), task.exception()
    store = TrustStore.open_readonly(trust_db_path(config.state_dir))
    try:
        completed = [event for event in store.events("custom/local")
                     if event["event_type"] == "call_completed"]
    finally:
        store.close()
    assert completed and completed[-1]["detail"]["outcome"] == "outcome_unknown"
    assert not (config.state_dir / "owner.unclean").exists()
    assert calls(log) == 1


async def test_caller_cancellation_still_propagates_and_is_recorded(tmp_path):
    config, log = setup(tmp_path, call_delay=30)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        task = asyncio.create_task(monitor.call_tool("custom/local", "effect"))
        await until(log.exists)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        completed = [event for event in monitor.events("custom/local")
                     if event["event_type"] == "call_completed"]
        assert completed[-1]["detail"]["outcome"] == "outcome_unknown"
        assert calls(log) == 1


async def test_cancel_scope_around_a_call_keeps_its_completion_record(tmp_path):
    """anyio re-delivers cancellation while the scope stays cancelled; the record of a
    dispatched call must already be committed before the request is joined."""
    import anyio
    config, log = setup(tmp_path, call_delay=30)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        with anyio.move_on_after(1.0):
            await monitor.call_tool("custom/local", "effect")
        events = [(event["event_type"], event["detail"].get("outcome"))
                  for event in monitor.events("custom/local")
                  if event["event_type"] in {"call_dispatch_started", "call_completed"}]
        assert events == [("call_dispatch_started", None), ("call_completed", "outcome_unknown")]
        assert calls(log) == 1
