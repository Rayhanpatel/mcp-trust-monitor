"""Real-stdio regressions for monitor scheduling lifecycle (REQ-MON-03, REQ-ENF-07).

Starting the monitor is refused once the owner began closing. Start and stop are
serialized, and a stop detaches only the tasks it cancelled, so no worker, poll or review
task can outlive a close that was reported clean, and no unfinished task is ever lost.
Stopping is bounded even when a review ignores cancellation, and a plain stop followed
by a start still resumes monitoring.
"""
import asyncio
import contextlib
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import POLICY_PATH
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import CallBlocked, ServerConfig
from mcp_trust_monitor.sdk import ShutdownIncompleteError, TrustMonitor
from mcp_trust_monitor.trust_store import TrustError, TrustState
from test_owner_shutdown import uncooperative_reviewer

pytestmark = pytest.mark.anyio

HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"
SERVER = "custom/local"


def setup(tmp_path, *, shutdown_timeout=10.0, poll_interval=60.0, **settings):
    path = tmp_path / "server.json"
    path.write_text(json.dumps(settings))
    profile = ServerConfig(SERVER, sys.executable, (str(HELPER), str(path), str(tmp_path / "calls.jsonl")),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {SERVER: profile},
                           poll_interval=poll_interval, timeout_seconds=30,
                           shutdown_timeout=shutdown_timeout)
    return config, path


async def approve(monitor):
    record = await monitor.observe(SERVER)
    await monitor.approve(SERVER, revision=record.observed_revision,
                          expected_generation=record.generation, actor="operator")


async def until(predicate, seconds=30.0):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError("condition did not become true")
        await asyncio.sleep(0.02)


def scheduler_tasks():
    """Unfinished scheduler tasks (workers, poll, assessments) in this event loop."""
    return {task for task in asyncio.all_tasks() if not task.done()
            and task.get_coro().__qualname__.startswith("MonitorLoop.")}


async def cleanup(monitor, review):
    review.release.set()
    await asyncio.gather(*review.tasks, return_exceptions=True)
    with contextlib.suppress(Exception):
        await asyncio.wait_for(monitor.aclose(), 30)
    leftover = scheduler_tasks()  # only reachable when the code under test leaked tasks
    for task in leftover:
        task.cancel()
    await asyncio.gather(*leftover, return_exceptions=True)


async def test_start_during_close_is_refused_and_no_scheduler_task_outlives_a_clean_close(tmp_path):
    config, _ = setup(tmp_path)
    reviewer, review = uncooperative_reviewer()
    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    try:
        await monitor.start_monitor()
        await asyncio.wait_for(review.entered.wait(), 30)
        closer = asyncio.create_task(monitor.aclose())
        await asyncio.wait_for(review.cancelled.wait(), 15)  # the owner is shutting down
        before = scheduler_tasks()
        with pytest.raises(TrustError, match="closing"):
            await monitor.start_monitor()
        assert scheduler_tasks() <= before, "a refused start created scheduler tasks"
        review.release.set()  # the review now finishes within shutdown_timeout
        await asyncio.wait_for(closer, 30)  # a clean close
        assert scheduler_tasks() == set(), "scheduler tasks outlived a clean close"
        assert not monitor._loop.running
        assert not (config.state_dir / "owner.unclean").exists()
        async with TrustMonitor(config):
            pass
    finally:
        await cleanup(monitor, review)


async def test_a_start_during_a_stop_waits_and_keeps_its_own_tasks(tmp_path):
    config, _ = setup(tmp_path)
    reviewer, review = uncooperative_reviewer()
    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    try:
        await monitor.start_monitor()
        await asyncio.wait_for(review.entered.wait(), 30)
        first = {*monitor._loop.tasks, review.tasks[0]}
        stopping = asyncio.create_task(monitor.stop_monitor())
        await asyncio.wait_for(review.cancelled.wait(), 15)
        starting = asyncio.create_task(monitor.start_monitor())
        await asyncio.sleep(0.3)
        assert not starting.done(), "start_monitor() ran while a stop was still in progress"
        review.release.set()
        await asyncio.wait_for(stopping, 30)
        await asyncio.wait_for(starting, 30)
        second = set(monitor._loop.tasks)
        assert monitor._loop.running and second and not second & first
        assert all(task.done() for task in first)
        assert all(not task.done() for task in second), "the stop discarded the new start's tasks"
        await asyncio.wait_for(monitor.aclose(), 30)  # clean: the new review is released
        assert all(task.done() for task in second)
        assert scheduler_tasks() == set()
        assert not (config.state_dir / "owner.unclean").exists()
    finally:
        await cleanup(monitor, review)


async def test_stop_monitor_is_bounded_when_review_cleanup_ignores_cancellation(tmp_path):
    config, _ = setup(tmp_path, shutdown_timeout=0.5)
    reviewer, review = uncooperative_reviewer()
    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    try:
        await approve(monitor)
        await monitor.start_monitor()
        await asyncio.wait_for(review.entered.wait(), 30)
        task = review.tasks[0]
        stopping = asyncio.create_task(monitor.stop_monitor())
        done, _ = await asyncio.wait({stopping}, timeout=15)
        assert stopping in done, "stop_monitor() waited for cleanup that ignores cancellation"
        with pytest.raises(asyncio.TimeoutError):
            stopping.result()
        assert not task.done() and monitor.health()["status"] == "stopped"
        assert task in monitor._loop.owned_tasks()  # still tracked after the stop
        # The owner's close joins it again and reports the incomplete shutdown.
        with pytest.raises(ShutdownIncompleteError) as raised:
            await asyncio.wait_for(monitor.aclose(), 15)
        assert raised.value.ownership_released is True
        assert review.cancellations == 1  # the stop cancelled it; the close only joined it
        assert (config.state_dir / "owner.unclean").exists()
    finally:
        await cleanup(monitor, review)


async def test_restart_after_an_incomplete_stop_still_tracks_the_unfinished_task(tmp_path):
    config, _ = setup(tmp_path, shutdown_timeout=0.5)
    reviewer, review = uncooperative_reviewer()
    monitor = await TrustMonitor(replace(config, reviewer=reviewer)).__aenter__()
    try:
        await monitor.start_monitor()
        await asyncio.wait_for(review.entered.wait(), 30)
        task = review.tasks[0]
        stopping = asyncio.create_task(monitor.stop_monitor())
        done, _ = await asyncio.wait({stopping}, timeout=15)
        assert stopping in done, "stop_monitor() waited for cleanup that ignores cancellation"
        with pytest.raises(asyncio.TimeoutError):
            stopping.result()
        await monitor.start_monitor()  # allowed; the unfinished task stays tracked
        assert monitor._loop.running and task not in monitor._loop.tasks
        assert task in monitor._loop.owned_tasks()
        review.release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.wait_for(monitor.aclose(), 30)  # nothing remains: a clean close
        assert scheduler_tasks() == set()
        assert not (config.state_dir / "owner.unclean").exists()
    finally:
        await cleanup(monitor, review)


async def test_stop_then_start_resumes_monitoring(tmp_path):
    """Preserved behavior: a plain stop followed by a start still works."""
    config, settings = setup(tmp_path, poll_interval=0.2)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        await monitor.start_monitor()
        await monitor.stop_monitor()
        assert monitor.health()["status"] == "stopped" and not monitor._loop.tasks
        settings.write_text(json.dumps({"description": "Changed while monitoring was stopped."}))
        await asyncio.sleep(0.6)  # three poll intervals: nothing observes while stopped
        assert monitor.status(SERVER).state is TrustState.APPROVED
        await monitor.start_monitor()
        await until(lambda: monitor.status(SERVER).state is TrustState.PENDING_REVIEW)
        assert monitor._loop.running and monitor._loop.tasks
        await monitor.stop_monitor()
    assert scheduler_tasks() == set()
    assert not (config.state_dir / "owner.unclean").exists()


async def test_repeated_session_close_cancels_each_request_and_observation_once(tmp_path, monkeypatch):
    """Review finding F4: ManagedClient._begin_close cancels in-flight work once. A repeat
    (the fault shutdown, then the owner's close) only collects it, so cleanup that is
    honoring the first cancellation is never interrupted by a second one."""
    config, _ = setup(tmp_path)
    async with TrustMonitor(config) as monitor:
        record = await monitor.observe(SERVER)
        await monitor.approve(SERVER, revision=record.observed_revision,
                              expected_generation=record.generation, actor="operator")
        session = monitor.new_session()
        await session.observe(SERVER)
        released = asyncio.Event()
        cancellations = {"request": 0, "observation": 0}

        def stubborn(kind):
            async def work(*args, **kwargs):
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cancellations[kind] += 1
                    while not released.is_set():  # cleanup still under way
                        try:
                            await released.wait()
                        except asyncio.CancelledError:
                            cancellations[kind] += 1
                    raise
            return work

        connection = session._connections[SERVER]
        monkeypatch.setattr(connection.session, "call_tool", stubborn("request"))
        call = asyncio.create_task(session.call_tool(SERVER, "effect"))
        await asyncio.sleep(0.1)
        monkeypatch.setattr(session, "_list_tools", stubborn("observation"))
        observation = asyncio.create_task(session.observe(SERVER))
        await asyncio.sleep(0.1)

        try:
            first = session._begin_close()
            await asyncio.sleep(0.1)
            second = session._begin_close()  # e.g. the owner's close after a fault shutdown
            await asyncio.sleep(0.1)
            assert cancellations == {"request": 1, "observation": 1}
            assert set(second) <= set(first)
        finally:
            released.set()  # let the stubborn cleanup finish even if an assertion failed
            await asyncio.wait({call, observation}, timeout=10)
        assert call.done() and observation.done()
        assert isinstance(call.exception(), CallBlocked) and call.exception().reason == "client_closed"
        observation.cancelled() or observation.exception()  # retrieved
        blocked = [event for event in monitor.events(SERVER) if event["event_type"] == "call_blocked"
                   and event["detail"].get("reason") == "client_closed"]
        assert len(blocked) == 1  # settled exactly once


async def _stubborn_request(monitor, monkeypatch):
    """An approved session whose next request honors its first cancellation slowly and
    counts every cancellation it receives."""
    record = await monitor.observe(SERVER)
    await monitor.approve(SERVER, revision=record.observed_revision,
                          expected_generation=record.generation, actor="operator")
    session = monitor.new_session()
    await session.observe(SERVER)
    released, counter = asyncio.Event(), {"cancellations": 0}

    async def request(*args, **kwargs):
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            counter["cancellations"] += 1
            while not released.is_set():
                try:
                    await released.wait()
                except asyncio.CancelledError:
                    counter["cancellations"] += 1
            raise

    monkeypatch.setattr(session._connections[SERVER].session, "call_tool", request)
    call = asyncio.create_task(session.call_tool(SERVER, "effect"))
    await asyncio.sleep(0.1)
    return session, call, released, counter


async def test_caller_cancelled_before_shutdown_has_its_request_cancelled_once(tmp_path, monkeypatch):
    """Re-verification finding N-A: shutdown must not re-cancel a request the caller's own
    cancellation already cancelled and settled."""
    config, _ = setup(tmp_path)
    async with TrustMonitor(config) as monitor:
        session, call, released, counter = await _stubborn_request(monitor, monkeypatch)
        try:
            call.cancel()  # the caller's own cancellation comes first
            await asyncio.sleep(0.1)
            session._begin_close()
            await asyncio.sleep(0.1)
            assert counter["cancellations"] == 1
        finally:
            released.set()
            await asyncio.wait({call}, timeout=10)
        assert call.cancelled()


async def test_caller_cancelled_after_shutdown_does_not_cancel_its_request_again(tmp_path, monkeypatch):
    config, _ = setup(tmp_path)
    async with TrustMonitor(config) as monitor:
        session, call, released, counter = await _stubborn_request(monitor, monkeypatch)
        try:
            session._begin_close()  # shutdown cancels and settles first
            call.cancel()           # then the caller is cancelled while waking
            await asyncio.sleep(0.1)
            assert counter["cancellations"] == 1
        finally:
            released.set()
            await asyncio.wait({call}, timeout=10)
        assert call.cancelled()
        blocked = [event for event in monitor.events(SERVER) if event["event_type"] == "call_blocked"
                   and event["detail"].get("reason") == "client_closed"]
        assert len(blocked) == 1  # settled once, by shutdown
