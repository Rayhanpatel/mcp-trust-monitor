"""R10: cancellation cleanup stays owned and receives one lifecycle cancellation.

The instrumented cleanup wraps actual MCP requests to a real stdio subprocess.
Independent effect/list-start logs prove the transport was exercised (REQ-MON-03,
REQ-LIB-04, REQ-ENF-05/07/08).
"""
import asyncio
import contextlib
import json
import linecache
import time

import pytest

from mcp_trust_monitor.sdk import ShutdownIncompleteError, TrustMonitor
from test_owner_shutdown import alive, approve, setup, until

pytestmark = pytest.mark.anyio
SERVER = "custom/local"


class Cleanup:
    def __init__(self, operation, *, abort_on_repeat=False):
        self.operation = operation
        self.abort_on_repeat = abort_on_repeat
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.cancellations = 0
        self.completed = False
        self.task = None

    async def __call__(self, *args, **kwargs):
        self.task = asyncio.current_task()
        try:
            return await self.operation(*args, **kwargs)
        except asyncio.CancelledError:
            self.cancellations += 1
            self.cancelled.set()
            while not self.release.is_set():
                try:
                    await self.release.wait()
                except asyncio.CancelledError:
                    self.cancellations += 1
                    if self.abort_on_repeat:
                        raise
            self.completed = True
            raise


def at_request_cleanup_join(caller):
    """Do not cancel before the caller reaches the join: that misses R10's race."""
    coro = caller.get_coro()
    while coro is not None:
        frame = getattr(coro, "cr_frame", None)
        if frame is not None and frame.f_code.co_name == "call_tool":
            line = linecache.getline(frame.f_code.co_filename, frame.f_lineno)
            if "await asyncio." in line and "request" in line and "closing" not in line:
                return True
        coro = getattr(coro, "cr_await", None)
    return False


async def finish(monitor, cleanup, *tasks):
    cleanup.release.set()
    owned = {task for task in (*tasks, cleanup.task) if task is not None}
    with contextlib.suppress(ShutdownIncompleteError):
        await asyncio.wait_for(monitor.aclose(), 20)
    if owned:
        done, pending = await asyncio.wait(owned, timeout=10)
        for task in done:
            if not task.cancelled():
                task.exception()
        assert not pending, "test-owned cleanup did not finish after release"


@pytest.mark.parametrize("first", ["shutdown", "caller"])
@pytest.mark.parametrize("outlives_bound", [False, True])
async def test_request_cleanup_survives_caller_cancellation_at_the_join(
        tmp_path, monkeypatch, first, outlives_bound):
    pidfile = tmp_path / "server.pid"
    config, log = setup(tmp_path, shutdown_timeout=.2, call_delay=30,
                        list_started=str(pidfile))
    monitor = await TrustMonitor(config).__aenter__()
    await approve(monitor)
    pid = int(pidfile.read_text())
    session = monitor.client
    cleanup = Cleanup(session._connections[SERVER].session.call_tool)
    monkeypatch.setattr(session._connections[SERVER].session, "call_tool", cleanup)
    caller = asyncio.create_task(monitor.call_tool(SERVER, "effect"))
    closer = None
    try:
        await until(log.exists)
        if first == "caller":
            caller.cancel()
            await asyncio.wait_for(cleanup.cancelled.wait(), 5)
            await until(lambda: at_request_cleanup_join(caller))
        else:
            closer = asyncio.create_task(monitor.aclose())
            await asyncio.wait_for(cleanup.cancelled.wait(), 5)
            await until(lambda: at_request_cleanup_join(caller))
        # A first caller cancellation after shutdown, or a second while handling its
        # own first cancellation, must not propagate through the cleanup join.
        caller.cancel()
        await asyncio.sleep(0)  # deliver it before checking the child cleanup
        assert cleanup.cancellations == 1
        await until(caller.done)
        assert caller.cancelled(), "the caller's cancellation was swallowed"
        assert cleanup.cancellations == 1
        assert not cleanup.task.done() and cleanup.task in session._inflight
        if closer is None:
            # The caller has already left; close must still find and join its work.
            closer = asyncio.create_task(monitor.aclose())

        if outlives_bound:
            with pytest.raises(ShutdownIncompleteError) as raised:
                await asyncio.wait_for(closer, 15)
            assert raised.value.ownership_released
            assert cleanup.task in monitor._unfinished
            assert (config.state_dir / "owner.unclean").exists()
        else:
            cleanup.release.set()
            await asyncio.wait_for(closer, 15)
            assert cleanup.completed
            assert not (config.state_dir / "owner.unclean").exists()
        assert not alive(pid)
        assert session.dispatch_count(SERVER) == 1
        assert len(log.read_text().splitlines()) == 1  # no replay
        # Store is closed now; inspect the settled audit through a read-only snapshot.
        import sqlite3
        with sqlite3.connect(config.state_dir / "trust.sqlite3") as db:
            events = [json.loads(row[0]) for row in db.execute(
                "SELECT detail FROM trust_events WHERE event_type='call_completed'")]
        assert [event["outcome"] for event in events] == ["outcome_unknown"]
    finally:
        await finish(monitor, cleanup, caller, closer)
    assert cleanup.completed
    assert cleanup.task not in session._inflight
    assert cleanup.task not in monitor._unfinished


@pytest.mark.parametrize("first", ["stop", "session_close"])
@pytest.mark.parametrize("outlives_bound", [False, True])
@pytest.mark.parametrize("abort_on_repeat", [False, True])
async def test_observation_cleanup_is_cancelled_once_across_stop_and_close(
        tmp_path, monkeypatch, first, outlives_bound, abort_on_repeat):
    pidfile = tmp_path / "server.pid"
    config, log = setup(tmp_path, shutdown_timeout=.2, list_started=str(pidfile))
    monitor = await TrustMonitor(config).__aenter__()
    await monitor.observe(SERVER)
    pid = int(pidfile.read_text())
    pidfile.unlink()
    (tmp_path / "server.json").write_text(json.dumps(
        {"list_delay": 30, "list_started": str(pidfile)}))
    session = monitor.client
    cleanup = Cleanup(session._list_tools, abort_on_repeat=abort_on_repeat)
    monkeypatch.setattr(session, "_list_tools", cleanup)
    closer = session_close = None
    try:
        await monitor.start_monitor()
        await until(pidfile.exists)  # tools/list reached the actual server
        if first == "session_close":
            session_close = asyncio.create_task(session.aclose())
            await asyncio.wait_for(cleanup.cancelled.wait(), 5)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(monitor.stop_monitor(), 5)
        assert cleanup.cancellations == 1 and not cleanup.task.done()
        assert cleanup.task in session._observations
        assert cleanup.task in monitor._loop.owned_tasks()
        started = time.monotonic()
        closer = asyncio.create_task(monitor.aclose())
        await until(lambda: session._closing.is_set() and not alive(pid), 15)
        if outlives_bound:
            with pytest.raises(ShutdownIncompleteError) as raised:
                await asyncio.wait_for(closer, 15)
            assert raised.value.ownership_released
            assert not cleanup.completed and not cleanup.task.done()
            assert cleanup.task in monitor._unfinished
            assert (config.state_dir / "owner.unclean").exists()
        else:
            assert not closer.done(), "close reported clean with cleanup still waiting"
            cleanup.release.set()
            await asyncio.wait_for(closer, 15)
            assert cleanup.completed
            assert not (config.state_dir / "owner.unclean").exists()
        assert time.monotonic() - started < 5
        assert cleanup.cancellations == 1
        assert not log.exists() and session.dispatch_count(SERVER) == 0
    finally:
        await finish(monitor, cleanup, closer, session_close)
    assert cleanup.completed
    assert cleanup.task not in session._observations
    assert cleanup.task not in monitor._loop.owned_tasks()
    assert cleanup.task not in monitor._unfinished


async def test_cancelled_observation_does_not_exempt_a_later_operation_in_same_task(
        tmp_path, monkeypatch):
    """Cancellation belongs to active operations, not the application's whole task."""
    listed = tmp_path / "listed.pid"
    config, log = setup(tmp_path, list_started=str(listed))
    monitor = await TrustMonitor(config).__aenter__()
    first, second = monitor.client, monitor.new_session()
    await first.observe(SERVER)
    await second.observe(SERVER)
    (tmp_path / "server.json").write_text(json.dumps(
        {"list_delay": 30, "list_started": str(listed)}))
    cleanups = [Cleanup(session._list_tools) for session in (first, second)]
    for session, cleanup in zip((first, second), cleanups):
        monkeypatch.setattr(session, "_list_tools", cleanup)
    observed = []

    async def application():
        for session in (first, second):
            try:
                await session.observe(SERVER)
            except asyncio.CancelledError:
                observed.append(session)

    listed.unlink()
    application_task = asyncio.create_task(application())
    closes = []
    try:
        for session, cleanup in zip((first, second), cleanups):
            await until(listed.exists)
            listed.unlink()
            close = asyncio.create_task(session.aclose())
            closes.append(close)
            await asyncio.wait_for(cleanup.cancelled.wait(), 5)
            cleanup.release.set()
        await asyncio.wait_for(application_task, 5)
        await asyncio.wait_for(asyncio.gather(*closes), 15)
        assert observed == [first, second]
        assert all(cleanup.task is application_task and cleanup.completed
                   and cleanup.cancellations == 1 for cleanup in cleanups)
        assert not log.exists()
        await asyncio.wait_for(monitor.aclose(), 15)
        assert not (config.state_dir / "owner.unclean").exists()
    finally:
        for cleanup in cleanups:
            cleanup.release.set()
        await finish(monitor, cleanups[0], application_task, *closes)
