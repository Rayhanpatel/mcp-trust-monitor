"""Real SIGTERM against the separate-process `monitor` and `serve` commands (REQ-MON-03).

SIGTERM is a routine stop, not a crash. After a clean stop the command exits 0, the
owned server process is gone, the console port no longer accepts connections, the
unclean marker is removed and an approved server is still approved when the next owner
opens the state. When the stop cannot be completed cleanly the command exits 5 with one
stable JSON error on stderr and keeps the unclean marker, so the next owner runs
recovery. SIGINT keeps its exit status, 130.
"""
import contextlib
import json
import os
import selectors
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest

from conftest import POLICY_PATH, REPO_ROOT
from mcp_trust_monitor.ownership import OwnershipError, StateOwner

HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"
ENV = dict(os.environ, PYTHONPATH=str(REPO_ROOT))

# Simulates a transport whose shutdown cannot be confirmed; everything else is real.
STUCK_TRANSPORT = """
import sys
import mcp_trust_monitor.managed_client as managed_client

async def close(self):
    return

managed_client._Connection.close = close
from mcp_trust_monitor.library_cli import main
sys.exit(main(sys.argv[1:]))
"""


# A transport task that, after its real session ended and the server was reaped, never
# finishes and ignores cancellation: closure can never be confirmed (review finding F2).
CANCEL_IGNORING_TRANSPORT = """
import asyncio
import sys
import mcp_trust_monitor.managed_client as managed_client

original = managed_client._Connection._run

async def run(self):
    try:
        await original(self)
    finally:
        while True:
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass

managed_client._Connection._run = run
from mcp_trust_monitor.library_cli import main
sys.exit(main(sys.argv[1:]))
"""


def cli(config, *args):
    return subprocess.run([sys.executable, "-m", "mcp_trust_monitor", "--config", str(config), *args],
                          capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT), env=ENV)


def approved_service(tmp_path, *, shutdown_timeout=5, poll_interval=30):
    """A config with one real stdio server, observed and approved by separate CLI runs."""
    pidfile = tmp_path / "server.pid"
    settings = tmp_path / "server.json"
    settings.write_text(json.dumps({"list_started": str(pidfile)}))
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "state_dir": "state", "policy_path": str(POLICY_PATH), "poll_interval": poll_interval,
        "timeout_seconds": 30, "shutdown_timeout": shutdown_timeout,
        "servers": [{"server_id": "local", "command": sys.executable,
                     "args": [str(HELPER), str(settings), str(tmp_path / "calls.jsonl")],
                     "cwd": str(tmp_path), "origin": "synthetic_fixture"}]}))
    observed = cli(config, "observe", "local")
    assert observed.returncode == 0, observed.stderr[-500:]
    record = json.loads(observed.stdout)
    approved = cli(config, "approve", "local", "--revision", record["observed_revision"],
                   "--generation", str(record["generation"]))
    assert approved.returncode == 0, approved.stderr[-500:]
    pidfile.unlink()
    return config, tmp_path / "state", pidfile


def observations(state):
    database = sqlite3.connect(f"file:{quote(str(state / 'trust.sqlite3'))}?mode=ro", uri=True)
    try:
        return database.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    finally:
        database.close()


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_until(predicate, seconds=60.0):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError("condition did not become true")
        time.sleep(0.05)


class Service:
    """A running `monitor`/`serve` process in its own process group."""

    def __init__(self, command, state, pidfile):
        self.process = subprocess.Popen(command, cwd=str(REPO_ROOT), env=ENV, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        start_new_session=True)
        self.state, self.pidfile, self.child = state, pidfile, None

    def ready(self):
        """Readiness line, after the monitor's own observation of the server completed."""
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            assert selector.select(60), "no readiness line"
        line = json.loads(self.process.stdout.readline())
        wait_until(self.pidfile.exists)
        self.child = int(self.pidfile.read_text())
        # The CLI's observe and approve recorded one observation; this is the monitor's.
        wait_until(lambda: observations(self.state) >= 2)
        return line

    def stop(self, signum=signal.SIGTERM):
        self.process.send_signal(signum)
        code = self.process.wait(timeout=90)
        return code, self.process.stderr.read()

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(self.process.pid, signal.SIGKILL)
        if self.child is not None and alive(self.child):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.child, signal.SIGKILL)  # the server has its own session


def module(config, mode):
    return [sys.executable, "-m", "mcp_trust_monitor", "--config", str(config), mode]


def error_json(stderr):
    lines = [line for line in stderr.splitlines() if line.startswith("{")]
    assert len(lines) == 1, stderr[-1000:]
    return json.loads(lines[0])


def reopened_state(config):
    """Open the state as the next owner (recovery runs if the marker was kept)."""
    observed = cli(config, "observe", "local")
    assert observed.returncode == 0, observed.stderr[-500:]
    return json.loads(observed.stdout)["state"]


def refused(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=5).close()
    except ConnectionRefusedError:
        return True
    return False


@pytest.mark.parametrize("mode", ["monitor", "serve"])
def test_sigterm_is_a_clean_stop(tmp_path, mode):
    config, state, pidfile = approved_service(tmp_path)
    service = Service(module(config, mode), state, pidfile)
    try:
        line = service.ready()
        port = None
        if mode == "serve":
            port = urlsplit(line["console_url"]).port
            assert not refused(port)  # the console was accepting connections
        assert (state / "owner.unclean").exists()  # the running owner's marker
        code, stderr = service.stop()
        assert code == 0, (code, stderr[-1000:])
        assert '"error"' not in stderr
        assert not (state / "owner.unclean").exists()
        wait_until(lambda: not alive(service.child), 10)
        if port is not None:
            assert refused(port)
        assert reopened_state(config) == "approved"
    finally:
        service.kill()


def test_sigint_keeps_exit_status_130_and_stops_cleanly(tmp_path):
    config, state, pidfile = approved_service(tmp_path)
    service = Service(module(config, "monitor"), state, pidfile)
    try:
        service.ready()
        code, stderr = service.stop(signal.SIGINT)
        assert code == 130, (code, stderr[-1000:])
        assert not (state / "owner.unclean").exists()
        assert reopened_state(config) == "approved"
    finally:
        service.kill()


@pytest.mark.skipif(os.geteuid() == 0, reason="directory permissions do not restrict root")
def test_sigterm_with_unwritable_state_keeps_the_marker_and_exits_nonzero(tmp_path):
    config, state, pidfile = approved_service(tmp_path)
    service = Service(module(config, "monitor"), state, pidfile)
    try:
        service.ready()
        state.chmod(0o555)  # the clean shutdown can no longer remove the unclean marker
        code, stderr = service.stop()
        state.chmod(0o755)
        assert code == 5, (code, stderr[-1000:])
        error = error_json(stderr)
        assert error["recovery_required"] is True and error["error"] in {"PermissionError", "OSError"}
        assert "unclean marker is kept" in error["message"]
        assert (state / "owner.unclean").exists()
        wait_until(lambda: not alive(service.child), 10)
        assert reopened_state(config) == "pending_review"  # recovery, not a clean reopen
    finally:
        state.chmod(0o755)
        service.kill()


def test_sigterm_after_a_storage_fault_keeps_the_marker_and_exits_nonzero(tmp_path):
    config, state, pidfile = approved_service(tmp_path, poll_interval=1)
    service = Service(module(config, "monitor"), state, pidfile)
    blocker = None
    try:
        service.ready()
        # Another process holds the write lock past the owner's busy timeout, so the
        # monitor's next poll observation cannot commit: a real authoritative fault.
        blocker = sqlite3.connect(state / "trust.sqlite3", isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        wait_until(lambda: not alive(service.child), 90)  # the fault shutdown reaped it
        blocker.execute("ROLLBACK")
        blocker.close()
        blocker = None
        code, stderr = service.stop()
        assert code == 5, (code, stderr[-1000:])
        error = error_json(stderr)
        assert error["error"] == "StorageFaultError" and error["recovery_required"] is True
        assert (state / "owner.unclean").exists()
        assert reopened_state(config) == "pending_review"
    finally:
        if blocker is not None:
            blocker.close()
        service.kill()


def test_sigterm_keeps_ownership_while_a_transport_cannot_be_confirmed_closed(tmp_path):
    shutdown_timeout = 6
    config, state, pidfile = approved_service(tmp_path, shutdown_timeout=shutdown_timeout)
    wrapper = tmp_path / "stuck_transport.py"
    wrapper.write_text(STUCK_TRANSPORT)
    service = Service([sys.executable, str(wrapper), "--config", str(config), "monitor"],
                      state, pidfile)
    try:
        service.ready()
        started = time.monotonic()
        service.process.send_signal(signal.SIGTERM)
        time.sleep(1.0)
        assert service.process.poll() is None, "exited before the retry window ended"
        with pytest.raises(OwnershipError):  # the stopping process still owns the state
            StateOwner(state).acquire()
        code = service.process.wait(timeout=90)
        elapsed = time.monotonic() - started
        stderr = service.process.stderr.read()
        assert code == 5, (code, stderr[-1000:])
        assert elapsed >= shutdown_timeout * 0.9, elapsed  # closing was retried
        error = error_json(stderr)
        assert error["error"] == "ShutdownIncompleteError"
        assert error["ownership_released"] is False and error["recovery_required"] is True
        assert "released only because this process exits" in error["message"]
        assert (state / "owner.unclean").exists()
        assert reopened_state(config) == "pending_review"
    finally:
        service.kill()



def test_sigterm_with_a_transport_ignoring_cancellation_exits_within_the_documented_bound(tmp_path):
    """Review finding F2: the stop must end within about 2 x shutdown_timeout + 15 s, and
    the process must actually exit even though a task never honors cancellation."""
    shutdown_timeout = 3
    config, state, pidfile = approved_service(tmp_path, shutdown_timeout=shutdown_timeout)
    wrapper = tmp_path / "cancel_ignoring_transport.py"
    wrapper.write_text(CANCEL_IGNORING_TRANSPORT)
    service = Service([sys.executable, str(wrapper), "--config", str(config), "monitor"],
                      state, pidfile)
    try:
        service.ready()
        started = time.monotonic()
        service.process.send_signal(signal.SIGTERM)
        code = service.process.wait(timeout=2 * shutdown_timeout + 15 + 10)  # load margin
        elapsed = time.monotonic() - started
        stderr = service.process.stderr.read()
        assert code == 5, (code, stderr[-1000:])
        assert elapsed <= 2 * shutdown_timeout + 15 + 5, elapsed
        error = error_json(stderr)
        assert error["ownership_released"] is False and error["recovery_required"] is True
        assert (state / "owner.unclean").exists()
    finally:
        service.kill()


def test_one_shot_command_with_a_transport_ignoring_cancellation_still_exits(tmp_path):
    config, state, pidfile = approved_service(tmp_path, shutdown_timeout=2)
    wrapper = tmp_path / "cancel_ignoring_transport.py"
    wrapper.write_text(CANCEL_IGNORING_TRANSPORT)
    started = time.monotonic()
    completed = subprocess.run([sys.executable, str(wrapper), "--config", str(config), "observe", "local"],
                               capture_output=True, text=True, timeout=90, cwd=str(REPO_ROOT), env=ENV)
    assert time.monotonic() - started < 60
    assert completed.returncode == 5, (completed.returncode, completed.stderr[-1000:])
    assert error_json(completed.stderr)["ownership_released"] is False
    assert (state / "owner.unclean").exists()


def test_incomplete_close_keeps_a_dispatched_calls_classification(tmp_path):
    """Review finding F3: when the close after a call is incomplete, exit 5 still says the
    call was dispatched, so a script never mistakes it for a retryable refusal."""
    settings = tmp_path / "server.json"
    settings.write_text("{}")
    calls = tmp_path / "calls.jsonl"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "state_dir": "state", "policy_path": str(POLICY_PATH), "timeout_seconds": 3,
        "shutdown_timeout": 1,
        "servers": [{"server_id": "local", "command": sys.executable,
                     "args": [str(HELPER), str(settings), str(calls)], "cwd": str(tmp_path),
                     "origin": "synthetic_fixture"}]}))
    observed = json.loads(cli(config, "observe", "local").stdout)
    assert cli(config, "approve", "local", "--revision", observed["observed_revision"],
               "--generation", str(observed["generation"])).returncode == 0
    settings.write_text(json.dumps({"call_delay": 30}))  # executes, then never answers in time
    wrapper = tmp_path / "stuck_transport.py"
    wrapper.write_text(STUCK_TRANSPORT)
    completed = subprocess.run([sys.executable, str(wrapper), "--config", str(config), "call", "local",
                                "effect", "--refresh"], capture_output=True, text=True, timeout=120,
                               cwd=str(REPO_ROOT), env=ENV)
    assert completed.returncode == 5, (completed.returncode, completed.stderr[-1000:])
    error = error_json(completed.stderr)
    assert error["error"] == "ShutdownIncompleteError" and error["ownership_released"] is False
    assert error["dispatched"] is True and error["call_error"] == "ToolOutcomeUnknown"
    assert len(calls.read_text().splitlines()) == 1
