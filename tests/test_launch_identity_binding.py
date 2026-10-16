"""Observations and dispatch are bound to the running connection's launch identity.

Corrective review D1 (launch-identity race, REQ-REV-04, REQ-ENF-01/02, REQ-ENF-06,
REQ-REV-02/03). `ServerConfig.launch_identity` is recomputed from the filesystem on
every access, while a live connection keeps running the process it spawned. When the
configured executable symlink was swapped while a session started or listed its tools,
or while an older session stayed connected, an approval recorded for the new target
authorized `tools/call` dispatch to the old process.

Every test uses the public SDK and real stdio processes. The configured command is a
symlink to one of two real wrapper scripts; each wrapper's server process appends the
tools/call requests it receives to its own log (`calls.jsonl.A` or `calls.jsonl.B`)
before responding. Those per-process logs are the independent receipt evidence: a
refusal alone only establishes local nondispatch.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path

import pytest

from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor
from mcp_trust_monitor.managed_client import CallBlocked, ObservationError
from mcp_trust_monitor.trust_store import StaleDecisionError, TrustState

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tests" / "helpers" / "monitored_server.py"
POLICY = ROOT / "policies" / "demo-policy.json"
SERVER = "identity/test"
# Long enough to swap the symlink deterministically once the marker file appears.
LIST_DELAY = 1.0
STARTUP_DELAY = "1"
WAIT_SECONDS = 20.0


def write_settings(path: Path, settings: dict) -> None:
    """Atomic, so the server never reads a partly written settings file."""
    staged = path.with_name(path.name + ".tmp")
    staged.write_text(json.dumps(settings))
    os.replace(staged, path)


def wrapper(path: Path, process: str, *, startup_marker: Path | None = None) -> Path:
    """A real launcher whose server logs received calls to `<log>.<process>`."""
    lines = ["#!/bin/sh"]
    if startup_marker is not None:
        # Started, but not yet a server: the session is still starting up.
        sleep = shutil.which("sleep") or "/bin/sleep"
        lines += [f": > {shlex.quote(str(startup_marker))}",
                  f"{shlex.quote(sleep)} {STARTUP_DELAY}"]
    lines.append(f'exec {shlex.quote(sys.executable)} "$1" "$2" "$3.{process}"')
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o755)
    return path


@dataclasses.dataclass(repr=False)
class Swappable:
    config: MonitorConfig
    settings: Path
    link: Path
    a: Path
    b: Path
    log: Path
    list_started: Path
    startup_marker: Path

    @property
    def identity(self) -> str:
        """The configured launch identity now (it follows the symlink)."""
        return self.config.servers[SERVER].launch_identity

    def calls(self, process: str) -> int:
        path = self.log.with_name(f"{self.log.name}.{process}")
        return len(path.read_text().splitlines()) if path.exists() else 0

    def __repr__(self) -> str:
        return "launch"

    def point_to(self, target: Path) -> None:
        """Swap the configured executable symlink atomically."""
        staged = self.link.with_name(self.link.name + ".swap")
        os.symlink(target, staged)
        os.replace(staged, self.link)


def swappable(tmp_path: Path, settings: dict | None = None, *, slow_a: bool = False) -> Swappable:
    settings_path = tmp_path / "settings.json"
    write_settings(settings_path, settings or {})
    log = tmp_path / "calls.jsonl"
    marker = tmp_path / "a-starting"
    a = wrapper(tmp_path / "a.sh", "A", startup_marker=marker if slow_a else None)
    b = wrapper(tmp_path / "b.sh", "B")
    (tmp_path / "bin").mkdir()
    link = tmp_path / "bin" / "server"
    os.symlink(a, link)
    profile = ServerConfig(SERVER, str(link), (str(HELPER), str(settings_path), str(log)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", POLICY, {SERVER: profile},
                           poll_interval=60, timeout_seconds=30)
    # The spawned command is the configured symlink, not its target.
    assert config.servers[SERVER].command == str(link)
    return Swappable(config, settings_path, link, a, b, log,
                     tmp_path / "list-started", marker)


async def outcome(awaitable):
    """The result, or the exception: attempt everything, then judge the evidence."""
    try:
        return await awaitable
    except Exception as exc:  # noqa: BLE001 - classified by the assertions
        return exc


def describe(value) -> str:
    """A compact outcome for assertion messages, without identity digests."""
    if isinstance(value, BaseException):
        return f"{type(value).__name__}({getattr(value, 'reason', value)})"
    if hasattr(value, "isError"):
        return "tool error" if value.isError else "tool result"
    state = getattr(value, "state", None)
    return f"record {state.value}" if state is not None else repr(value)


async def wait_for_file(path: Path, task: asyncio.Future) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while not path.exists():
        if task.done():
            raise AssertionError(f"{path.name} never appeared; observation ended: "
                                 f"{describe(await outcome(task))}")
        if time.monotonic() > deadline:
            raise AssertionError(f"{path.name} did not appear within {WAIT_SECONDS}s")
        await asyncio.sleep(0.005)


async def attempt_approval(monitor: TrustMonitor):
    record = monitor.status(SERVER)
    return await outcome(monitor.approve(
        SERVER, revision=record.observed_revision if record else "unobserved",
        expected_generation=record.generation if record else None, actor="operator"))


async def approve(monitor: TrustMonitor, session=None):
    target = session or monitor
    record = await target.observe(SERVER)
    return await target.approve(SERVER, revision=record.observed_revision,
                                expected_generation=record.generation, actor="operator")


def kinds(monitor: TrustMonitor) -> list[str]:
    return [event["event_type"] for event in monitor.events(SERVER)]


def observed_identities(monitor: TrustMonitor) -> list[str]:
    """The launch identity in each retained observation's endpoint provenance."""
    return [row["endpoint"].rsplit("#", 1)[-1] for row in monitor.store.observations(SERVER)]


async def recover_under_b(monitor: TrustMonitor, launch: Swappable, identity_b: str,
                          *, calls_a: int) -> None:
    """A fresh observation under B succeeds but grants nothing until approved."""
    write_settings(launch.settings, {})
    recovered = await monitor.observe(SERVER)
    assert recovered.launch_identity == identity_b
    assert recovered.state is not TrustState.APPROVED
    refused = await outcome(monitor.call_tool(SERVER, "effect"))
    assert isinstance(refused, CallBlocked), refused
    assert (launch.calls("A"), launch.calls("B")) == (calls_a, 0)
    approved = await monitor.approve(SERVER, revision=recovered.observed_revision,
                                     expected_generation=recovered.generation, actor="operator")
    assert approved.approved_launch_identity == identity_b
    entry, = monitor.catalog(SERVER)
    assert entry.selection.launch_identity == identity_b
    assert not (await monitor.call_tool(SERVER, "effect")).isError
    assert not (await monitor.call_tool(SERVER, "effect", selection=entry.selection)).isError
    assert (launch.calls("A"), launch.calls("B")) == (calls_a, 2)


async def test_swap_during_first_tools_list_is_never_recorded_or_dispatched(tmp_path):
    launch = swappable(tmp_path, {"list_started": str(tmp_path / "list-started"),
                                  "list_delay": LIST_DELAY})
    identity_a = launch.identity
    async with TrustMonitor(launch.config) as monitor:
        observing = asyncio.ensure_future(monitor.observe(SERVER))
        await wait_for_file(launch.list_started, observing)  # process A is listing
        launch.point_to(launch.b)
        identity_b = launch.identity
        assert identity_b != identity_a
        observed = await outcome(observing)
        approved = await attempt_approval(monitor)
        called = await outcome(monitor.call_tool(SERVER, "effect"))
        # Independent receipt evidence first: neither process received a call.
        assert launch.calls("A") == 0, (
            f"tools/call reached the old process A (observe -> {describe(observed)}, "
            f"approve -> {describe(approved)}, call -> {describe(called)})")
        assert launch.calls("B") == 0
        assert isinstance(observed, ObservationError), observed
        assert "launch identity" in str(observed)
        assert isinstance(approved, StaleDecisionError), approved
        assert isinstance(called, CallBlocked) and called.reason == "unobserved", called
        assert monitor.status(SERVER) is None  # never recorded, so never approvable
        assert observed_identities(monitor) == []
        assert kinds(monitor).count("observation_failed") == 1
        assert not monitor.client.is_connected(SERVER)
        assert monitor.catalog() == ()
        await recover_under_b(monitor, launch, identity_b, calls_a=0)


async def test_swap_during_startup_is_never_recorded_or_dispatched(tmp_path):
    launch = swappable(tmp_path, slow_a=True)
    identity_a = launch.identity
    async with TrustMonitor(launch.config) as monitor:
        observing = asyncio.ensure_future(monitor.observe(SERVER))
        await wait_for_file(launch.startup_marker, observing)  # A started, not initialized
        launch.point_to(launch.b)
        identity_b = launch.identity
        assert identity_b != identity_a
        observed = await outcome(observing)
        approved = await attempt_approval(monitor)
        called = await outcome(monitor.call_tool(SERVER, "effect"))
        assert launch.calls("A") == 0, (
            f"tools/call reached the old process A (observe -> {describe(observed)}, "
            f"approve -> {describe(approved)}, call -> {describe(called)})")
        assert launch.calls("B") == 0
        assert isinstance(observed, ObservationError), observed
        assert "launch identity" in str(observed)
        assert isinstance(approved, StaleDecisionError), approved
        assert isinstance(called, CallBlocked) and called.reason == "unobserved", called
        assert monitor.status(SERVER) is None
        assert observed_identities(monitor) == []
        assert kinds(monitor).count("observation_failed") == 1
        assert not monitor.client.is_connected(SERVER)
        assert monitor.catalog() == ()
        assert monitor.client.transports_finished()  # the startup process was reaped
        await recover_under_b(monitor, launch, identity_b, calls_a=0)


async def test_swap_during_reobservation_of_an_approved_server_fails_closed(tmp_path):
    launch = swappable(tmp_path)
    identity_a = launch.identity
    async with TrustMonitor(launch.config) as monitor:
        await approve(monitor)
        assert not (await monitor.call_tool(SERVER, "effect")).isError
        assert launch.calls("A") == 1
        write_settings(launch.settings, {"list_started": str(launch.list_started),
                                         "list_delay": LIST_DELAY})
        observing = asyncio.ensure_future(monitor.observe(SERVER))  # reuses process A
        await wait_for_file(launch.list_started, observing)
        launch.point_to(launch.b)
        identity_b = launch.identity
        observed = await outcome(observing)
        called = await outcome(monitor.call_tool(SERVER, "effect"))
        assert (launch.calls("A"), launch.calls("B")) == (1, 0)
        assert isinstance(called, CallBlocked), called
        # Process A's metadata is never retained as an observation of B.
        assert observed_identities(monitor) == [identity_a], (
            f"process A's tools/list was retained as an observation of B "
            f"(observe -> {describe(observed)})")
        assert isinstance(observed, ObservationError), observed
        record = monitor.status(SERVER)
        assert record.state is TrustState.PENDING_REVIEW
        assert record.observation_failed_at is not None
        assert kinds(monitor).count("observation_failed") == 1
        assert not monitor.client.is_connected(SERVER)
        assert monitor.catalog() == ()
        await recover_under_b(monitor, launch, identity_b, calls_a=1)
        assert observed_identities(monitor) == [identity_a, identity_b]


async def test_connected_old_session_cannot_dispatch_under_approval_for_a_new_target(tmp_path):
    launch = swappable(tmp_path)
    async with TrustMonitor(launch.config) as monitor:
        first = monitor.client
        reviewed_a = await approve(monitor)
        assert not (await monitor.call_tool(SERVER, "effect")).isError
        assert launch.calls("A") == 1
        first_session = monitor.health()["servers"][SERVER]["session_id"]
        launch.point_to(launch.b)
        second = monitor.new_session()
        pending = await second.observe(SERVER)  # spawns B; the record moves to identity B
        assert pending.launch_identity == launch.identity != reviewed_a.launch_identity
        assert pending.state is TrustState.PENDING_REVIEW
        reviewed_b = await second.approve(SERVER, revision=pending.observed_revision,
                                          expected_generation=pending.generation,
                                          actor="operator")
        assert reviewed_b.approved_launch_identity == launch.identity
        assert first.is_connected(SERVER)  # the first session still runs process A
        entry, = second.catalog(SERVER)
        # The token the first session's own catalog would carry for the B approval.
        first_token = dataclasses.replace(entry.selection, session_id=first_session)
        tokenless = await outcome(first.call_tool(SERVER, "effect"))
        with_token = await outcome(first.call_tool(SERVER, "effect", selection=first_token))
        first_catalog = first.catalog(SERVER)
        freshness = monitor.health()["servers"][SERVER]["freshness"]
        assert launch.calls("A") == 1, (
            f"the old session dispatched to process A under the approval for B "
            f"(tokenless -> {describe(tokenless)}, token -> {describe(with_token)})")
        assert isinstance(tokenless, CallBlocked), tokenless
        assert tokenless.reason == "launch_identity_changed"
        assert isinstance(with_token, CallBlocked), with_token
        assert with_token.reason == "launch_identity_changed"
        assert first_catalog == ()
        assert freshness == "launch_identity_changed"
        blocked = [event["detail"] for event in monitor.events(SERVER)
                   if event["event_type"] == "call_blocked"]
        assert [detail["reason"] for detail in blocked] == ["launch_identity_changed"] * 2
        assert all(detail["local_nondispatch"] for detail in blocked)
        # The session that observed B dispatches to B only.
        assert not (await second.call_tool(SERVER, "effect")).isError
        assert not (await second.call_tool(SERVER, "effect", selection=entry.selection)).isError
        assert (launch.calls("A"), launch.calls("B")) == (1, 2)
        # Observing again replaces the first session's process A with B.
        await first.observe(SERVER)
        assert monitor.health()["servers"][SERVER]["freshness"] == "fresh"
        assert monitor.health()["servers"][SERVER]["session_id"] != first_session
        assert not (await first.call_tool(SERVER, "effect")).isError
        assert (launch.calls("A"), launch.calls("B")) == (1, 3)
        assert monitor.status(SERVER).state is TrustState.APPROVED
        assert observed_identities(monitor) == [reviewed_a.launch_identity,
                                                launch.identity, launch.identity]


async def test_swap_after_a_clean_observation_blocks_before_dispatch(tmp_path):
    launch = swappable(tmp_path)
    async with TrustMonitor(launch.config) as monitor:
        await approve(monitor)
        entry, = monitor.catalog(SERVER)
        launch.point_to(launch.b)
        identity_b = launch.identity
        tokenless = await outcome(monitor.call_tool(SERVER, "effect"))
        with_token = await outcome(monitor.call_tool(SERVER, "effect", selection=entry.selection))
        assert (launch.calls("A"), launch.calls("B")) == (0, 0)
        assert isinstance(tokenless, CallBlocked), tokenless
        assert tokenless.reason == "launch_identity_changed"
        assert isinstance(with_token, CallBlocked), with_token
        assert with_token.reason == "launch_identity_changed"
        assert monitor.catalog() == ()
        await recover_under_b(monitor, launch, identity_b, calls_a=0)


def virtualenv_interpreter(tmp_path: Path) -> Path:
    """`venv/bin/python` -> this test's interpreter, inside a virtualenv layout.

    The interpreter finds its environment from the configured (symlink) path, so the
    server only imports its dependencies when it is spawned through that path.
    """
    if sys.prefix == sys.base_prefix:
        pytest.skip("requires the test interpreter to run in a virtual environment")
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    shutil.copyfile(Path(sys.prefix) / "pyvenv.cfg", venv / "pyvenv.cfg")
    (venv / "lib").symlink_to(Path(sys.prefix) / "lib", target_is_directory=True)
    python = venv / "bin" / "python"
    python.symlink_to(sys.executable)
    return python


async def test_unchanged_symlinked_virtualenv_interpreter_keeps_a_stable_identity(tmp_path):
    python = virtualenv_interpreter(tmp_path)
    assert python.resolve() != python  # identity dereferences it; the spawn does not
    settings, log = tmp_path / "settings.json", tmp_path / "calls.jsonl"
    write_settings(settings, {})
    profile = ServerConfig(SERVER, str(python), (str(HELPER), str(settings), str(log)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", POLICY, {SERVER: profile},
                           poll_interval=60, timeout_seconds=30)
    assert config.servers[SERVER].command == str(python)
    identity = config.servers[SERVER].launch_identity

    def calls() -> int:
        return len(log.read_text().splitlines()) if log.exists() else 0

    async with TrustMonitor(config) as monitor:
        approved = await approve(monitor)
        assert approved.launch_identity == approved.approved_launch_identity == identity
        assert monitor.health()["servers"][SERVER]["freshness"] == "fresh"
        entry, = monitor.catalog(SERVER)
        assert not (await monitor.call_tool(SERVER, "effect", selection=entry.selection)).isError
        assert calls() == 1
    assert config.servers[SERVER].launch_identity == identity
    async with TrustMonitor(config) as monitor:  # a new owner of the same state
        kept = monitor.status(SERVER)
        assert kept.state is TrustState.APPROVED and kept.launch_identity == identity
        refused = await outcome(monitor.call_tool(SERVER, "effect"))
        assert isinstance(refused, CallBlocked) and refused.reason == "session_refresh_required"
        observed = await monitor.observe(SERVER)
        assert observed.state is TrustState.APPROVED and observed.launch_identity == identity
        assert not (await monitor.call_tool(SERVER, "effect")).isError
        assert calls() == 2
        assert not {"launch_identity_changed", "observation_failed"} & set(kinds(monitor))
        assert observed_identities(monitor) == [identity, identity]
