"""The managed MCP client and its trust gate.

`call_tool` is the only path to `tools/call`. Under a per-server lock it reads the
persisted trust record immediately before writing the request to the MCP
transport (REQ-ENF-01) and refuses unless that exact revision is approved under the
active policy (REQ-ENF-02). It checks once before connecting, so a blocked call
never launches or contacts the server, and again immediately before dispatch.

A session is eligible for dispatch only while its own most recent observation
succeeded and recorded the revision the store currently holds. A session validated
at an older revision is re-observed before dispatch, so a persisted approval cannot
stand in for current metadata.

A connection, initialization, or tools/list failure atomically moves an approved
server to pending review and records `observation_failed` (quarantine is
preserved), then closes the failing session (REQ-REV-02). Because every session of
this managed client authorizes against the same persisted record, they all block
until valid metadata is observed and an operator approves again.

`observe` is metadata-only (initialize and paginated tools/list). It records the
server revision with its provenance (REQ-REV-03), which may invalidate an approval,
and never dispatches a tool.

`apply_hard_deny` applies a deterministic detector match under the same per-server
lock, only if the assessed revision, generation, and policy are still current, and
closes the connection when it quarantines (REQ-DEC-01, REQ-ENF-03).

The final gate and the hand-off of a tools/call to the transport are one synchronous
step under the per-server lock: no await separates authorization, the dispatch-start
audit and the enqueue, so quarantine, invalidation and policy reload either commit
before the gate or after the request entered the transport (REQ-ENF-05). When a server
stops draining its input, the call waits for the transport without holding that lock
and repeats the whole gate; the wait is bounded, and a call that never entered the
transport is refused, never replayed (REQ-ENF-04, REQ-ENF-08).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import time
import uuid
import weakref
from types import MappingProxyType
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Mapping

import anyio
import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ._lifecycle import _CancellationTracker
from .revision import digest, server_revision, tool_metadata
from .trust_store import HardDenyOutcome, TrustRecord, TrustState, TrustStore, StorageFaultError, StaleDecisionError, TrustError

MAX_TOOL_LIST_PAGES = 20
# Backoff bounds while a tools/call waits for a transport that is not accepting input.
_ENQUEUE_POLL_MIN = 0.001
_ENQUEUE_POLL_MAX = 0.05
# Closing a stdio transport: the MCP shutdown sequence (stdin EOF, then SIGTERM and
# SIGKILL to the server's process group) gets this long before its task is cancelled,
# and the cancelled task this long again to finish reaping the process (REQ-MON-03).
_TRANSPORT_CLOSE_SECONDS = 5.0
_TRANSPORT_CANCEL_SECONDS = 5.0
# Once a transport was cancelled, later closes of it only recheck, so one shutdown pays
# the close bound once per transport rather than once per sweep or retry.
_TRANSPORT_RECHECK_SECONDS = 0.5


@dataclass(frozen=True)
class ServerConfig:
    server_id: str
    command: str
    args: tuple[str, ...] = ()
    # None passes only the MCP SDK's minimal default environment to the server.
    env: Mapping[str, str] | None = None
    cwd: str | None = None
    # `live` or `synthetic_fixture`; recorded with every observation (REQ-REV-03).
    origin: str = "live"

    secret_env: Mapping[str, str] = field(default_factory=dict)

    @property
    def launch_identity(self) -> str:
        executable = shutil.which(self.command) or self.command
        return digest({"command": str(Path(executable).resolve()), "args": list(self.args),
                       "cwd": str(Path(self.cwd or os.getcwd()).resolve()),
                       "env": dict(self.env or {}), "secret_env": dict(self.secret_env)})

    def launch_env(self):
        result = dict(self.env or {})
        for key, reference in self.secret_env.items():
            if reference not in os.environ:
                raise ObservationError(f"missing credential reference for environment key {key}")
            result[key] = os.environ[reference]
        return result or None

    @property
    def endpoint(self) -> str:
        """Endpoint identity without arguments, which could carry credentials."""
        return f"stdio:{self.server_id}#{self.launch_identity}"



class CallBlocked(Exception):
    def __init__(self, server_id: str, tool: str, reason: str) -> None:
        super().__init__(f"call to {server_id}/{tool} blocked before dispatch: {reason}")
        self.server_id = server_id
        self.tool = tool
        self.reason = reason


class ToolOutcomeUnknown(Exception):
    """A dispatched call did not yield a result; it is never automatically replayed."""


class DispatchedCallUnrecorded(Exception):
    """A dispatched tools/call returned, but its completion audit was not committed.

    The call executed and `result` holds the server's response. This is not a refusal
    before dispatch (`CallBlocked`, or `StorageFaultError` from the gate), so it is
    deliberately not a `TrustError`: never replay it. Authoritative storage stays
    latched until the owner is closed, repaired and reopened (REQ-ENF-05, REQ-ENF-07,
    REQ-ENF-08).
    """

    def __init__(self, server_id: str, tool: str, result: types.CallToolResult) -> None:
        super().__init__(f"call to {server_id}/{tool} was dispatched and returned, but its "
                         "completion audit was not committed; do not replay it")
        self.server_id = server_id
        self.tool = tool
        self.result = result


@dataclass(eq=False)
class _PendingCall:
    """An in-flight protected call: enough to settle its outcome exactly once."""

    server_id: str
    tool: str
    call_id: str
    attempt: dict
    recorded: bool = False


class ObservationError(Exception):
    """tools/list did not produce a complete, valid observation. Never a clean result."""


@dataclass(eq=False)
class _Connection:
    """Owns one stdio session in a dedicated task so it can close independently.

    A live resource: compared and hashed by identity."""

    config: ServerConfig
    timeout: timedelta
    launch_identity: str = field(init=False)
    session: ClientSession | None = None
    # From the MCP initialize result; recorded as observation provenance (REQ-REV-03).
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None
    # Revision recorded by this session's last successful observation; None until then.
    validated_revision: str | None = None
    observed_at: float | None = None
    dirty_epoch: int = 0
    observed_epoch: int = -1
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    notification: Callable[[str], None] | None = None
    dispatch: Callable | None = None
    _ready: asyncio.Event = field(default_factory=asyncio.Event)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    _task: asyncio.Task[None] | None = None
    _error: BaseException | None = None
    _cancel_issued: bool = False

    def __post_init__(self):
        self.launch_identity = self.config.launch_identity

    async def open(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"mcp:{self.config.server_id}")
        try:
            await asyncio.wait_for(self._ready.wait(), self.timeout.total_seconds())
        except BaseException:
            await self.close()
            raise
        if self.session is None:
            await self.close()
            raise ObservationError(
                f"could not connect to {self.config.server_id}: {self._error!r}"
            )

    @property
    def alive(self) -> bool:
        return self.session is not None and self._task is not None and not self._task.done()

    @property
    def finished(self) -> bool:
        """The transport task ended; its stdio subprocess was closed and reaped by then."""
        return self._task is None or self._task.done()

    async def close(self) -> None:
        """Stop the session and reap its server process, within a bound.

        A transport task that has still not finished afterwards stays unfinished
        (`finished` is False), so the owner keeps ownership instead of waiting
        indefinitely for it (REQ-MON-03).
        """
        self._stop.set()
        task = self._task
        if task is None:
            return
        if self._cancel_issued:
            # An earlier close spent the bound and cancelled the task: only recheck.
            await asyncio.wait({task}, timeout=_TRANSPORT_RECHECK_SECONDS)
        else:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=_TRANSPORT_CLOSE_SECONDS)
            except (Exception, asyncio.CancelledError):
                self._cancel_issued = True
                task.cancel()
                await asyncio.wait({task}, timeout=_TRANSPORT_CANCEL_SECONDS)
        if task.done() and not task.cancelled():
            task.exception()  # retrieved: _run records its own error

    async def _message(self, message):
        if isinstance(message, types.ServerNotification) and isinstance(message.root, types.ToolListChangedNotification):
            self.dirty_epoch += 1
            if self.notification:
                self.notification(self.config.server_id)

    async def _run(self) -> None:
        try:
            params = StdioServerParameters(
                command=self.config.command,
                args=list(self.config.args),
                env=self.config.launch_env(),
                cwd=self.config.cwd,
            )
            async with stdio_client(params) as (read, write):
                transport = _DispatchStream(write, self) if self.dispatch else write
                async with ClientSession(read, transport, read_timeout_seconds=self.timeout,
                                         message_handler=self._message) as session:
                    initialized = await session.initialize()
                    self.server_name = initialized.serverInfo.name
                    self.server_version = initialized.serverInfo.version
                    self.protocol_version = str(initialized.protocolVersion)
                    self.session = session
                    self._ready.set()
                    await self._stop.wait()
        except Exception as exc:
            self._error = exc
        finally:
            was_live = self.session is not None
            self.session = None
            self._ready.set()
            if was_live and not self._stop.is_set() and self.notification is not None:
                self.notification(self.config.server_id)


class ManagedClient:
    def __init__(
        self,
        store: TrustStore,
        servers: Mapping[str, ServerConfig],
        *,
        policy_revision: str,
        timeout_seconds: float = 15.0,
        strict: bool = False,
        poll_interval: float = 30.0,
        notification: Callable[[str], None] | None = None,
        _cancellation: _CancellationTracker | None = None,
    ) -> None:
        self.store = store
        self.servers = dict(servers)
        self.policy_revision = policy_revision
        self._timeout = timedelta(seconds=timeout_seconds)
        self.strict = strict
        self.poll_interval = poll_interval
        self.notification = notification
        self._cancellation = _cancellation or _CancellationTracker()
        self._closed = False
        # Set when the owner closes or storage faults: in-flight calls stop waiting.
        self._closing = asyncio.Event()
        # In-flight protected calls: each request task and the state needed to settle it.
        self._inflight: dict[asyncio.Future, _PendingCall] = {}
        self._observations: set[asyncio.Task] = set()
        self._connections: dict[str, _Connection] = {}
        # Every transport this client started, until its task has finished (REQ-MON-03).
        self._opened: set[_Connection] = set()
        if not hasattr(store, "_client_locks"):
            store._client_locks = {}
        self._locks: dict[str, asyncio.Lock] = store._client_locks
        if not hasattr(store, "_owned_clients"):
            store._owned_clients = weakref.WeakSet()
        if strict:
            store._owned_clients.add(self)
        self._dispatched: Counter[str] = Counter()

    async def __aenter__(self) -> "ManagedClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    def dispatch_count(self, server_id: str) -> int:
        """tools/call requests this client instance has written to the transport."""
        return self._dispatched[server_id]

    def is_connected(self, server_id: str) -> bool:
        connection = self._connections.get(server_id)
        return connection is not None and connection.alive

    async def observe(self, server_id: str) -> TrustRecord:
        task = asyncio.current_task()
        self._observations.add(task)
        self._cancellation.register(task)
        try:
            return await self._observe_locked(server_id)
        finally:
            self._observations.discard(task)
            self._cancellation.release(task)

    async def _observe_locked(self, server_id: str) -> TrustRecord:
        async with self._lock(server_id):
            self.store.check_health()
            if self.strict and self._closed:
                raise TrustError("client is closed")
            if self.strict:
                self.store.ensure_identity(server_id, self.servers[server_id].launch_identity)
            connection = await self._open_connection(server_id)
            return await self._observe(server_id, connection)

    async def approve(
        self, server_id: str, *, revision: str, expected_generation: int | None, actor: str, restore: bool = False
    ) -> TrustRecord:
        async with self._lock(server_id):
            if self.strict:
                current = self.store.get(server_id)
                if current is None or current.launch_identity != self.servers[server_id].launch_identity:
                    raise StaleDecisionError("launch identity needs observation")
                if expected_generation is not None and current.generation != expected_generation:
                    raise StaleDecisionError("decision generation changed")
            record = self.store.approve(
                server_id,
                revision=revision,
                policy_revision=self.policy_revision,
                expected_generation=expected_generation,
                actor=actor, restore=restore,
            )
            self._catalog_changed()
            return record

    async def quarantine(self, server_id: str, *, actor: str, reason: str) -> TrustRecord:
        async with self._lock(server_id):
            record = self.store.quarantine(server_id, actor=actor, reason=reason)
            await self._disconnect_owned(server_id)
            return record

    async def apply_hard_deny(
        self,
        server_id: str,
        *,
        revision: str,
        generation: int,
        policy_context: str,
        active_policy_context: Callable[[], str],
        detection: Mapping[str, Any],
        actor: str = "hard-deny-detector",
        context_guard: Callable[[], str | None] | None = None,
    ) -> HardDenyOutcome:
        """Apply under the per-server lock. `active_policy_context` is evaluated here, at
        apply time, so a policy or rules change since the scan makes the result stale."""
        async with self._lock(server_id):
            outcome = self.store.apply_hard_deny(
                server_id, revision=revision, generation=generation,
                policy_revision=policy_context, active_policy_revision=active_policy_context(),
                detection=detection, actor=actor, context_guard=context_guard,
            )
            if outcome.status in ("applied", "already_quarantined"):
                await self._disconnect_owned(server_id)
            return outcome

    async def record_assessment_if_current(self, server_id: str, *, revision: str,
                                           generation: int, policy_context: str,
                                           active_policy_context: Callable[[], str], detail,
                                           actor="model-reviewer", context_guard=None):
        async with self._lock(server_id):
            return self.store.record_assessment_if_current(
                server_id, revision=revision, generation=generation,
                policy_revision=policy_context, active_policy_revision=active_policy_context(),
                detail=detail, actor=actor, context_guard=context_guard)

    async def observe_and_call(self, server_id, tool, arguments=None, *, selection=None):
        self._authorize(server_id, tool, selection=selection)
        await self.observe(server_id)
        return await self.call_tool(server_id, tool, arguments, selection=selection)

    async def call_tool(self, server_id, tool, arguments=None, *, selection=None):
        if not self.strict:
            return await self._legacy_call_tool(server_id, tool, arguments)
        # Strict ordinary calls never start or refresh a transport.
        connection = self._connections.get(server_id)
        self._authorize(server_id, tool, connection, require_session=True, selection=selection)
        assert connection is not None and connection.session is not None
        call_id = uuid.uuid4().hex
        # The stream guard repeats authorization at enqueue, with this call's token.
        attempt = {"dispatched": False}
        token = _dispatch_context.set((tool, selection, call_id, attempt))
        try:
            # The request runs as a child task that inherits this context. Owner shutdown
            # or a storage fault cancels and settles that request, never the caller's
            # task, so the caller receives an outcome instead of a bare cancellation.
            request = asyncio.ensure_future(connection.session.call_tool(tool, arguments or {}))
        finally:
            _dispatch_context.reset(token)
        pending = self._inflight[request] = _PendingCall(server_id, tool, call_id, attempt)
        self._cancellation.register(request)
        request.add_done_callback(self._request_finished)
        try:
            closing = asyncio.ensure_future(self._closing.wait())
            try:
                await asyncio.wait({request, closing}, return_when=asyncio.FIRST_COMPLETED)
            except asyncio.CancelledError:
                # The caller's own cancellation. A cancelled request can no longer reach
                # the transport (the hand-off is synchronous), so its dispatched state is
                # final: record before waiting for it to unwind, then propagate. If
                # shutdown already cancelled and settled it, it is not cancelled again.
                if not pending.recorded:
                    self._cancellation.cancel(request)
                    self._settle(pending, closing=False)
                await asyncio.wait({request})
                raise
            finally:
                closing.cancel()
            if not request.done() or request.cancelled():
                # The owner closed or storage faulted. Shutdown cancelled and settled this
                # request; a second cancellation would interrupt cleanup already under way.
                if not pending.recorded:
                    self._cancellation.cancel(request)
                    self._settle(pending, closing=True)
                # asyncio.wait does not forward a later caller cancellation into
                # cleanup already under way. The client owns it until it finishes.
                await asyncio.wait({request})
                if not attempt["dispatched"]:
                    raise CallBlocked(server_id, tool, "client_closed")
                raise ToolOutcomeUnknown(
                    f"{server_id}/{tool}: the owner closed before a response; outcome unknown; "
                    "no automatic retry")
            try:
                result = request.result()
            except Exception as exc:
                if not attempt["dispatched"]:
                    raise  # Refused or failed before the transport hand-off.
                self._record_completion(server_id, call_id, tool, "outcome_unknown")
                raise ToolOutcomeUnknown(
                    f"{server_id}/{tool}: dispatched outcome unknown; no automatic retry") from exc
            self._record_completion(server_id, call_id, tool,
                                    "tool_error" if result.isError else "ok", result=result)
            return result
        finally:
            if request.done():
                self._inflight.pop(request, None)

    def _request_finished(self, request) -> None:
        """A cancelled caller may leave before its request cleanup (REQ-MON-03)."""
        self._inflight.pop(request, None)
        self._cancellation.release(request)
        if not request.cancelled():
            request.exception()  # retrieve even when the caller already left

    def _settle(self, pending: _PendingCall, *, closing: bool) -> None:
        """Record, once, the outcome of a call whose request was cancelled unresolved.

        Runs synchronously right after the request was cancelled. From then on it can
        no longer reach the transport, so `dispatched` is final: a dispatched call is
        recorded as outcome_unknown, and a call stopped by owner close before dispatch
        as a client_closed refusal. With storage latched nothing can be recorded; the
        caller still receives its classified outcome (REQ-ENF-05/08, REQ-AUD-01).
        """
        if pending.recorded:
            return
        pending.recorded = True
        if self.store.faulted:
            return
        try:
            if pending.attempt["dispatched"]:
                self.store.record_event(pending.server_id, "call_completed", actor="managed-client",
                                        detail={"call_id": pending.call_id, "tool": pending.tool,
                                                "outcome": "outcome_unknown"})
            elif closing:
                self.store.record_event(pending.server_id, "call_blocked", actor="managed-client",
                                        detail={"tool": pending.tool, "reason": "client_closed",
                                                "call_id": pending.call_id, "local_nondispatch": True,
                                                "independent_verification": "verification_unavailable"})
        except StorageFaultError:
            pass  # Storage is latched; the classified outcome still reaches the caller.

    def _record_completion(self, server_id: str, call_id: str, tool: str, outcome: str, *,
                           result: types.CallToolResult | None = None, quiet: bool = False) -> None:
        """Commit a dispatched call's completion audit.

        A storage fault here never masquerades as a refusal before dispatch: a known
        result is returned inside `DispatchedCallUnrecorded`, an unknown outcome stays
        `ToolOutcomeUnknown`, and cancellation still propagates (REQ-ENF-05/08).
        """
        try:
            self.store.record_event(server_id, "call_completed", actor="managed-client",
                                    detail={"call_id": call_id, "tool": tool, "outcome": outcome})
        except StorageFaultError as fault:
            if quiet:
                return  # Storage stays latched; the caller's cancellation is preserved.
            if result is not None:
                raise DispatchedCallUnrecorded(server_id, tool, result) from fault
            raise ToolOutcomeUnknown(
                f"{server_id}/{tool}: dispatched outcome unknown and its completion audit was "
                "not committed; no automatic retry") from fault

    async def _dispatch(self, connection, message, transport):
        """The final gate for one tools/call, then its hand-off to the transport.

        Under the per-server lock, with no await in between, the gate re-authorizes,
        records the dispatch start and hands the request to a transport writer that is
        ready to take it. A transport that is not accepting input is waited for outside
        the lock, after which the complete gate runs again. The wait is bounded by the
        session timeout; a call refused while waiting never entered the transport.
        """
        server_id = connection.config.server_id
        context = _dispatch_context.get()
        if context is None:
            raise TrustError("tools/call outside the protected call path")
        tool, selection, call_id, attempt = context
        deadline = time.monotonic() + self._timeout.total_seconds()
        delay = _ENQUEUE_POLL_MIN
        while True:
            async with self._lock(server_id):
                record = self._authorize(server_id, tool, connection, require_session=True,
                                         selection=selection)
                state = _transport_state(transport)
                if state == "closed":
                    # The stdio writer is gone (for example, the server exited): nothing
                    # can be sent, so refuse now rather than wait for the deadline.
                    self._refuse(server_id, tool, "transport_closed", call_id=call_id)
                if state == "ready":
                    self.store.record_event(server_id, "call_dispatch_started",
                                            actor="managed-client",
                                            detail={"call_id": call_id, "tool": tool,
                                                    "revision": record.observed_revision,
                                                    "generation": record.generation})
                    try:
                        transport.send_nowait(message)
                    except anyio.WouldBlock:
                        self._refuse(server_id, tool, "transport_backpressure", call_id=call_id)
                    except (anyio.ClosedResourceError, anyio.BrokenResourceError):
                        self._refuse(server_id, tool, "transport_closed", call_id=call_id)
                    self._dispatched[server_id] += 1
                    attempt["dispatched"] = True
                    return
            # Response waiting, and any wait for the transport, happen outside the lock,
            # permitting quarantine, invalidation and policy reload to commit.
            if time.monotonic() >= deadline:
                self._refuse(server_id, tool, "transport_backpressure", call_id=call_id)
            await asyncio.sleep(delay)
            delay = min(delay * 2, _ENQUEUE_POLL_MAX)

    def catalog(self, server_id=None):
        self.store.check_health()
        entries = []
        if self._closed:
            return ()
        for sid in ([server_id] if server_id else self.servers):
            record = self.store.get(sid)
            if record is None:
                continue
            connection = self._connections.get(sid)
            for tool in record.observed_tools:
                reason = self._block_reason(record, tool["name"])
                if reason is None and (record.launch_identity != self.servers[sid].launch_identity or
                                       record.approved_launch_identity != record.launch_identity):
                    reason = "launch_identity_changed"
                if reason is None:
                    reason = self._session_reason(record, connection)
                if reason is not None:
                    continue
                token = SelectionToken(sid, record.launch_identity, record.observed_revision,
                                       record.generation, self.policy_revision, connection.session_id)
                entries.append(CatalogEntry(sid, _freeze(tool_metadata(tool)), token))
        return tuple(entries)

    async def _legacy_call_tool(
        self, server_id: str, tool: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        async with self._lock(server_id):
            try:
                self._authorize(server_id, tool)
                connection = await self._validated_connection(server_id)
                record = self._authorize(server_id, tool, connection)
            except CallBlocked as blocked:
                if blocked.reason == TrustState.QUARANTINED.value:
                    # Quarantined elsewhere, such as by the CLI: drop this client's session too.
                    await self._disconnect(server_id)
                raise
            assert connection.session is not None
            # No await between the authoritative check above and this transport write.
            self._dispatched[server_id] += 1
            outcome = "error"
            try:
                result = await connection.session.call_tool(tool, arguments or {})
                outcome = "tool_error" if result.isError else "ok"
                return result
            finally:
                self.store.record_event(
                    server_id, "call_dispatched", actor="managed-client",
                    detail={"tool": tool, "outcome": outcome,
                            "revision": record.observed_revision,
                            "generation": record.generation},
                )

    async def aclose(self) -> None:
        """Close this session: settle in-flight calls, close its transports, then wait
        a bounded time (the session timeout) for cancelled observations and requests."""
        tasks = self._begin_close()
        await self._close_transports()
        pending = {task for task in tasks if not task.done()}
        if pending:
            await asyncio.wait(pending, timeout=self._timeout.total_seconds())
        for task in tasks:
            if task.done() and not task.cancelled():
                task.exception()  # outcomes were settled and reported by _begin_close

    def _begin_close(self) -> list[asyncio.Task]:
        """Refuse new work, stop in-flight calls waiting and cancel observations.

        Each in-flight request is cancelled and its outcome recorded now, while the
        store is open; the caller's own task is neither cancelled nor joined. The caller
        then raises `ToolOutcomeUnknown` once dispatched, or `CallBlocked` before, so
        owner shutdown or a storage fault never turns a call that may have executed into
        a bare cancellation (REQ-ENF-05, REQ-ENF-08). Returns the tasks to join.
        """
        # A second call (a fault shutdown, then the owner's close) only collects the
        # unfinished work: cancelling it again would interrupt cleanup already under way.
        self._closed = True
        self._closing.set()
        requests = []
        for request, pending in list(self._inflight.items()):
            if not request.done():
                # Cancel and settle once, including when the caller already cancelled
                # and settled it (its cleanup may still be under way).
                if not pending.recorded:
                    self._cancellation.cancel(request)
                    self._settle(pending, closing=True)  # while the store is still open
                requests.append(request)
        current = asyncio.current_task()
        observations = [task for task in self._observations
                        if task is not current and not task.done()]
        for task in observations:
            self._cancellation.cancel(task)
        # Only the per-call request tasks are joined, never the callers' own tasks.
        return [*observations, *requests]

    async def _close_transports(self) -> None:
        """Close every transport this client started without waiting for caller cleanup.

        Closing does not depend on cancelled application tasks finishing their own
        cleanup, so owned subprocesses are reaped before ownership can be released.
        """
        await asyncio.gather(*(self._disconnect(server_id) for server_id in list(self._connections)),
                             return_exceptions=True)
        stragglers = [connection for connection in self._opened if not connection.finished]
        if stragglers:  # e.g. a disconnect that was itself interrupted
            await asyncio.gather(*(connection.close() for connection in stragglers),
                                 return_exceptions=True)

    def transports_finished(self) -> bool:
        """True when every transport this client started has finished (REQ-MON-03)."""
        self._opened = {connection for connection in self._opened if not connection.finished}
        return not self._opened

    # Internals

    def _lock(self, server_id: str) -> asyncio.Lock:
        if server_id not in self.servers:
            raise KeyError(f"{server_id} is not configured for this client")
        return self._locks.setdefault(server_id, asyncio.Lock())

    def _authorize(
        self, server_id: str, tool: str, connection: _Connection | None = None,
        *, require_session=False, selection=None
    ) -> TrustRecord:
        self.store.check_health()
        record = self.store.get(server_id)
        reason = "client_closed" if self.strict and self._closed else self._block_reason(record, tool)
        if reason is None and self.strict and record is not None:
            if record.launch_identity != self.servers[server_id].launch_identity or record.approved_launch_identity != record.launch_identity:
                reason = "launch_identity_changed"
        if reason is None and selection is not None:
            wanted = (server_id, record.launch_identity, record.observed_revision,
                      record.generation, self.policy_revision)
            got = (selection.server_id, selection.launch_identity, selection.revision,
                   selection.generation, selection.policy_binding)
            if got != wanted:
                reason = "stale_selection"
        if reason is None and require_session:
            reason = self._session_reason(record, connection)
            if reason is None and selection is not None and selection.session_id != connection.session_id:
                reason = "stale_selection_session"
        if reason is None and connection is not None:
            assert record is not None
            if connection.session is None or connection.validated_revision != record.observed_revision:
                reason = "session_not_validated"
        if reason == "policy_revision_changed":
            self.store.invalidate(server_id, actor="managed-client",
                                  reason="active policy revision changed")
        if reason is not None:
            self._refuse(server_id, tool, reason)
        assert record is not None
        return record

    def _refuse(self, server_id: str, tool: str, reason: str, **detail: Any) -> None:
        """Record a local refusal before any transport hand-off, then raise it."""
        self.store.record_event(server_id, "call_blocked", actor="managed-client",
                                detail={"tool": tool, "reason": reason, **detail,
                                        "local_nondispatch": True,
                                        "independent_verification": "verification_unavailable"})
        raise CallBlocked(server_id, tool, reason)

    def _session_reason(self, record, connection):
        if connection is None or not connection.alive or connection.observed_at is None:
            return "session_refresh_required"
        if connection.validated_revision != record.observed_revision:
            return "session_not_validated"
        if connection.dirty_epoch != connection.observed_epoch:
            return "session_dirty"
        if time.monotonic() - connection.observed_at > 2 * self.poll_interval:
            return "session_stale"
        return None

    def _block_reason(self, record: TrustRecord | None, tool: str) -> str | None:
        if record is None:
            return "unobserved"
        if record.state is not TrustState.APPROVED:
            return record.state.value
        if record.approved_revision != record.observed_revision:
            return "revision_not_approved"
        if record.approved_policy_revision != self.policy_revision:
            return "policy_revision_changed"
        if tool not in record.tool_names:
            return "tool_not_in_approved_revision"
        return None

    async def _open_connection(self, server_id: str) -> _Connection:
        """An open session; not necessarily validated for dispatch."""
        connection = self._connections.get(server_id)
        if (connection is not None and connection.alive and
                connection.launch_identity == self.servers[server_id].launch_identity):
            return connection
        if connection is not None:
            await self._disconnect(server_id)
        connection = _Connection(self.servers[server_id], self._timeout,
                                 notification=self.notification,
                                 dispatch=self._dispatch if self.strict else None)
        self._opened.add(connection)
        try:
            await connection.open()
        except (Exception, asyncio.CancelledError) as exc:  # incomplete observation fails closed
            self._record_observation_failure(server_id, exc)
            raise
        self._connections[server_id] = connection
        return connection

    async def _validated_connection(self, server_id: str) -> _Connection:
        """A session whose last successful observation matches the stored revision."""
        connection = await self._open_connection(server_id)
        record = self.store.get(server_id)
        if (connection.validated_revision is None or record is None
                or connection.validated_revision != record.observed_revision):
            await self._observe(server_id, connection)
        return connection

    async def _observe(self, server_id: str, connection: _Connection) -> TrustRecord:
        connection.validated_revision = None
        self._catalog_changed()
        epoch = connection.dirty_epoch
        try:
            tools, raw_tools = await self._list_tools(server_id, connection)
            try:
                revision = server_revision(tools)
            except ValueError as exc:
                raise ObservationError(f"invalid tools/list from {server_id}: {exc}") from exc
            config = self.servers[server_id]
            record = self.store.record_observation(
                server_id, revision, tools,
                provenance={"endpoint": config.endpoint, "transport": "stdio",
                            "server_name": connection.server_name,
                            "server_version": connection.server_version,
                            "protocol_version": connection.protocol_version,
                            "raw_tools_json": json.dumps(raw_tools, sort_keys=True),
                            "origin": config.origin,
                            "launch_identity": config.launch_identity if self.strict else None},
            )
        except (Exception, asyncio.CancelledError) as exc:
            # A failed or incomplete observation never leaves a session eligible.
            if not self.store.faulted:
                self._record_observation_failure(server_id, exc)
            await self._disconnect(server_id)
            raise
        connection.validated_revision = revision
        connection.observed_at = time.monotonic()
        connection.observed_epoch = epoch
        self._catalog_changed()
        if epoch != connection.dirty_epoch and self.notification:
            self.notification(server_id)
        return record

    def _record_observation_failure(self, server_id: str, exc: Exception) -> None:
        """Invalidate approval for every session of this client (REQ-REV-02)."""
        self.store.record_observation_failure(server_id, actor="managed-client",
                                              error=f"{type(exc).__name__}: {exc}")
        self._catalog_changed()

    async def _list_tools(
        self, server_id: str, connection: _Connection
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Reviewed fields per tool, and the complete JSON-serializable tool as received."""
        if connection.session is None:
            raise ObservationError(f"session for {server_id} is closed")
        tools: list[dict[str, Any]] = []
        raw_tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_TOOL_LIST_PAGES):
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            try:
                page = await connection.session.list_tools(params=params)
            except Exception as exc:
                raise ObservationError(f"tools/list failed for {server_id}: {exc!r}") from exc
            for tool in page.tools:
                if len(tools) >= 10000 or len(json.dumps(tool.model_dump(mode="json"))) > 1_000_000:
                    raise ObservationError("metadata limits exceeded")
                tools.append(tool_metadata(tool.model_dump(by_alias=True)))
                raw_tools.append(tool.model_dump(mode="json", by_alias=True, exclude_none=True))
            cursor = page.nextCursor
            if not cursor:
                return tools, raw_tools
        raise ObservationError(f"tools/list for {server_id} exceeded {MAX_TOOL_LIST_PAGES} pages")

    async def _disconnect(self, server_id: str) -> None:
        connection = self._connections.pop(server_id, None)
        if connection is not None:
            self._catalog_changed()
            await connection.close()

    async def _disconnect_owned(self, server_id: str) -> None:
        """A guarded quarantine closes every strict session owned by this store."""
        clients = tuple(self.store._owned_clients) if self.strict else (self,)
        await asyncio.gather(*(client._disconnect(server_id) for client in clients))
        self._catalog_changed()

    def _catalog_changed(self) -> None:
        callback = getattr(self.store, "_catalog_changed", None)
        if callback is not None:
            callback()


def trust_db_path(state_dir: Path) -> Path:
    return Path(state_dir) / "trust.sqlite3"


from contextvars import ContextVar
_dispatch_context = ContextVar("protected_call", default=None)


class _DispatchStream:
    def __init__(self, stream, connection):
        self.stream, self.connection = stream, connection

    def __getattr__(self, name):
        return getattr(self.stream, name)

    async def __aenter__(self):
        await self.stream.__aenter__()
        return self

    async def __aexit__(self, *args):
        return await self.stream.__aexit__(*args)

    async def send(self, message):
        if getattr(message.message.root, "method", None) == "tools/call":
            await self.connection.dispatch(self.connection, message, self.stream)
            return
        # Protocol and metadata traffic is bounded too: a server that stops draining its
        # input fails that operation (an observation failure for tools/list) instead of
        # leaving the caller, and any lock it holds, waiting indefinitely (REQ-REV-02).
        with anyio.fail_after(self.connection.timeout.total_seconds()):
            await self.stream.send(message)


async def _cancel_and_join(task: asyncio.Future) -> None:
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


def _transport_state(stream) -> str:
    """'ready' when a tools/call can be handed to the stdio writer now, without waiting;
    'busy' while the writer is still writing; 'closed' once it has stopped.

    The MCP stdio writer takes messages from a zero-capacity stream: `send_nowait`
    succeeds only while the writer is idle and waiting for the next message.
    """
    statistics = stream.statistics()
    if statistics.open_receive_streams == 0:
        return "closed"
    if (statistics.tasks_waiting_receive > 0
            or statistics.current_buffer_used < statistics.max_buffer_size):
        return "ready"
    return "busy"


@dataclass(frozen=True)
class SelectionToken:
    server_id: str
    launch_identity: str | None
    revision: str
    generation: int
    policy_binding: str
    session_id: str


@dataclass(frozen=True)
class CatalogEntry:
    server_id: str
    definition: Mapping[str, Any]
    selection: SelectionToken

    def as_dict(self):
        from dataclasses import asdict
        return {"server_id": self.server_id, "definition": _thaw(self.definition),
                "selection": asdict(self.selection)}


def _freeze(value):
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def _thaw(value):
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    return value
