"""Public, explicitly owned local-stdio trust monitor (REQ-LIB-01)."""
from __future__ import annotations
import asyncio
import inspect
import time
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast, overload
from mcp.types import CallToolResult
from ._lifecycle import _CancellationTracker
from .config import ConfigurationError, MonitorConfig
from .managed_client import CatalogEntry, ManagedClient, SelectionToken, _Connection, trust_db_path
from .monitor import MonitorLoop
from .ownership import StateOwner
from .policy import load_policy, DetectorBinding, PolicyRef
from .trust_store import TrustRecord, TrustStore, TrustError, StorageFaultError, TrustState


# Written by the separate historical demo CLI into its own state directories.
HISTORICAL_DEMO_MARKER = 'historical-demo-state'


class ShutdownIncompleteError(TrustError):
    """`aclose()` could not complete a clean shutdown (REQ-MON-03, REQ-ENF-07).

    `ownership_released` is False while an owned transport could not be confirmed
    closed: the state directory stays owned (and marked unclean) until a later
    `aclose()` confirms it, or this process exits. It is True when every transport was
    closed and ownership released, but cancelled work outlived `shutdown_timeout`; the
    unclean marker is then retained, so the next owner runs recovery.
    """

    def __init__(self, message: str, *, ownership_released: bool) -> None:
        super().__init__(message)
        self.ownership_released = ownership_released


class AssessmentNotReady(TrustError):
    """No current, complete session observation exists to assess yet.

    Raised before any detector or model work; it is not a failed assessment.
    """


class SessionHealth(TypedDict):
    session_id: str | None
    last_observed_monotonic: float | None
    freshness: str
    connected: bool


class MonitorHealth(TypedDict):
    status: Literal['failed', 'stopped', 'degraded', 'running']
    storage_faulted: bool
    servers: dict[str, SessionHealth]
    catalog_revision: int
    errors: dict[str, str]
    detector: Literal['enabled', 'disabled']
    reviewer: Literal['enabled', 'disabled']

@dataclass(frozen=True)
class ReviewResult:
    server_id: str
    revision: str | None
    generation: int
    detector: str
    assessment: str
    outcome: str
    detail: object | None = None

@dataclass(frozen=True)
class AssessmentContext:
    server_id: str
    revision: str
    generation: int
    policy_binding: str
    launch_identity: str
    session_id: str
    dirty_epoch: int

class TrustMonitor:
    """Owner of one state directory for one lifetime.

    An object that was opened is single-use: after `aclose()` create a new instance to
    own the directory again. Per-lifetime ownership, fault and scheduling state is never
    silently reused (REQ-ENF-07, REQ-MON-03).
    """

    def __init__(self, config: MonitorConfig) -> None:
        self.config = config
        self._store: TrustStore | None = None
        self._client: ManagedClient | None = None
        self._policy: PolicyRef | None = None
        self._opened = False
        self._reset_lifetime()

    def _reset_lifetime(self) -> None:
        """Fresh per-lifetime ownership, fault, session and scheduling state.

        Runs before every open attempt, so retrying an object whose open failed (for
        example on a storage fault during recovery) never inherits a stale fault latch,
        fault-shutdown task or owner state (REQ-ENF-07).
        """
        self._owner = StateOwner(self.config.state_dir)
        self._policy_path = self.config.policy_path
        self._detector = self.config.detector
        self._sessions: list[ManagedClient] = []
        self._cancellation = _CancellationTracker()
        self._loop = MonitorLoop(self)
        self._catalog_revision = 0
        self._catalog_event = asyncio.Event()
        self._expired_sessions: set[tuple[str, float]] = set()
        self._fault_shutdown: asyncio.Task[None] | None = None
        self._closing = False
        self._review_locks: dict[str, asyncio.Lock] = {}
        self._active_reviews: set[asyncio.Task[Any] | None] = set()
        self._close_task: asyncio.Future[None] | None = None
        self._release_pending = False
        # Cancelled work still running after this lifetime's shutdown; kept referenced.
        self._unfinished: set[asyncio.Future[Any]] = set()

    @property
    def store(self) -> TrustStore:
        if self._store is None:
            raise TrustError('monitor is not open')
        return self._store

    @property
    def client(self) -> ManagedClient:
        if self._client is None:
            raise TrustError('monitor is not open')
        return self._client

    @property
    def policy(self) -> PolicyRef:
        if self._policy is None:
            raise TrustError('monitor is not open')
        return self._policy

    @property
    def policy_path(self) -> Path:
        return self._policy_path

    @property
    def detector_binding(self) -> DetectorBinding | None:
        return self._detector

    async def __aenter__(self) -> TrustMonitor:
        if self._store is not None:
            raise TrustError('monitor is already open')
        if self._opened:
            raise TrustError('TrustMonitor objects are single-use; create a new instance '
                             'to own the state directory again')
        if (self.config.state_dir / HISTORICAL_DEMO_MARKER).exists():
            raise ConfigurationError('state directory belongs to the historical demo CLI; '
                                     'use a separate library state directory')
        self._reset_lifetime()
        candidate = load_policy(self.config.policy_path)
        if self._detector is not None:
            self._detector.validate(self.config.policy_path)
        self._owner.acquire()
        try:
            self._store = TrustStore(trust_db_path(self.config.state_dir), self.config.client_id,
                                     strict_integrity=True)
            self._store.on_fault = self._storage_fault
            cast(Any, self._store)._catalog_changed = self._catalog_changed
            if self._owner.recovery_required:
                self._store.recover_owner()
            self._policy = candidate
            self._store.invalidate_policy(candidate.binding)
            for sid, profile in self.config.servers.items():
                self._store.ensure_identity(sid, profile.launch_identity)
            self._client = self.new_session()
            self._opened = True
            return self
        except BaseException:
            if self._store is not None:
                self._store.close()
                self._store = None
            self._owner.release(clean=False)
            raise

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    def _storage_fault(self, exc):
        self._owner.faulted = True
        self._catalog_changed()
        if self._fault_shutdown is None:
            # Bound to the lifetime that faulted, never to a later retried open.
            self._fault_shutdown = asyncio.create_task(self._shutdown_sessions(
                tuple(self._sessions), self._loop, tuple(self._active_reviews)))

    def _stop_work(self, sessions=None, reviews=None, loop=None) -> list[asyncio.Task[Any]]:
        """Refuse new work and later monitor starts, stop scheduling, cancel monitor
        tasks, reviews and observations, and stop in-flight calls waiting (they report
        their own outcome). Returns the work to join; nothing here waits (REQ-MON-03)."""
        sessions = self._sessions if sessions is None else sessions
        reviews = self._active_reviews if reviews is None else reviews
        loop = self._loop if loop is None else loop
        # Each task is cancelled once: a repeated cancellation would interrupt cleanup
        # that is honoring the first. A second call (a fault shutdown, then aclose) and
        # monitor tasks cancelled by an earlier stop are only collected for the join.
        work: list[asyncio.Task[Any]] = loop.halt(close=True)
        current = asyncio.current_task()
        for task in reviews:
            if task is None or task is current or task.done() or task in work:
                continue
            self._cancellation.cancel(task)
            work.append(task)
        for session in sessions:
            work.extend(session._begin_close())
        return work

    async def _close_transports(self, sessions=None) -> None:
        sessions = self._sessions if sessions is None else sessions
        await asyncio.gather(*(session._close_transports() for session in sessions),
                             return_exceptions=True)

    async def _shutdown_sessions(self, sessions, loop, reviews):
        """Fault path for one lifetime: stop its work and close its owned transports.

        Transports are closed without waiting for cancelled work, so cleanup that
        ignores cancellation cannot keep a server process alive (REQ-ENF-07). The work
        is joined, with a bound, by aclose(); ownership is kept until then.
        """
        self._stop_work(sessions, reviews, loop)
        await self._close_transports(sessions)

    def _transports_finished(self) -> bool:
        return all(session.transports_finished() for session in self._sessions)

    async def aclose(self) -> None:
        """Close this owner lifetime (REQ-MON-03, REQ-LIB-04, REQ-ENF-07).

        Safe to call repeatedly and concurrently: every caller waits for the same
        shutdown and sees its outcome. Monitoring stops and later starts are refused
        first. Owned transports are closed, and their subprocesses reaped, before any
        cancelled work is awaited, so application or review cleanup that ignores
        cancellation cannot keep a server alive. That work, including every monitor task,
        is awaited for at most `shutdown_timeout`; ownership is released only after every
        owned transport task has finished. Otherwise `ShutdownIncompleteError` reports
        what remains, and the unclean marker is kept.
        """
        task = self._close_task
        if task is None or (task.done() and self._release_pending):
            if self._store is None and not self._release_pending:
                return
            task = self._close_task = asyncio.ensure_future(
                self._finish_release() if self._release_pending else self._close())
        elif task.done():
            return  # Already closed; the callers of that shutdown received its outcome.
        await asyncio.shield(task)

    async def _close(self) -> None:
        self._closing = True
        store = self.store
        stopped = False  # All cancelled work finished within shutdown_timeout.
        try:
            work = self._stop_work()
            # Close owned transports before waiting for cancelled work, so application
            # or review cleanup that ignores cancellation cannot keep a subprocess alive.
            await self._close_transports()
            pending: set[asyncio.Future[Any]] = set(work) | self._loop.owned_tasks()
            if self._fault_shutdown is not None:
                pending.add(self._fault_shutdown)
            pending = {task for task in pending if not task.done()}
            if pending:
                # Bounded without depending on cancellation being acknowledged.
                await asyncio.wait(pending, timeout=self.config.shutdown_timeout)
            await self._close_transports()  # Anything reopened while work unwound.
            # Every task the monitor ever started is tracked, so none is missed here.
            self._unfinished = ({task for task in pending if not task.done()}
                                | self._loop.owned_tasks())
            for task in self._unfinished:
                task.add_done_callback(self._unfinished.discard)
            stopped = not self._unfinished
        finally:
            # A latched storage fault keeps the unclean marker; it was already reported
            # to callers as StorageFaultError and is not a shutdown failure.
            clean = stopped and not store.faulted
            store.on_fault = None  # Late use of this closed store is not a new fault.
            store.close()
            self._store = self._client = None
            self._release_pending = True
        await self._finish_release(clean=clean)
        if not stopped:
            raise ShutdownIncompleteError(
                'cancelled work outlived shutdown_timeout; owned transports were closed and '
                'ownership released, and the unclean marker was retained',
                ownership_released=True)

    async def _finish_release(self, clean: bool = False) -> None:
        """Release ownership once every owned transport task has finished."""
        if not self._transports_finished():
            await self._close_transports()
        if not self._transports_finished():
            raise ShutdownIncompleteError(
                'an owned transport could not be confirmed closed; ownership is retained',
                ownership_released=False)
        self._sessions.clear()
        self._owner.release(clean=clean)
        self._release_pending = False

    def new_session(self) -> ManagedClient:
        """Independent transport sessions share this owner's store and server locks."""
        if self._closing:
            raise TrustError('monitor is closing')
        self.store.check_health()
        result = ManagedClient(self.store, self.config.servers, policy_revision=self.policy.binding,
                               strict=True, poll_interval=self.config.poll_interval,
                               timeout_seconds=self.config.timeout_seconds,
                               notification=self._loop.notify,
                               _cancellation=self._cancellation)
        self._sessions.append(result)
        return result

    @overload
    def status(self, server_id: None = None) -> tuple[TrustRecord, ...]: ...

    @overload
    def status(self, server_id: str) -> TrustRecord | tuple[TrustRecord, ...] | None: ...

    def status(self, server_id: str | None = None) -> TrustRecord | tuple[TrustRecord, ...] | None:
        """Return one server's record; omitted or empty IDs select all records."""
        self.store.check_health()
        return self.store.get(server_id) if server_id else tuple(self.store.records())

    def events(self, server_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.events(server_id)

    def catalog(self, server_id: str | None = None) -> tuple[CatalogEntry, ...]:
        return self.client.catalog(server_id)

    def assessment_context(self, server_id: str) -> AssessmentContext:
        """Capture the observed context before awaiting optional review I/O."""
        record = cast(TrustRecord | None, self.status(server_id))
        connection = self.client._connections.get(server_id)
        if record is None or self.client._session_reason(record, connection) is not None:
            raise AssessmentNotReady('assessment requires a current complete session observation')
        # The session check above establishes complete revision/identity metadata.
        connection = cast(_Connection, connection)
        return AssessmentContext(server_id, cast(str, record.observed_revision), record.generation,
                                 self.policy.binding, cast(str, record.launch_identity),
                                 connection.session_id, connection.dirty_epoch)

    def assessment_stale_reason(self, context: AssessmentContext) -> str | None:
        """Use inside the guarded completion transaction; no external I/O."""
        record = cast(TrustRecord | None, self.status(context.server_id))
        if record is None or (record.observed_revision, record.generation,
                self.policy.binding, record.launch_identity) != (context.revision,
                context.generation, context.policy_binding, context.launch_identity):
            return 'assessment trust context changed'
        connection = self.client._connections.get(context.server_id)
        reason = self.client._session_reason(record, connection)
        if reason is not None:
            return 'assessment ' + reason
        connection = cast(_Connection, connection)
        if connection.session_id != context.session_id or connection.dirty_epoch != context.dirty_epoch:
            return 'assessment session or notification epoch changed'
        return None

    @property
    def catalog_revision(self) -> int:
        """Coalesced catalog change sequence, local to this owner lifetime."""
        return self._catalog_revision

    def _catalog_changed(self):
        self._catalog_revision += 1
        event, self._catalog_event = self._catalog_event, asyncio.Event()
        event.set()

    async def wait_for_catalog_change(self, after_revision: int, timeout: float | None = None) -> int:
        """Wake on change or session expiry; callers must fetch a fresh catalog.

        Notifications are hints and may coalesce. The returned sequence never grants
        dispatch authority. A timeout raises asyncio.TimeoutError.
        """
        async def wait():
            while self._catalog_revision <= after_revision:
                self.store.check_health()
                event = self._catalog_event
                observations = [(connection.session_id, connection.observed_at)
                    for session in self._sessions for connection in session._connections.values()
                    if connection.alive and connection.observed_at is not None]
                newly_expired = {observation for observation in observations
                    if observation[1] + 2 * self.config.poll_interval <= time.monotonic()
                    and observation not in self._expired_sessions}
                if newly_expired:
                    self._expired_sessions.update(newly_expired)
                    self._catalog_changed()
                    continue
                self._expired_sessions.intersection_update(observations)
                expiries = [observed_at + 2 * self.config.poll_interval for _,observed_at in observations]
                future = [value for value in expiries if value > time.monotonic()]
                if not future:
                    await event.wait()
                else:
                    try:
                        await asyncio.wait_for(event.wait(), max(0, min(future) - time.monotonic()))
                    except asyncio.TimeoutError:
                        self._catalog_changed()
            return self._catalog_revision
        return await asyncio.wait_for(wait(), timeout) if timeout is not None else await wait()

    def health(self) -> MonitorHealth:
        servers: dict[str, SessionHealth] = {}
        for sid in self.config.servers:
            connection = self.client._connections.get(sid)
            record = None if self.store.faulted else self.store.get(sid)
            reason = self.client._session_reason(record, connection) if record is not None else 'unobserved'
            servers[sid] = {'session_id': connection.session_id if connection else None,
                            'last_observed_monotonic': connection.observed_at if connection else None,
                            'freshness': reason or 'fresh',
                            'connected': bool(connection and connection.alive)}
        return {'status': 'failed' if self.store.faulted else 'stopped' if not self._loop.running else
                'degraded' if self._loop.errors else 'running',
                'storage_faulted': self.store.faulted, 'servers': servers,
                'catalog_revision': self._catalog_revision, 'errors': dict(self._loop.errors),
                'detector': 'enabled' if self._detector else 'disabled',
                'reviewer': 'enabled' if self.config.reviewer else 'disabled'}

    async def observe(self, server_id: str) -> TrustRecord:
        return await self.client.observe(server_id)

    async def approve(self, server_id: str, *, revision: str,
                      expected_generation: int | None, actor: str) -> TrustRecord:
        return await self.client.approve(server_id, revision=revision,
                                        expected_generation=expected_generation, actor=actor)

    async def restore(self, server_id: str, *, revision: str,
                      expected_generation: int | None, actor: str) -> TrustRecord:
        return await self.client.approve(server_id, revision=revision,
                                        expected_generation=expected_generation, actor=actor, restore=True)

    async def quarantine(self, server_id: str, *, actor: str, reason: str) -> TrustRecord:
        return await self.client.quarantine(server_id, actor=actor, reason=reason)

    async def call_tool(self, server_id: str, tool: str, arguments: dict[str, Any] | None = None,
                        *, selection: SelectionToken | None = None) -> CallToolResult:
        return await self.client.call_tool(server_id, tool, arguments, selection=selection)

    async def observe_and_call(self, server_id: str, tool: str,
                               arguments: dict[str, Any] | None = None,
                               *, selection: SelectionToken | None = None) -> CallToolResult:
        return await self.client.observe_and_call(server_id, tool, arguments, selection=selection)

    async def reload_policy(self, policy_path: str | Path,
                            detector: DetectorBinding | None = None) -> PolicyRef:
        path = Path(policy_path).resolve()
        candidate = load_policy(path)
        candidate_detector = self._detector if detector is None else detector
        if candidate_detector is not None:
            candidate_detector.validate(path)
        self._activate_policy(candidate, candidate_detector, path)
        self._catalog_changed()
        self._loop.last_reviewed.clear()
        self._loop.reset_review_retries()
        for sid in self.config.servers:
            self._loop.notify(sid)
        return candidate

    def _activate_policy(self, candidate: PolicyRef, detector: DetectorBinding | None,
                         path: Path) -> None:
        """Invalidate approvals and switch the active policy in one synchronous step.

        This is the synchronization boundary shared with the final dispatch gate, which
        authorizes against the active policy and hands the request to the transport with
        no await in between. Both run on the owner's event loop, so every call is either
        enqueued before this invalidation commits or authorized against the new policy
        (REQ-ENF-05, REQ-TRU-03). No server lock is held: waiting here for one server's
        observation would delay quarantine and dispatch on every other server.
        """
        self.store.invalidate_policy(candidate.binding)
        self._policy, self._detector = candidate, detector
        self._policy_path = path
        for session in self._sessions:
            session.policy_revision = candidate.binding

    def reset_review_retries(self, server_id: str | None = None) -> None:
        """Explicitly re-arm automatic assessment after its retry budget was used up.

        The monitor bounds automatic assessment of an unchanged failed context
        (`review_max_attempts`, REQ-MON-02). A changed revision, launch identity or policy
        resets the budget by itself; this is the operator's manual reset. It never
        approves anything; `review_once` remains available regardless of the budget.
        """
        if server_id is not None and server_id not in self.config.servers:
            raise KeyError(f'{server_id} is not configured for this monitor')
        self._loop.reset_review_retries(server_id)
        for sid in ([server_id] if server_id is not None else self.config.servers):
            self._loop.notify(sid)

    async def review_once(self, server_id: str, *, observe: bool = True) -> ReviewResult:
        if self._closing:
            raise TrustError('monitor is closing')
        task = asyncio.current_task()
        self._active_reviews.add(task)
        self._cancellation.register(task)
        try:
            return await self._review_once(server_id, observe=observe)
        finally:
            self._active_reviews.discard(task)
            self._cancellation.release(task)

    async def _review_once(self, server_id, *, observe=True):
        lock = self._review_locks.setdefault(server_id, asyncio.Lock())
        async with lock:
            record = await self.observe(server_id) if observe else self.status(server_id)
            if record is None:
                raise TrustError('server has not been observed')
            detector_status, assessment_status = 'disabled', 'disabled'
            observed_context = self.assessment_context(server_id)
            policy = self.policy
            path = getattr(self, '_policy_path', self.config.policy_path)
            detail = None
            if self._detector is not None:
                detector = self._detector
                def detector_context_guard():
                    stale = self.assessment_stale_reason(observed_context)
                    if stale:
                        return stale
                    if detector is not self._detector:
                        return 'detector configuration changed'
                    try:
                        detector.validate(self.policy_path)
                    except Exception:
                        return 'detector policy or rules changed'
                    return None
                try:
                    result = await self._scan(detector, record.observed_tools, path)
                    detector_status = 'matched' if result.matches else 'clean'
                    detail = result.as_dict()
                    if result.matches:
                        context = policy.binding + '|rules=' + detector.rules_digest
                        applied = await self.client.apply_hard_deny(server_id,
                            revision=record.observed_revision, generation=record.generation,
                            policy_context=context,
                            active_policy_context=lambda: self.policy.binding + '|rules=' + self._detector.rules_digest,
                            detection=detail,
                            context_guard=detector_context_guard)
                        if applied.status == 'stale':
                            return ReviewResult(server_id, record.observed_revision, record.generation,
                                                'stale', 'disabled', 'stale', detail)
                        return ReviewResult(server_id, record.observed_revision, record.generation,
                                            'matched', 'skipped_hard_deny', 'quarantined', detail)
                    else:
                        check = await self.client.record_assessment_if_current(server_id,
                            revision=record.observed_revision, generation=record.generation,
                            policy_context=policy.binding + '|rules=' + detector.rules_digest,
                            active_policy_context=lambda: self.policy.binding + '|rules=' + self._detector.rules_digest,
                            actor='hard-deny-detector', detail={'stage': 'detector', **detail},
                            context_guard=detector_context_guard)
                        if check.status == 'stale':
                            return ReviewResult(server_id, record.observed_revision, record.generation,
                                                'stale', 'disabled', 'stale', detail)
                except StorageFaultError:
                    raise
                except Exception as exc:
                    self.store.record_event(server_id, 'detector_failed', actor='hard-deny-detector',
                                            detail={'error': type(exc).__name__})
                    return ReviewResult(server_id, record.observed_revision, record.generation,
                                        'failed', 'disabled', 'failed')
            if self.config.reviewer is not None:
                reviewer = self.config.reviewer
                try:
                    detail = await reviewer(self, server_id)
                    assessment_status = getattr(detail, 'outcome', 'recorded')
                    if assessment_status == 'stale':
                        return ReviewResult(server_id, record.observed_revision, record.generation,
                                            detector_status, 'stale', 'stale', detail)
                except StorageFaultError:
                    raise
                except Exception as exc:
                    assessment_status = 'failed'
                    self.store.record_event(server_id, 'model_assessment_failed', actor='model-reviewer',
                                            detail={'stage': 'adapter', 'error': type(exc).__name__})
            current = self.status(server_id)
            return ReviewResult(server_id, record.observed_revision, record.generation,
                                detector_status, assessment_status, current.state.value, detail)

    async def start_monitor(self) -> None:
        """Start background observation and review (REQ-MON-01/03).

        Refused with `TrustError` once the owner began closing, and with
        `StorageFaultError` after a storage fault. Starting a running monitor is a no-op.
        """
        if self._closing:
            raise TrustError('monitor is closing')
        self.store.check_health()
        await self._loop.start()  # Serialized with stop; it re-checks both conditions.

    async def _scan(self, detector, tools, path):
        if not isinstance(detector, DetectorBinding):
            return await asyncio.to_thread(detector.scan, tools, path)
        cancel = threading.Event()
        worker = asyncio.create_task(asyncio.to_thread(detector.scan, tools, path,
            cancel_event=cancel, timeout_seconds=self.config.timeout_seconds))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            cancel.set()
            await asyncio.gather(worker, return_exceptions=True)
            raise

    async def stop_monitor(self) -> None:
        """Stop background work; `start_monitor()` may start it again (REQ-MON-03).

        Scheduling stops at once. Cancelled tasks are awaited for at most
        `shutdown_timeout`, without depending on them acknowledging cancellation;
        `asyncio.TimeoutError` reports any still running. They stay tracked, and
        `aclose()` joins them again and reports an incomplete shutdown if they remain.
        """
        await self._loop.stop()
