"""Bounded coalescing observation/review scheduler; notifications never await work.

Observations are coalesced per server across the queue and the workers: a server is
either queued once, or being observed by exactly one worker with at most one follow-up
observation requested by notifications that arrived meanwhile (REQ-MON-01). A slow or
continuously notifying server therefore occupies at most one worker and cannot starve
unrelated servers (REQ-ENF-04).

Automatic assessment of an unchanged context (revision, launch identity and the
activated policy/detector decision binding) that failed or went stale is retried with
exponential backoff from the poll interval, at most `review_max_attempts` times. A
changed context or an explicit `reset_review_retries` re-arms it. An assessment whose
context changed while it ran, or that was still running when the budget was reset
(every policy or detector reload resets it), is not an attempt of the current
budget: it uses none of it, and the current context is scheduled promptly
(REQ-DEC-06). Each such skip needs a context change or a reset, so retries stay
bounded. Metadata observation is never suppressed (REQ-MON-02,
REQ-ENF-08).

Lifecycle (REQ-MON-03). `start` and `stop` are serialized. Every task the scheduler
creates is tracked until it has finished, whichever start created it, so a stop or a
later start never loses a reference to work that is still unwinding. `halt` stops
scheduling and cancels the current tasks synchronously, without waiting; with
`close=True`, used by owner shutdown and storage faults, it also refuses every later
start. Joins are
bounded with `asyncio.wait`, so they never depend on a cancelled task acknowledging its
cancellation: a task that ignores cancellation is reported as still running, not waited
for indefinitely.
"""
from __future__ import annotations
import asyncio
import inspect
import time
from collections import deque
from dataclasses import dataclass

from .trust_store import TrustError


@dataclass
class _ReviewBudget:
    key: tuple
    failures: int = 0
    next_attempt: float = 0.0
    exhausted_recorded: bool = False


class MonitorLoop:
    def __init__(self, owner):
        self.owner = owner
        self.pending: set[str] = set()
        self.active: set[str] = set()
        self.rerun: set[str] = set()
        self.queue = deque()
        self.wake = asyncio.Event()
        # Tasks of the current start; `review_tasks` deduplicates assessments per server.
        self.tasks = []
        self.running = False
        # Every task this loop created that has not finished yet, from any start.
        self._owned: set[asyncio.Task] = set()
        # A task belongs to one start; tasks of an earlier start never resume scheduling.
        self._generation = 0
        self._lifecycle = asyncio.Lock()
        self.closed = False  # set by owner shutdown or a storage fault; refuses start()
        self.errors: dict[str, str] = {}
        self.last_reviewed = {}
        self.review_tasks = {}
        self.review_budgets: dict[str, _ReviewBudget] = {}
        # Advanced by every budget reset; an attempt that started before it is not charged.
        self.review_epochs: dict[str, int] = {}
        self._assessment_slots = asyncio.Semaphore(owner.config.max_concurrency)

    def notify(self, server_id):
        # Bounded by configured server count; a flood adds no unbounded tasks/queue.
        if server_id in self.owner.config.servers:
            if server_id in self.active:
                self.rerun.add(server_id)  # One follow-up after the active observation.
            elif server_id not in self.pending:
                self.pending.add(server_id)
                self.queue.append(server_id)
                self.wake.set()
        self.owner._catalog_changed()

    def reset_review_retries(self, server_id=None):
        targets = list(self.owner.config.servers) if server_id is None else [server_id]
        for sid in targets:
            self.review_budgets.pop(sid, None)
            self.errors.pop('@review:' + sid, None)
            self.review_epochs[sid] = self.review_epochs.get(sid, 0) + 1

    def _review_key(self, record):
        # The decision binding, not the policy alone: a detector reload under an unchanged
        # policy is a new context with its own budget (REQ-MON-02, REQ-DEC-06).
        return (record.observed_revision, record.launch_identity, self.owner.decision_binding)

    def _superseded(self, sid, key, epoch):
        """The attempt's context changed, or its budget was reset, while it ran."""
        current = self.owner.status(sid)
        return (self.review_epochs.get(sid, 0) != epoch
                or (current is not None and self._review_key(current) != key))

    def _charge(self, sid, key, epoch, outcome):
        """Count a failed or stale attempt, unless it was superseded while it ran; the
        finally block of `_assess` then reschedules the current context."""
        if not self._superseded(sid, key, epoch):
            self._review_failed(sid, key, outcome)

    def _review_due(self, sid, key):
        budget = self.review_budgets.get(sid)
        if budget is None or budget.key != key:
            self.review_budgets.pop(sid, None)  # A changed context gets a fresh budget.
            return True
        if budget.failures >= self.owner.config.review_max_attempts:
            return False
        return time.monotonic() >= budget.next_attempt

    def _review_failed(self, sid, key, outcome):
        budget = self.review_budgets.get(sid)
        if budget is None or budget.key != key:
            budget = self.review_budgets[sid] = _ReviewBudget(key)
        budget.failures += 1
        limit = self.owner.config.review_max_attempts
        budget.next_attempt = time.monotonic() + self.owner.config.poll_interval * 2 ** (budget.failures - 1)
        if budget.failures < limit:
            self.errors['@review:' + sid] = outcome
            return
        self.errors['@review:' + sid] = 'retries_exhausted'
        if not budget.exhausted_recorded and not self.owner.store.faulted:
            budget.exhausted_recorded = True
            self.owner.store.record_event(sid, 'assessment_retries_exhausted', actor='monitor',
                detail={'attempts': budget.failures, 'last_outcome': outcome,
                        'revision': key[0], 'policy_binding': key[2],
                        'reset': 'context change or reset_review_retries'})

    def _current(self, generation):
        return self.running and generation == self._generation

    def _owner_faulted(self):
        store = self.owner._store
        return store is None or store.faulted  # a closed owner counts as unavailable

    def _spawn(self, coro):
        task = asyncio.create_task(coro)
        self._owned.add(task)
        self.owner._cancellation.register(task)
        task.add_done_callback(self._finished)
        return task

    def _finished(self, task):
        self._owned.discard(task)
        self.owner._cancellation.release(task)
        if not task.cancelled():
            task.exception()  # outcomes are reported through `errors`; never log it again

    def owned_tasks(self) -> set[asyncio.Task]:
        """Every unfinished task this loop created, including any still unwinding after
        an earlier stop; the caller's own task is excluded."""
        current = asyncio.current_task()
        return {task for task in self._owned if task is not current and not task.done()}

    async def start(self):
        async with self._lifecycle:
            if self.closed:
                raise TrustError('monitor is closing')
            self.owner.store.check_health()
            if self.running:
                return
            self._generation += 1
            generation = self._generation
            self.running = True
            self.tasks = [self._spawn(self._worker(generation))
                          for _ in range(self.owner.config.max_concurrency)]
            self.tasks.append(self._spawn(self._poll(generation)))
            if self.owner.config.history_sink is not None:
                self.tasks.append(self._spawn(self._deliver(generation)))
            for sid in self.owner.config.servers:
                self.notify(sid)

    def halt(self, *, close: bool = False) -> list[asyncio.Task]:
        """Stop scheduling and cancel this start's tasks now, without waiting.

        Returns the work to join. With `close`, every later `start` is refused.
        Only the tasks of the current start are detached, so a later start keeps its own.
        """
        if close:
            self.closed = True
        self.running = False
        self._generation += 1
        current = asyncio.current_task()
        snapshot = [task for task in (*self.tasks, *self.review_tasks.values())
                    if task is not current and not task.done()]
        self.tasks = []
        self.review_tasks = {}
        self.pending.clear()
        self.active.clear()
        self.rerun.clear()
        self.queue.clear()
        for task in snapshot:
            self.owner._cancellation.cancel(task)
        return snapshot

    async def join(self, timeout: float) -> set[asyncio.Task]:
        """Wait at most `timeout` for every owned task; return those still running."""
        tasks = self.owned_tasks()
        if not tasks:
            return set()
        _, pending = await asyncio.wait(tasks, timeout=timeout)
        return {task for task in pending if not task.done()}

    async def stop(self):
        """Stop scheduling. Waits at most `shutdown_timeout` for cancelled tasks.

        Raises `asyncio.TimeoutError` if any task is still unwinding then; it remains
        tracked, and owner shutdown joins and reports it.
        """
        async with self._lifecycle:
            self.halt()
            remaining = await self.join(self.owner.config.shutdown_timeout)
        if remaining:
            raise asyncio.TimeoutError(
                f'{len(remaining)} monitor task(s) did not finish within shutdown_timeout')

    async def _poll(self, generation):
        while self._current(generation):
            await asyncio.sleep(self.owner.config.poll_interval)
            if not self._current(generation):
                return
            for sid in self.owner.config.servers:
                self.notify(sid)

    async def _worker(self, generation):
        while self._current(generation):
            await self.wake.wait()
            if not self._current(generation):
                return
            if not self.queue:
                self.wake.clear()
                continue
            sid = self.queue.popleft()
            self.pending.discard(sid)
            if not self.queue:
                self.wake.clear()
            self.active.add(sid)
            try:
                record = await self.owner.observe(sid)
                # A refresh on the primary transport cannot freshen other transports.
                # Observe each already-live session independently; do not implicitly
                # launch extra sessions created for manual use.
                for session in tuple(self.owner._sessions):
                    if session is not self.owner.client and session.is_connected(sid):
                        record = await session.observe(sid)
                key = self._review_key(record)
                if (self._current(generation) and self.last_reviewed.get(sid) != key
                        and sid not in self.review_tasks and self._review_due(sid, key)):
                    self.review_tasks[sid] = self._spawn(self._assess(sid, generation))
                self.errors.pop(sid, None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.errors[sid] = type(exc).__name__
                if self._owner_faulted():
                    if generation == self._generation:
                        self.running = False
                    return
            finally:
                # A stopped start's worker leaves the scheduling state of a later start alone.
                if generation == self._generation:
                    self.active.discard(sid)
                    if sid in self.rerun:
                        self.rerun.discard(sid)
                        if self.running:
                            self.notify(sid)

    async def _assess(self, sid, generation):
        from .sdk import AssessmentNotReady
        key = epoch = None
        try:
            async with self._assessment_slots:
                # Observation work has separate workers and remains live throughout I/O.
                key = self._review_key(self.owner.status(sid))
                epoch = self.review_epochs.get(sid, 0)
                try:
                    # A session that is mid-refresh is not ready; that is not an attempt
                    # and uses no retry budget. The next completed observation reschedules.
                    self.owner.assessment_context(sid)
                    result = await self.owner.review_once(sid, observe=False)
                except AssessmentNotReady:
                    self.errors['@review:' + sid] = 'awaiting_fresh_observation'
                    key = None
                    return
                if result.outcome != 'stale' and result.detector != 'failed' and result.assessment not in ('failed', 'stale'):
                    self.last_reviewed[sid] = key
                    self.review_budgets.pop(sid, None)
                    self.errors.pop('@review:' + sid, None)
                else:
                    self._charge(sid, key, epoch, result.outcome)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if key is not None and not self._owner_faulted():
                self._charge(sid, key, epoch, type(exc).__name__)
            else:
                self.errors['@review:' + sid] = type(exc).__name__
        finally:
            if self.review_tasks.get(sid) is asyncio.current_task():
                del self.review_tasks[sid]
            if self._current(generation) and not self._owner_faulted() and key is not None:
                # Polling schedules bounded retries. A changed context, or a budget reset
                # while this attempt ran, refreshes promptly.
                if self.owner.status(sid) and self._superseded(sid, key, epoch):
                    self.notify(sid)

    async def _deliver(self, generation):
        while self._current(generation):
            try:
                sink = self.owner.config.history_sink
                if inspect.iscoroutinefunction(sink) or inspect.iscoroutinefunction(getattr(sink, '__call__', None)):
                    await sink(self.owner.store)
                else:
                    # A synchronous sink must not own the event loop or SQLite connection.
                    batch = self.owner.store.pending_outbox()
                    if batch:
                        await asyncio.to_thread(sink, batch)
                        self.owner.store.mark_delivered([row['event_id'] for row in batch])
                self.errors.pop('@history', None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.errors['@history'] = type(exc).__name__
            await asyncio.sleep(self.owner.config.poll_interval)
