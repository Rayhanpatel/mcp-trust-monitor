"""Cancellation shared by overlapping owned operations (REQ-MON-03).

Python 3.10 has no Task.cancelling(). Track the cancellation we issue explicitly,
only for the lifetime of the owned work, not the lifetime of an application task.
"""
from __future__ import annotations

import asyncio


class _CancellationTracker:
    def __init__(self):
        self._users: dict[asyncio.Future, int] = {}
        self._cancelled: set[asyncio.Future] = set()

    def register(self, task):
        self._users[task] = self._users.get(task, 0) + 1

    def release(self, task):
        users = self._users[task] - 1
        if users:
            self._users[task] = users
        else:
            del self._users[task]
            self._cancelled.discard(task)

    def cancel(self, task):
        # A scheduler task can also own a review and an observation. Each registers
        # separately, but all share this cancellation until their last exit. A stale
        # shutdown snapshot cannot cancel an application task whose operation ended.
        if task in self._users and task not in self._cancelled and not task.done():
            self._cancelled.add(task)
            task.cancel()
