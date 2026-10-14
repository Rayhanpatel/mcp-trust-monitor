"""Explicit ClickHouse batch adapter for the owner's optional history worker."""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Mapping, Sequence

from .history import TABLE, ClickHouseHTTP, sanitize, table_ddl


class ClickHouseSink:
    """Cancellable delivery, with SQLite work confined to the owning event loop.

    Pass to MonitorConfig.history_sink. The owner sends bounded batches outside
    enforcement locks and marks delivery only after this callback returns.
    """
    def __init__(self, settings: Mapping[str, str], *, attempts: int = 3,
                 timeout_seconds: float = 20.0, backoff_seconds: float = 0.5,
                 async_transport: Any = None) -> None:
        database = settings["CLICKHOUSE_DATABASE"]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", database):
            raise ValueError("ClickHouse database must be a SQL identifier")
        if not 1 <= attempts <= 5 or timeout_seconds <= 0 or backoff_seconds < 0:
            raise ValueError("invalid bounded retry settings")
        self.client = ClickHouseHTTP(settings, timeout_seconds=timeout_seconds)
        self.database, self.attempts = database, attempts
        self.backoff_seconds = backoff_seconds
        self._ready = False
        self._async_transport = async_transport

    async def __call__(self, store) -> None:
        await self.deliver(store)

    async def deliver(self, store) -> None:
        import httpx
        batch = store.pending_outbox(limit=500)
        if not batch:
            return
        ids = [row["event_id"] for row in batch]
        body = "\n".join(json.dumps(row["payload"], sort_keys=True) for row in batch)
        async with httpx.AsyncClient(timeout=self.client.timeout, headers=self.client.headers,
            verify=self.client.context, transport=self._async_transport) as client:
            async def execute(sql, content=None):
                params = {"database": self.database, "date_time_input_format": "best_effort"}
                if content is not None:
                    params["query"] = sql
                response = await client.post(self.client.base, params=params,
                    content=(content if content is not None else sql).encode())
                response.raise_for_status()
            for attempt in range(self.attempts):
                try:
                    if not self._ready:
                        for statement in table_ddl(self.database):
                            await execute(statement)
                        self._ready = True
                    await execute(f"INSERT INTO `{self.database}`.{TABLE} FORMAT JSONEachRow", body)
                    break
                except Exception as exc:
                    error = sanitize(str(exc), self.client.secrets)[:300]
                    if attempt + 1 == self.attempts:
                        store.mark_delivery_failed(ids, error)
                        raise RuntimeError(error) from None
                    await asyncio.sleep(self.backoff_seconds * 2 ** attempt)
        store.mark_delivered(ids)

    def deliver_batch(self, batch: Sequence[Mapping[str, Any]]) -> None:
        """Blocking manual delivery; callers own cancellation and acknowledgement."""
        if not batch:
            return
        body = "\n".join(json.dumps(row["payload"], sort_keys=True) for row in batch)
        for attempt in range(self.attempts):
            try:
                if not self._ready:
                    for statement in table_ddl(self.database):
                        self.client.execute(statement)
                    self._ready = True
                self.client.execute(f"INSERT INTO `{self.database}`.{TABLE} FORMAT JSONEachRow", body=body)
                return
            except Exception as exc:
                error = sanitize(str(exc), self.client.secrets)[:300]
                if attempt + 1 == self.attempts:
                    raise RuntimeError(error) from None
                time.sleep(self.backoff_seconds * 2 ** attempt)
