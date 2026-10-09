"""The managed MCP client and its trust gate.

`call_tool` is the only path to `tools/call`. Under a per-server lock it reads the
persisted trust record immediately before writing the request to the MCP
transport (REQ-ENF-01) and refuses unless that exact revision is approved under the
active policy (REQ-ENF-02). It checks once before connecting, so a blocked call
never launches or contacts the server, and again after a new connection has
recorded its observation.

`observe` is metadata-only (initialize and paginated tools/list). It records the
server revision, which may invalidate an approval, and never dispatches a tool.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Mapping

import mcp.types as types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .revision import server_revision, tool_metadata
from .trust_store import TrustRecord, TrustState, TrustStore

MAX_TOOL_LIST_PAGES = 20


@dataclass(frozen=True)
class ServerConfig:
    server_id: str
    command: str
    args: tuple[str, ...] = ()
    # None passes only the MCP SDK's minimal default environment to the server.
    env: Mapping[str, str] | None = None
    cwd: str | None = None


class CallBlocked(Exception):
    def __init__(self, server_id: str, tool: str, reason: str) -> None:
        super().__init__(f"call to {server_id}/{tool} blocked before dispatch: {reason}")
        self.server_id = server_id
        self.tool = tool
        self.reason = reason


class ObservationError(Exception):
    """tools/list did not produce a complete, valid observation. Never a clean result."""


@dataclass
class _Connection:
    """Owns one stdio session in a dedicated task so it can close independently."""

    config: ServerConfig
    timeout: timedelta
    session: ClientSession | None = None
    _ready: asyncio.Event = field(default_factory=asyncio.Event)
    _stop: asyncio.Event = field(default_factory=asyncio.Event)
    _task: asyncio.Task[None] | None = None
    _error: BaseException | None = None

    async def open(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"mcp:{self.config.server_id}")
        await self._ready.wait()
        if self.session is None:
            await self.close()
            raise ObservationError(
                f"could not connect to {self.config.server_id}: {self._error!r}"
            )

    @property
    def alive(self) -> bool:
        return self.session is not None and self._task is not None and not self._task.done()

    async def close(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await self._task
            except Exception:
                pass

    async def _run(self) -> None:
        params = StdioServerParameters(
            command=self.config.command,
            args=list(self.config.args),
            env=dict(self.config.env) if self.config.env is not None else None,
            cwd=self.config.cwd,
        )
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write, read_timeout_seconds=self.timeout) as session:
                    await session.initialize()
                    self.session = session
                    self._ready.set()
                    await self._stop.wait()
        except Exception as exc:
            self._error = exc
        finally:
            self.session = None
            self._ready.set()


class ManagedClient:
    def __init__(
        self,
        store: TrustStore,
        servers: Mapping[str, ServerConfig],
        *,
        policy_revision: str,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.store = store
        self.servers = dict(servers)
        self.policy_revision = policy_revision
        self._timeout = timedelta(seconds=timeout_seconds)
        self._connections: dict[str, _Connection] = {}
        self._locks: dict[str, asyncio.Lock] = {}
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
        async with self._lock(server_id):
            connection = await self._connection(server_id, observe_new=False)
            return await self._observe(server_id, connection)

    async def approve(
        self, server_id: str, *, revision: str, expected_generation: int | None, actor: str
    ) -> TrustRecord:
        async with self._lock(server_id):
            return self.store.approve(
                server_id,
                revision=revision,
                policy_revision=self.policy_revision,
                expected_generation=expected_generation,
                actor=actor,
            )

    async def quarantine(self, server_id: str, *, actor: str, reason: str) -> TrustRecord:
        async with self._lock(server_id):
            record = self.store.quarantine(server_id, actor=actor, reason=reason)
            await self._disconnect(server_id)
            return record

    async def call_tool(
        self, server_id: str, tool: str, arguments: dict[str, Any] | None = None
    ) -> types.CallToolResult:
        async with self._lock(server_id):
            try:
                self._authorize(server_id, tool)
                connection = await self._connection(server_id, observe_new=True)
                record = self._authorize(server_id, tool)
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
        for server_id in list(self._connections):
            await self._disconnect(server_id)

    # Internals

    def _lock(self, server_id: str) -> asyncio.Lock:
        if server_id not in self.servers:
            raise KeyError(f"{server_id} is not configured for this client")
        return self._locks.setdefault(server_id, asyncio.Lock())

    def _authorize(self, server_id: str, tool: str) -> TrustRecord:
        record = self.store.get(server_id)
        reason = self._block_reason(record, tool)
        if reason == "policy_revision_changed":
            self.store.invalidate(server_id, actor="managed-client",
                                  reason="active policy revision changed")
        if reason is not None:
            self.store.record_event(server_id, "call_blocked", actor="managed-client",
                                    detail={"tool": tool, "reason": reason})
            raise CallBlocked(server_id, tool, reason)
        assert record is not None
        return record

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

    async def _connection(self, server_id: str, *, observe_new: bool) -> _Connection:
        connection = self._connections.get(server_id)
        if connection is not None and connection.alive:
            return connection
        if connection is not None:
            await self._disconnect(server_id)
        connection = _Connection(self.servers[server_id], self._timeout)
        await connection.open()
        self._connections[server_id] = connection
        if observe_new:
            await self._observe(server_id, connection)
        return connection

    async def _observe(self, server_id: str, connection: _Connection) -> TrustRecord:
        assert connection.session is not None
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAX_TOOL_LIST_PAGES):
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            try:
                page = await connection.session.list_tools(params=params)
            except Exception as exc:
                raise ObservationError(f"tools/list failed for {server_id}: {exc!r}") from exc
            tools.extend(tool_metadata(tool.model_dump(by_alias=True)) for tool in page.tools)
            cursor = page.nextCursor
            if not cursor:
                break
        else:
            raise ObservationError(f"tools/list for {server_id} exceeded {MAX_TOOL_LIST_PAGES} pages")
        try:
            revision = server_revision(tools)
        except ValueError as exc:
            raise ObservationError(f"invalid tools/list from {server_id}: {exc}") from exc
        return self.store.record_observation(server_id, revision, tools)

    async def _disconnect(self, server_id: str) -> None:
        connection = self._connections.pop(server_id, None)
        if connection is not None:
            await connection.close()


def trust_db_path(state_dir: Path) -> Path:
    return Path(state_dir) / "trust.sqlite3"
