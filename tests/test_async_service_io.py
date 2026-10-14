import asyncio
import json
import threading

import httpx
import pytest

from mcp_trust_monitor.history_adapter import ClickHouseSink
from mcp_trust_monitor.senso import SensoClient

pytestmark = pytest.mark.anyio


async def test_senso_native_async_search_scope_and_no_upload_retry():
    requests = []
    async def handler(request):
        requests.append(request)
        if request.url.path.endswith("/raw"):
            raise httpx.ReadTimeout("ambiguous request", request=request)
        return httpx.Response(200, json={"results": []})
    client = SensoClient("test-key", attempts=3, backoff_seconds=0,
                         async_transport=httpx.MockTransport(handler))
    assert await client.search_context_async("q", ["content"]) == {"results": []}
    body = json.loads(requests[0].content)
    assert body["content_ids"] == ["content"] and body["require_scoped_ids"] is True
    with pytest.raises(Exception):
        await client.upload_raw_async("approved text", "title")
    assert len(requests) == 2


async def test_senso_cancellation_stops_request_without_retry():
    started, stopped = asyncio.Event(), asyncio.Event()
    requests = []
    async def handler(request):
        requests.append(request)
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()
    client = SensoClient("test-key", async_transport=httpx.MockTransport(handler))
    task = asyncio.create_task(client.node_async("node"))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert stopped.is_set() and len(requests) == 1


class Outbox:
    def __init__(self):
        self.thread = threading.get_ident()
        self.delivered = []
        self.failed = []
    def pending_outbox(self, limit):
        assert threading.get_ident() == self.thread
        return [{"event_id": "event", "payload": {"event_id": "event"}}]
    def mark_delivered(self, ids):
        assert threading.get_ident() == self.thread
        self.delivered.extend(ids)
    def mark_delivery_failed(self, ids, error):
        assert threading.get_ident() == self.thread
        self.failed.extend(ids)


def sink(handler):
    return ClickHouseSink({"CLICKHOUSE_HOST": "example.invalid", "CLICKHOUSE_PORT": "8443",
        "CLICKHOUSE_USER": "test-user", "CLICKHOUSE_PASSWORD": "test-password",
        "CLICKHOUSE_DATABASE": "test_database"}, attempts=1,
        async_transport=httpx.MockTransport(handler))


async def test_async_history_acknowledges_only_after_success_on_owner_loop():
    calls = []
    async def handler(request):
        calls.append(request)
        return httpx.Response(200, text="")
    store = Outbox()
    await sink(handler)(store)
    assert store.delivered == ["event"] and not store.failed and len(calls) == 3


async def test_async_history_cancellation_retains_pending():
    started = asyncio.Event()
    async def handler(request):
        started.set()
        await asyncio.Event().wait()
    store = Outbox()
    task = asyncio.create_task(sink(handler)(store))
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 1)
    assert not store.delivered and not store.failed
