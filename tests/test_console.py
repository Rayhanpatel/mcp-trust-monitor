"""HTTP boundary and same-owner state proofs for the loopback console."""
from __future__ import annotations

import asyncio
import http.client
import json
import threading
from importlib import resources
from types import SimpleNamespace

import pytest

from mcp_trust_monitor.console import ConsoleBackend, ConsoleServer
from mcp_trust_monitor.policy import PolicyRef
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.trust_store import TrustState, TrustStore


class LocalMonitor:
    """Public facade stand-in with a real owner-thread SQLite store."""
    def __init__(self, path):
        self.store = TrustStore(path)
        self.policy = PolicyRef("console-test", "1", "test-digest")
        self.config = SimpleNamespace(servers={"partner/notes": None, "partner/not-observed": None})
        self.thread = threading.get_ident()
        self.calls = []

    def status(self):
        assert threading.get_ident() == self.thread
        return tuple(self.store.records())

    def events(self):
        return self.store.events()

    def catalog(self, server_id):
        record = self.store.get(server_id)
        if not record or record.state is not TrustState.APPROVED:
            return ()
        return ({"server_id": server_id, "definition": record.observed_tools[0]},)

    def health(self):
        return {"status": "stopped", "servers": {"partner/notes": {"freshness": "fresh"}}}

    async def approve(self, server_id, *, revision, expected_generation, actor):
        self.calls.append(("approve", threading.get_ident()))
        return self.store.approve(server_id, revision=revision,
            expected_generation=expected_generation, actor=actor, policy_revision=self.policy.binding)

    async def restore(self, server_id, *, revision, expected_generation, actor):
        self.calls.append(("restore", threading.get_ident()))
        return self.store.approve(server_id, revision=revision,
            expected_generation=expected_generation, actor=actor, policy_revision=self.policy.binding,
            restore=True)

    async def quarantine(self, server_id, *, actor, reason):
        self.calls.append(("quarantine", threading.get_ident()))
        return self.store.quarantine(server_id, actor=actor, reason=reason)


def observe(monitor, description="Read a public note"):
    tools = ({"name": "notes", "description": description,
              "inputSchema": {"type": "object", "properties": {}}},)
    return monitor.store.record_observation("partner/notes", server_revision(tools), tools,
                                            provenance={"origin": "synthetic_fixture"})


async def request(console, method="GET", path="/api/state", *, body=None, auth=True,
                  origin=None, csrf=None, host=None, headers=None):
    def send():
        connection = http.client.HTTPConnection(console.host, console.port, timeout=4)
        fields = dict(headers or {})
        if auth:
            fields["Authorization"] = "Bearer " + console.token
        if origin is not None:
            fields["Origin"] = origin
        if csrf is not None:
            fields["X-CSRF-Token"] = csrf
        if host is not None:
            fields["Host"] = host
        raw = json.dumps(body).encode() if body is not None else None
        if raw is not None:
            fields["Content-Type"] = "application/json"
        connection.request(method, path, body=raw, headers=fields)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result
    return await asyncio.to_thread(send)


def test_host_origin_token_and_csrf_guard_before_actions(tmp_path):
    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        record = observe(monitor)
        async with ConsoleServer(monitor) as console:
            action = {"action": "approve", "actor": "tester", "server_id": "partner/notes",
                      "revision": record.observed_revision, "generation": record.generation}
            assert (await request(console, auth=False))[0] == 401
            assert (await request(console, host="attacker.example"))[0] == 403
            assert (await request(console, origin="https://attacker.example"))[0] == 403
            for origin, csrf in [(None, None), (console.origin, None),
                                 ("https://attacker.example", console.csrf_token)]:
                assert (await request(console, "POST", "/api/action", body=action,
                                      origin=origin, csrf=csrf))[0] == 403
            assert monitor.calls == []
            assert monitor.store.get("partner/notes").state is TrustState.UNREVIEWED
            status, _, raw = await request(console, "POST", "/api/action", body=action,
                                         origin=console.origin, csrf=console.csrf_token)
            assert status == 200, raw
            assert monitor.store.get("partner/notes").state is TrustState.APPROVED
            assert monitor.calls == [("approve", monitor.thread)]
        monitor.store.close()
    asyncio.run(run())


def test_approval_and_restore_bind_current_revision_and_generation(tmp_path):
    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        old = observe(monitor)
        async with ConsoleServer(monitor) as console:
            async def action(name, record, generation=None):
                return await request(console, "POST", "/api/action", origin=console.origin,
                    csrf=console.csrf_token, body={"action": name, "actor": "tester",
                    "server_id": "partner/notes", "revision": record.observed_revision,
                    "generation": record.generation if generation is None else generation})
            current = observe(monitor, "Read a different public note")
            assert (await action("approve", old))[0] == 409
            assert (await action("approve", current, current.generation + 1))[0] == 409
            assert (await action("approve", current))[0] == 200
            quarantined = monitor.store.quarantine("partner/notes", actor="tester", reason="test")
            assert (await action("restore", current))[0] == 409
            assert (await action("restore", quarantined))[0] == 200
        monitor.store.close()
    asyncio.run(run())


def test_snapshot_is_real_records_and_never_fabricates_verification(tmp_path):
    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        record = observe(monitor, '</pre><script>alert("unsafe")</script>')
        async with ConsoleServer(monitor) as console:
            status, headers, raw = await request(console)
            assert status == 200
            data = json.loads(raw)["result"]
            assert data["csrf_token"] == console.csrf_token
            assert data["servers"][0]["observed_revision"] == record.observed_revision
            assert data["servers"][0]["catalog"] == []
            assert data["servers"][0]["origin"] == "synthetic_fixture"
            assert data["servers"][1]["state"] == "not_observed"
            assert data["audit"]["pending"] > 0
            assert data["memory"]["available"] is False
            assert data["monitor_health"]["status"] == "stopped"
            assert not any(e["event_type"] == "verified_blocked" for e in data["events"])
            assert headers["Content-Type"].startswith("application/json")
            assert headers["Cache-Control"] == "no-store"
            assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
            _, _, shell = await request(console, path="/", auth=False)
            _, _, script = await request(console, path="/app.js", auth=False)
            assert b"<script>alert" not in shell
            assert console.token.encode() not in shell
            assert console.token.encode() not in script
            assert b"innerHTML" not in script and b"textContent" in script
            assert b"eval(" not in script
        monitor.store.close()
    asyncio.run(run())


def test_explicit_tokens_no_query_auth_and_routes_are_bounded(tmp_path):
    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        async with ConsoleServer(monitor) as console:
            assert (await request(console, path="/api/state?token=" + console.token, auth=False))[0] == 400
            assert (await request(console, path="/../policy.json"))[0] == 404
            assert (await request(console, path="/api/approve"))[0] == 404
            assert (await request(console, "POST", "/api/action", body=[], origin=console.origin,
                                  csrf=console.csrf_token))[0] == 400
            assert (await request(console, "POST", "/api/action", body={"x": "a" * 70000},
                                  origin=console.origin, csrf=console.csrf_token))[0] == 413
        monitor.store.close()
    asyncio.run(run())


def test_missing_generation_never_reaches_approval(tmp_path):
    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        record = observe(monitor)
        backend = ConsoleBackend(monitor)
        for generation in [None, True, "1", -1]:
            with pytest.raises(ValueError):
                await backend.action({"action": "approve", "actor": "tester",
                    "server_id": "partner/notes", "revision": record.observed_revision,
                    "generation": generation})
        assert monitor.calls == []
        monitor.store.close()
    asyncio.run(run())


def test_lesson_approval_passes_exact_preview_digest_and_actor(tmp_path):
    class Memory:
        def __init__(self, store):
            self.store = store
            self.calls = []
        def preview(self, lesson_id):
            return {"lesson_id": lesson_id, "body": "Reviewed synthetic lesson", "digest": "sha256:exact"}
        def approve_lesson(self, lesson_id, *, digest, actor):
            if digest != "sha256:exact":
                raise ValueError("digest mismatch")
            self.calls.append((lesson_id, digest, actor))
            return {"state": "approved"}
    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        memory = Memory(monitor.store)
        backend = ConsoleBackend(monitor, memory)
        preview = await backend.action({"action": "preview_lesson", "actor": "tester", "lesson_id": "L1"})
        with pytest.raises(ValueError):
            await backend.action({"action": "approve_lesson", "actor": "tester", "lesson_id": "L1", "digest": "wrong"})
        await backend.action({"action": "approve_lesson", "actor": "tester", "lesson_id": "L1", "digest": preview["digest"]})
        assert memory.calls == [("L1", "sha256:exact", "tester")]
        with pytest.raises(ValueError, match="not configured"):
            await backend.action({"action": "publish_lesson", "actor": "tester", "lesson_id": "L1"})
        monitor.store.close()
    asyncio.run(run())


def test_failure_does_not_echo_secret_exception(tmp_path):
    class Broken(ConsoleBackend):
        async def snapshot(self):
            raise RuntimeError("authorization=top-secret-value")
    async def run():
        async with ConsoleServer(None, backend=Broken(None)) as console:
            status, _, raw = await request(console)
            assert status == 409
            assert b"top-secret-value" not in raw
    asyncio.run(run())


def test_loopback_only_and_bundled_assets():
    for host in ["0.0.0.0", "localhost", "::", "192.168.1.1"]:
        with pytest.raises(ValueError, match="127.0.0.1"):
            ConsoleServer(None, host=host)
    package = resources.files("mcp_trust_monitor").joinpath("console_assets")
    assert all(package.joinpath(name).is_file() for name in ("index.html", "app.js", "style.css"))


def test_verdict_context_is_an_authenticated_csrf_protected_read(tmp_path):
    """R9: eligible assessments come from the store through the guarded action route."""
    from mcp_trust_monitor.memory import MemoryService

    async def run():
        monitor = LocalMonitor(tmp_path / "trust.db")
        record = observe(monitor)
        assessment = monitor.store.record_assessment_if_current(
            "partner/notes", revision=record.observed_revision, generation=record.generation,
            policy_revision=monitor.policy.binding, active_policy_revision=monitor.policy.binding,
            detail={"synthetic_assessment": True}, actor="synthetic-reviewer")
        observation_id = monitor.store.observations("partner/notes")[-1]["observation_id"]
        memory = MemoryService(monitor.store, monitor.policy, rule_ids=("POL-001",))
        async with ConsoleServer(monitor, memory) as console:
            body = {"action": "verdict_context", "actor": "tester", "observation_id": observation_id}
            assert (await request(console, "POST", "/api/action", body=body, auth=False,
                                  origin=console.origin, csrf=console.csrf_token))[0] == 401
            assert (await request(console, "POST", "/api/action", body=body, origin=console.origin))[0] == 403
            assert (await request(console, "POST", "/api/action", body=body,
                                  origin="https://attacker.example", csrf=console.csrf_token))[0] == 403
            assert (await request(console, path="/api/verdict_context"))[0] == 404
            status, _, raw = await request(console, "POST", "/api/action", body=body,
                                           origin=console.origin, csrf=console.csrf_token)
            assert status == 200, raw
            result = json.loads(raw)["result"]
            assert result["observation"]["observation_id"] == observation_id
            assert [event["event_id"] for event in result["assessments"]] == [assessment.event_id]
            status, _, raw = await request(console, "POST", "/api/action",
                                           body={**body, "observation_id": "missing"},
                                           origin=console.origin, csrf=console.csrf_token)
            assert status == 409 and json.loads(raw)["error"] == "MemoryIntegrityError"
            _, _, raw = await request(console)
            data = json.loads(raw)["result"]
            assert data["policy_binding"] == monitor.policy.binding
            assert data["servers"][0]["latest_verdict_context"] == result
            assert data["servers"][1]["latest_verdict_context"] is None
        monitor.store.close()
    asyncio.run(run())


def test_shipped_app_posts_reviewed_context_and_renders_drafts_as_text():
    script = resources.files("mcp_trust_monitor").joinpath("console_assets", "app.js").read_text()
    for field in ("policy_binding:review.policy_binding", "launch_identity:review.launch_identity",
                  "revision:review.revision", "generation:review.generation"):
        assert field in script
    assert "verdict_context" in script and "innerHTML" not in script
    page = resources.files("mcp_trust_monitor").joinpath("console_assets", "index.html").read_text()
    for element in ("review-current", "review-stale", "keep-draft", "replace-draft", "record-verdict"):
        assert f'id="{element}"' in page
