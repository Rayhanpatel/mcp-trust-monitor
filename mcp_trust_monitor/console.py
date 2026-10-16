"""Token-protected loopback console for an already-open TrustMonitor (REQ-UI-01/02).

The HTTP worker never opens a database or touches the monitor. Every read and
action runs on the owning event loop. The server serves only bundled assets and
explicit API routes; untrusted records are rendered with textContent in the UI.

Approve and restore carry the context the operator reviewed: revision, generation,
active policy binding and launch identity. Each part must still be current
(REQ-TRU-02). Verdict drafts read their observation's eligible assessments from
the store, never from the bounded timeline (REQ-MEM-01).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import hmac
import inspect
import json
import secrets
import threading
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any, Mapping
from urllib.parse import urlsplit

from .trust_store import StaleDecisionError

# The evidence timeline in each snapshot is bounded; verdict drafts do not depend on it.
TIMELINE_LIMIT = 200


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "as_dict"):
        return _jsonable(value.as_dict())
    if dataclasses.is_dataclass(value):
        return {field.name: _jsonable(getattr(value, field.name))
                for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class ConsoleBackend:
    """The single integration seam between the local UI and public SDK services."""

    def __init__(self, monitor: Any, memory: Any = None, publication_backend: Any = None):
        if memory is not None and getattr(memory, "store", None) is not monitor.store:
            raise ValueError("Console memory must use the same owning monitor store")
        self.monitor = monitor
        self.memory = memory
        self.publication_backend = publication_backend

    async def snapshot(self) -> dict[str, Any]:
        records = await _resolve(self.monitor.status())
        records = tuple(records or ())
        events = list(await _resolve(self.monitor.events()))
        store = self.monitor.store
        observations = store.observations()
        servers = []
        configured = getattr(getattr(self.monitor, "config", None), "servers", {})
        record_ids = {record.server_id for record in records}
        for record in records:
            item = _jsonable(record)
            previous = (store.reviewed_tools_for_revision(record.server_id,
                        record.approved_revision) if record.approved_revision else None)
            history = [observation for observation in observations
                       if observation.get("server_id") == record.server_id]
            item["before_tools"] = _jsonable(previous) if previous is not None else []
            item["before_label"] = "Previously approved metadata"
            item["latest_observation"] = _jsonable(history[-1]) if history else None
            # A complete verdict context for the latest observation, independent of the
            # bounded timeline below (R9); older observations use `verdict_context`.
            item["latest_verdict_context"] = (
                _jsonable(self.memory.verdict_context(history[-1]["observation_id"]))
                if self.memory is not None and history else None)
            try:
                item["catalog"] = _jsonable(await _resolve(self.monitor.catalog(record.server_id)))
                item["catalog_error"] = None
            except Exception as exc:
                # A failed catalog remains empty; no raw inspection is passed off as approved.
                item["catalog"] = []
                item["catalog_error"] = type(exc).__name__
            servers.append(item)
        for server_id in configured:
            if server_id not in record_ids:
                servers.append({"server_id": server_id, "state": "not_observed",
                                "observed_revision": None, "generation": None,
                                "observed_tools": [], "before_tools": [], "catalog": [],
                                "before_label": "Previously approved metadata",
                                "latest_observation": None, "latest_verdict_context": None})
        policy = self.monitor.policy
        memory = {"available": self.memory is not None,
                  "publication_available": self.publication_backend is not None,
                  "verdicts": [], "lessons": []}
        if self.memory is not None:
            memory["verdicts"] = _jsonable(self.memory.list_verdicts())
            memory["lessons"] = _jsonable(self.memory.list_lessons())
        health = getattr(self.monitor, "health", None)
        if callable(health):
            health = await _resolve(health())
        return {"servers": servers, "events": _jsonable(events[-TIMELINE_LIMIT:]),
                "event_count": len(events), "policy": _jsonable(policy),
                "policy_binding": self._active_binding(),
                "audit": _jsonable(store.outbox_status()), "memory": memory,
                "monitor_health": _jsonable(health),
                "scope": "Only calls through this managed client are protected. Metadata does not prove executable code safe."}

    async def action(self, payload: Mapping[str, Any]) -> Any:
        action = _required_text(payload, "action")
        actor = _required_text(payload, "actor")
        if action in {"observe", "approve", "restore", "quarantine", "review"}:
            server_id = _required_text(payload, "server_id")
            if action in {"approve", "restore"}:
                revision = _required_text(payload, "revision")
                generation = payload.get("generation")
                if type(generation) is not int or generation < 0:
                    raise ValueError("A current integer generation is required")
                self._check_reviewed_context(server_id, payload)
                return await getattr(self.monitor, action)(server_id, revision=revision,
                                      expected_generation=generation, actor=actor)
            if action == "quarantine":
                return await self.monitor.quarantine(server_id, actor=actor,
                                      reason=_required_text(payload, "reason"))
            if action == "review":
                return await self.monitor.review_once(server_id)
            return await self.monitor.observe(server_id)
        if action in {"start_monitor", "stop_monitor"}:
            return await getattr(self.monitor, action)()
        if self.memory is None:
            raise ValueError("Reviewed memory is not configured for this owner")
        if action == "verdict_context":
            # Read only, behind the same token, Origin and CSRF checks as every action.
            return self.memory.verdict_context(_required_text(payload, "observation_id"))
        if action == "record_verdict":
            return self.memory.record_verdict(
                observation_id=_required_text(payload, "observation_id"),
                assessment_event_id=_required_text(payload, "assessment_event_id"),
                value=_required_text(payload, "value"), actor=actor,
                rationale=_required_text(payload, "rationale"),
                supersedes=payload.get("supersedes") or None)
        if action == "draft_lesson":
            rules = payload.get("rule_ids", [])
            if not isinstance(rules, list) or any(not isinstance(rule, str) for rule in rules):
                raise ValueError("rule_ids must be a list of policy IDs")
            return self.memory.draft_lesson(_required_text(payload, "verdict_id"),
                _required_text(payload, "summary"), actor=actor, rule_ids=rules,
                family=str(payload.get("family", "")),
                previous_lesson_id=payload.get("previous_lesson_id") or None)
        lesson_id = _required_text(payload, "lesson_id")
        if action == "preview_lesson":
            return self.memory.preview(lesson_id)
        if action == "approve_lesson":
            return self.memory.approve_lesson(lesson_id, digest=_required_text(payload, "digest"), actor=actor)
        if action in {"revoke_lesson", "reject_lesson"}:
            return getattr(self.memory, action)(lesson_id, actor=actor,
                                                reason=_required_text(payload, "reason"))
        if action == "publish_lesson":
            if self.publication_backend is None:
                raise ValueError("Private publication is not configured")
            return await self.memory.publish(lesson_id, self.publication_backend, actor=actor)
        raise ValueError("Unknown console action")

    def _active_binding(self) -> str | None:
        """The decision binding approvals bind: policy plus detector (REQ-DEC-06)."""
        binding = getattr(self.monitor, "decision_binding", None)
        return binding if isinstance(binding, str) else getattr(self.monitor.policy, "binding", None)

    def _check_reviewed_context(self, server_id: str, payload: Mapping[str, Any]) -> None:
        """Refuse an approve/restore whose reviewed policy or launch identity is stale.

        Revision and generation are checked by the SDK under the server lock. A real
        policy or detector change, or a launch-identity change, also advances the
        generation, so these checks are an early, explicit refusal of the reviewed
        context (REQ-TRU-02).
        """
        if "policy_binding" in payload:
            binding = payload["policy_binding"]
            if not isinstance(binding, str) or binding != self._active_binding():
                raise StaleDecisionError("the reviewed policy binding is no longer active")
        if "launch_identity" in payload:
            identity = payload["launch_identity"]
            record = self.monitor.store.get(server_id)
            if ((identity is not None and not isinstance(identity, str)) or record is None
                    or identity != record.launch_identity):
                raise StaleDecisionError("the reviewed launch identity is no longer current")


def _required_text(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} is required")
    if len(value) > 16000:
        raise ValueError(f"{key} is too long")
    return value


class ConsoleServer:
    """Run a local UI alongside an open monitor; never create a second owner.

    ``async with ConsoleServer(monitor) as console: print(console.url)``
    displays an authenticated URL. Treat that URL as a local credential. The
    random token is in the fragment, never an HTTP path or query parameter.
    """

    def __init__(self, monitor: Any, memory: Any = None, *, publication_backend: Any = None,
                 host: str = "127.0.0.1", port: int = 0, timeout: float = 120.0,
                 backend: ConsoleBackend | None = None):
        if host != "127.0.0.1":
            raise ValueError("The console binds only to 127.0.0.1")
        if not 0 <= port <= 65535:
            raise ValueError("Invalid console port")
        self.backend = backend or ConsoleBackend(monitor, memory, publication_backend)
        self.host, self.port, self.timeout = host, port, timeout
        self.token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._futures: set[concurrent.futures.Future] = set()
        self._future_lock = threading.Lock()
        self._closing = False

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.origin}/#token={self.token}"

    async def start(self) -> "ConsoleServer":
        if self._server is not None:
            raise RuntimeError("Console is already started")
        self._loop = asyncio.get_running_loop()
        self._closing = False
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_: Any) -> None:
                # No request, token, metadata, credential or body logging.
                return

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def respond(self, code: int, value: Any, content_type: str = "application/json") -> None:
                body = (json.dumps(_jsonable(value), ensure_ascii=False).encode()
                        if content_type == "application/json" else value)
                self.send_response(code)
                self.send_header("Content-Type", content_type + "; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def guard(self, *, sensitive: bool = False, mutation: bool = False) -> bool:
                hosts = self.headers.get_all("Host", [])
                if hosts != [f"{owner.host}:{owner.port}"]:
                    self.respond(403, {"error": "invalid_host"})
                    return False
                origins = self.headers.get_all("Origin", [])
                if len(origins) > 1:
                    self.respond(403, {"error": "invalid_origin"})
                    return False
                origin = origins[0] if origins else None
                if ((origin is not None and origin != owner.origin) or
                        self.headers.get("Sec-Fetch-Site") == "cross-site"):
                    self.respond(403, {"error": "invalid_origin"})
                    return False
                if sensitive:
                    auth = self.headers.get_all("Authorization", [])
                    if len(auth) != 1 or not hmac.compare_digest(
                            auth[0].encode("utf-8"), ("Bearer " + owner.token).encode("utf-8")):
                        self.respond(401, {"error": "local_token_required"})
                        return False
                csrf_values = self.headers.get_all("X-CSRF-Token", [])
                if mutation and (origin != owner.origin or len(csrf_values) != 1 or
                        not hmac.compare_digest(csrf_values[0].encode("utf-8"),
                                                owner.csrf_token.encode("utf-8"))):
                    self.respond(403, {"error": "csrf_rejected"})
                    return False
                return True

            def do_GET(self) -> None:
                path = urlsplit(self.path)
                if path.query or path.fragment or path.scheme or path.netloc:
                    self.respond(400, {"error": "invalid_path"})
                    return
                if not self.guard(sensitive=path.path.startswith("/api/")):
                    return
                if path.path == "/api/state":
                    self.run_api(owner.backend.snapshot(), include_csrf=True)
                    return
                assets = {"/": ("index.html", "text/html"),
                          "/app.js": ("app.js", "text/javascript"),
                          "/style.css": ("style.css", "text/css")}
                if path.path not in assets:
                    self.respond(404, {"error": "not_found"})
                    return
                filename, kind = assets[path.path]
                body = resources.files("mcp_trust_monitor").joinpath("console_assets", filename).read_bytes()
                self.respond(200, body, kind)

            def do_POST(self) -> None:
                if not self.guard(sensitive=True, mutation=True):
                    return
                if self.path != "/api/action":
                    self.respond(404, {"error": "not_found"})
                    return
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                    self.respond(400, {"error": "content_length_required"})
                    return
                try:
                    length = int(lengths[0])
                except ValueError:
                    length = -1
                if not 0 < length <= 65536:
                    self.respond(413, {"error": "invalid_body_size"})
                    return
                if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                    self.respond(415, {"error": "json_required"})
                    return
                try:
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError("Incomplete body")
                    payload = json.loads(raw)
                    if not isinstance(payload, dict):
                        raise ValueError("Object required")
                except (ValueError, UnicodeError):
                    self.respond(400, {"error": "invalid_json"})
                    return
                self.run_api(owner.backend.action(payload))

            def run_api(self, coroutine: Any, *, include_csrf: bool = False) -> None:
                if owner._closing:
                    coroutine.close()
                    self.respond(503, {"error": "console_closing"})
                    return
                future = asyncio.run_coroutine_threadsafe(coroutine, owner._loop)
                with owner._future_lock:
                    owner._futures.add(future)
                try:
                    value = future.result(timeout=owner.timeout)
                    if include_csrf:
                        value["csrf_token"] = owner.csrf_token
                    self.respond(200, {"result": value})
                except concurrent.futures.TimeoutError:
                    future.cancel()
                    self.respond(504, {"error": "operation_timed_out",
                                       "message": "Refresh state before repeating an action; its outcome may be unknown."})
                except Exception as exc:
                    # Never echo exception text: provider messages can contain credentials.
                    self.respond(409, {"error": type(exc).__name__,
                                       "message": "Operation refused. Refresh the state and check the current revision, required fields and service configuration."})
                finally:
                    with owner._future_lock:
                        owner._futures.discard(future)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                       kwargs={"poll_interval": 0.1}, daemon=True)
        self._thread.start()
        return self

    async def close(self) -> None:
        self._closing = True
        with self._future_lock:
            futures = list(self._futures)
        for future in futures:
            future.cancel()
        if self._server is not None:
            await asyncio.to_thread(self._server.shutdown)
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            await asyncio.to_thread(self._thread.join, 2)
            self._thread = None

    async def __aenter__(self) -> "ConsoleServer":
        return await self.start()

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
