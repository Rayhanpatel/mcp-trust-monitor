"""REQ-MEM-01–05: local eligibility owns authority; remote memory never does.

All state and audit mutations share the owning TrustStore transaction. Network
requests run outside it. The store's owner/fault latch remains authoritative.
"""
from __future__ import annotations

import asyncio
import json
import math
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, Sequence
from uuid import uuid4

from ..policy import PolicyRef
from ..trust_store import StorageFaultError, TrustStore
from .sanitize import (MAX_BODY_CHARS, body_digest, bounded_text,
                       normalize_passage, sanitize_summary)
from .types import (Lesson, MemoryBackend, MemoryConflict, MemoryIntegrityError,
                    MemorySnapshot, MemoryStale, NodeStatus, RemoteContent,
                    RetrievedMemory, RetrievedPrecedent, SearchPassage, UploadReceipt, Verdict)

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS memory_meta (client_id TEXT NOT NULL, scope TEXT NOT NULL, "
    "revision INTEGER NOT NULL, PRIMARY KEY(client_id,scope))",
    "CREATE TABLE IF NOT EXISTS memory_verdicts (client_id TEXT NOT NULL, scope TEXT NOT NULL, "
    "verdict_id TEXT NOT NULL, assessment_event_id TEXT NOT NULL, active INTEGER NOT NULL, "
    "payload TEXT NOT NULL, PRIMARY KEY(client_id,scope,verdict_id))",
    "CREATE UNIQUE INDEX IF NOT EXISTS memory_current_verdict ON memory_verdicts "
    "(client_id,scope,assessment_event_id) WHERE active=1",
    "CREATE TABLE IF NOT EXISTS memory_lessons (client_id TEXT NOT NULL, scope TEXT NOT NULL, "
    "lesson_id TEXT NOT NULL, verdict_id TEXT NOT NULL, series_id TEXT NOT NULL, version INTEGER NOT NULL, "
    "state TEXT NOT NULL, policy_binding TEXT NOT NULL, payload TEXT NOT NULL, "
    "PRIMARY KEY(client_id,scope,lesson_id), UNIQUE(client_id,scope,series_id,version))",
)
_ASSESSMENT_TYPES = {"model_assessment_recorded", "hard_deny_scan_clean", "quarantine_requested"}
_REVOKABLE = {"draft", "approved", "publishing", "uploaded_unverified", "active",
              "publication_indeterminate", "publication_failed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _bound_assessment_revision(observation: dict, event: dict, binding: str) -> str | None:
    """The assessed revision when `event` is an accepted assessment of exactly this
    observation (server, revision, generation) under the active policy `binding`;
    otherwise None. The one rule for `record_verdict` and `verdict_context`."""
    if event.get("event_type") not in _ASSESSMENT_TYPES:
        return None
    detail = event["detail"]
    revision = detail.get("assessed_revision", event.get("revision"))
    generation = detail.get("assessed_generation", event.get("generation"))
    context = detail.get("policy_context", detail.get("assessed_policy_revision", event.get("policy_revision")))
    if (event["server_id"] != observation["server_id"] or revision != observation["revision"]
            or generation != observation["generation"] or not isinstance(context, str)
            or not (context == binding or context.startswith(binding + "|"))):
        return None
    return revision


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class MemoryService:
    """A scoped registry sharing one application's already-owned trust store.

    Operator methods are synchronous, bounded transactions. Publication/retrieval
    are async and require an explicitly capability-verified backend. Core library
    callers need no network dependency to create, preview, approve or revoke.
    """

    def __init__(self, store: TrustStore, policy: PolicyRef | Callable[[], PolicyRef], *,
                 rule_ids: Sequence[str], scope: str = "default",
                 excluded_revisions: Sequence[str] = (),
                 summary_validator: Callable[[str], None] | None = None,
                 request_timeout: float = 20.0, max_eligible: int = 100) -> None:
        self.store = store
        self._policy = policy if callable(policy) else lambda: policy
        self.scope = bounded_text(scope, "scope", 128)
        if not rule_ids or any(not isinstance(item, str) or not item for item in rule_ids):
            raise MemoryIntegrityError("at least one explicit policy rule ID is required")
        self.rule_ids = tuple(sorted(set(rule_ids)))
        if not math.isfinite(request_timeout) or request_timeout <= 0:
            raise ValueError("request_timeout must be positive and finite")
        if type(max_eligible) is not int or not 1 <= max_eligible <= 1000:
            raise ValueError("max_eligible must be between 1 and 1000")
        self.request_timeout = request_timeout
        self.max_eligible = max_eligible
        self._excluded_revisions = frozenset(excluded_revisions)
        self._summary_validator = summary_validator
        self._publishing: set[str] = set()
        with self.store.atomic() as db:
            for statement in _SCHEMA:
                db.execute(statement)
            db.execute("INSERT OR IGNORE INTO memory_meta VALUES (?,?,0)", self._key)

    @property
    def _key(self) -> tuple[str, str]:
        return self.store.client_id, self.scope

    @property
    def policy(self) -> PolicyRef:
        return self._policy()

    def _bump(self, db: Any) -> None:
        db.execute("UPDATE memory_meta SET revision=revision+1 WHERE client_id=? AND scope=?", self._key)

    def _event(self, db: Any, event_type: str, actor: str, detail: dict) -> str:
        return self.store.emit_event_in_transaction(
            db, None, event_type, actor,
            {"memory_scope": self.scope, **detail})

    def _lesson(self, db: Any, lesson_id: str) -> Lesson:
        row = db.execute("SELECT payload FROM memory_lessons WHERE client_id=? AND scope=? AND lesson_id=?",
                         (*self._key, lesson_id)).fetchone()
        if row is None:
            raise MemoryConflict("lesson does not exist in this owner/scope")
        return Lesson(**json.loads(row["payload"]))

    def _verdict(self, db: Any, verdict_id: str) -> Verdict:
        row = db.execute("SELECT payload FROM memory_verdicts WHERE client_id=? AND scope=? AND verdict_id=?",
                         (*self._key, verdict_id)).fetchone()
        if row is None:
            raise MemoryConflict("verdict does not exist in this owner/scope")
        return Verdict(**json.loads(row["payload"]))

    def _put_lesson(self, db: Any, lesson: Lesson) -> None:
        db.execute("UPDATE memory_lessons SET state=?,policy_binding=?,payload=? "
                   "WHERE client_id=? AND scope=? AND lesson_id=?",
                   (lesson.state, lesson.policy_binding, _json(lesson.as_dict()), *self._key, lesson.lesson_id))

    def _eligible_verdict(self, db: Any, lesson: Lesson) -> Verdict:
        verdict = self._verdict(db, lesson.verdict_id)
        if not verdict.active or verdict.value == "uncertain":
            raise MemoryConflict("source verdict is uncertain or superseded")
        if verdict.policy_binding != self.policy.binding or lesson.policy_binding != self.policy.binding:
            raise MemoryConflict("lesson requires review for the current policy")
        if verdict.revision in self._excluded_revisions:
            raise MemoryIntegrityError("held-out observations cannot supply lessons")
        if body_digest(lesson.body) != lesson.digest:
            raise MemoryIntegrityError("local approved body digest does not match")
        return verdict

    def get_lesson(self, lesson_id: str) -> Lesson:
        with self.store.atomic() as db:
            return self._lesson(db, lesson_id)

    def get_verdict(self, verdict_id: str) -> Verdict:
        with self.store.atomic() as db:
            return self._verdict(db, verdict_id)

    def list_lessons(self) -> tuple[Lesson, ...]:
        with self.store.atomic() as db:
            rows = db.execute("SELECT payload FROM memory_lessons WHERE client_id=? AND scope=? "
                              "ORDER BY rowid", self._key)
            return tuple(Lesson(**json.loads(row["payload"])) for row in rows)

    def list_verdicts(self) -> tuple[Verdict, ...]:
        with self.store.atomic() as db:
            rows = db.execute("SELECT payload FROM memory_verdicts WHERE client_id=? AND scope=? "
                              "ORDER BY rowid", self._key)
            return tuple(Verdict(**json.loads(row["payload"])) for row in rows)

    def record_verdict(self, *, observation_id: str, assessment_event_id: str,
                       value: str, actor: str, rationale: str,
                       supersedes: str | None = None) -> Verdict:
        """Record human ground truth; approval/restore never creates a verdict."""
        if value not in {"violation", "non_violation", "uncertain"}:
            raise MemoryIntegrityError("invalid verdict")
        bounded_text(actor, "actor")
        bounded_text(rationale, "rationale", 2000)
        with self.store.atomic() as db:
            observation = next((item for item in self.store.observations()
                                if item["observation_id"] == observation_id), None)
            event = next((item for item in self.store.events()
                          if item["event_id"] == assessment_event_id), None)
            if observation is None or event is None or event["event_type"] not in _ASSESSMENT_TYPES:
                raise MemoryIntegrityError("a recorded observation and accepted assessment are required")
            binding = self.policy.binding
            revision = _bound_assessment_revision(observation, event, binding)
            if revision is None:
                raise MemoryIntegrityError("assessment does not bind this observation and current policy")
            existing = db.execute("SELECT verdict_id FROM memory_verdicts WHERE client_id=? AND scope=? "
                                  "AND assessment_event_id=? AND active=1",
                                  (*self._key, assessment_event_id)).fetchone()
            if existing and supersedes != existing["verdict_id"]:
                raise MemoryConflict("name the active verdict to supersede it explicitly")
            if supersedes:
                old = self._verdict(db, supersedes)
                if not old.active or old.assessment_event_id != assessment_event_id:
                    raise MemoryConflict("supersession must name the current verdict for this assessment")
                old = replace(old, active=False)
                db.execute("UPDATE memory_verdicts SET active=0,payload=? WHERE client_id=? AND scope=? AND verdict_id=?",
                           (_json(old.as_dict()), *self._key, supersedes))
                for row in db.execute("SELECT payload FROM memory_lessons WHERE client_id=? AND scope=? AND verdict_id=?",
                                      (*self._key, supersedes)).fetchall():
                    lesson = Lesson(**json.loads(row["payload"]))
                    if lesson.state not in {"revoked", "rejected"}:
                        self._put_lesson(db, replace(lesson, state="revoked", updated_at=_now(),
                                                    last_error="source verdict superseded"))
                        self._event(db, "lesson_revoked", actor,
                                    {"lesson_id": lesson.lesson_id, "reason": "verdict superseded",
                                     "content_id": lesson.content_id, "orphan": bool(lesson.content_id)})
            verdict = Verdict(str(uuid4()), observation_id, assessment_event_id, observation["server_id"],
                              revision, binding, value, actor, rationale, True, supersedes, _now(),
                              observation.get("origin") or "unrecorded")
            db.execute("INSERT INTO memory_verdicts VALUES (?,?,?,?,?,?)",
                       (*self._key, verdict.verdict_id, assessment_event_id, 1, _json(verdict.as_dict())))
            self._bump(db)
            self._event(db, "verdict_recorded", actor,
                        {"verdict_id": verdict.verdict_id, "value": value, "observation_id": observation_id,
                         "assessment_event_id": assessment_event_id, "revision": revision,
                         "policy_binding": binding, "supersedes": supersedes, "origin": verdict.origin})
            return verdict

    def verdict_context(self, observation_id: str, *, limit: int = 50) -> dict[str, Any]:
        """Read only: one observation and the assessments `record_verdict` accepts for it.

        Queried from the store for this observation, so it never depends on a bounded
        timeline (REQ-MEM-01, REQ-UI-01). At most `limit` assessments, oldest first.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        observation = self.store.observation(observation_id)
        if observation is None:
            raise MemoryIntegrityError("observation does not exist in this owner")
        binding = self.policy.binding
        assessments = [event for event in self.store.events(observation["server_id"])
                       if _bound_assessment_revision(observation, event, binding) is not None]
        try:
            tools = json.loads(observation["reviewed_metadata"])
        except (TypeError, ValueError) as exc:
            raise MemoryIntegrityError("observation metadata is not readable") from exc
        summary = {key: observation[key] for key in
                   ("observation_id", "ts", "server_id", "revision", "generation", "origin")}
        return {"observation": {**summary, "reviewed_tools": tools},
                "policy_binding": binding, "assessments": assessments[-limit:]}

    def draft_lesson(self, verdict_id: str, summary: str, *, actor: str,
                     rule_ids: Sequence[str] = (), family: str = "",
                     previous_lesson_id: str | None = None) -> Lesson:
        bounded_text(actor, "actor")
        summary = sanitize_summary(summary)
        if self._summary_validator:
            self._summary_validator(summary)
        if family:
            bounded_text(family, "family", 128)
        rules = tuple(sorted(set(rule_ids)))
        if set(rules) - set(self.rule_ids):
            raise MemoryIntegrityError("lesson cites unknown policy rule IDs")
        with self.store.atomic() as db:
            verdict = self._verdict(db, verdict_id)
            if not verdict.active or verdict.value == "uncertain":
                raise MemoryConflict("only a current definite verdict can supply a lesson")
            if verdict.policy_binding != self.policy.binding:
                raise MemoryConflict("verdict belongs to an old policy")
            if verdict.revision in self._excluded_revisions:
                raise MemoryIntegrityError("held-out observations cannot supply lessons")
            if verdict.value == "violation" and not rules:
                raise MemoryIntegrityError("a violation lesson must name a policy rule")
            lesson_id = str(uuid4())
            series_id, version = lesson_id, 1
            if previous_lesson_id:
                previous = self._lesson(db, previous_lesson_id)
                latest = db.execute("SELECT MAX(version) FROM memory_lessons WHERE client_id=? AND scope=? AND series_id=?",
                                    (*self._key, previous.series_id)).fetchone()[0]
                if previous.version != latest:
                    raise MemoryConflict("new versions must name the latest lesson version")
                series_id, version = previous.series_id, previous.version + 1
            body = _json({"lesson_id": lesson_id, "version": version, "policy_binding": verdict.policy_binding,
                          "scope": self.scope, "rule_ids": rules, "verdict": verdict.value,
                          "family": family, "summary": summary})
            if len(body) > MAX_BODY_CHARS:
                raise MemoryIntegrityError("lesson exceeds the body limit")
            now = _now()
            lesson = Lesson(lesson_id, series_id, version, verdict_id, verdict.policy_binding, self.scope,
                            body, body_digest(body), "draft", None, None, None, None, None, now, now, None,
                            verdict.origin)
            db.execute("INSERT INTO memory_lessons VALUES (?,?,?,?,?,?,?,?,?)",
                       (*self._key, lesson_id, verdict_id, series_id, version, "draft", verdict.policy_binding,
                        _json(lesson.as_dict())))
            self._bump(db)
            self._event(db, "lesson_drafted", actor,
                        {"lesson_id": lesson_id, "verdict_id": verdict_id, "digest": lesson.digest,
                         "version": version, "origin": lesson.origin})
            return lesson

    def preview(self, lesson_id: str) -> Lesson:
        return self.get_lesson(lesson_id)

    def approve_lesson(self, lesson_id: str, *, digest: str, actor: str) -> Lesson:
        bounded_text(actor, "actor")
        with self.store.atomic() as db:
            lesson = self._lesson(db, lesson_id)
            if lesson.state != "draft" or digest != lesson.digest:
                raise MemoryConflict("approval requires a draft and its exact preview digest")
            self._eligible_verdict(db, lesson)
            result = replace(lesson, state="approved", reviewer=actor, updated_at=_now())
            self._put_lesson(db, result)
            self._bump(db)
            self._event(db, "lesson_approved", actor,
                        {"lesson_id": lesson_id, "digest": digest, "version": lesson.version})
            return result

    def _end_lesson(self, lesson_id: str, state: str, actor: str, reason: str) -> Lesson:
        bounded_text(actor, "actor")
        bounded_text(reason, "reason", 1000)
        with self.store.atomic() as db:
            lesson = self._lesson(db, lesson_id)
            if lesson.state == state:
                return lesson
            if state == "rejected" and lesson.state != "draft":
                raise MemoryConflict("only a draft can be rejected")
            if state == "revoked" and lesson.state not in _REVOKABLE:
                raise MemoryConflict("lesson cannot be revoked from this state")
            result = replace(lesson, state=state, updated_at=_now(), last_error=reason)
            self._put_lesson(db, result)
            self._bump(db)
            self._event(db, "lesson_" + state, actor,
                        {"lesson_id": lesson_id, "digest": lesson.digest, "content_id": lesson.content_id,
                         "orphan": bool(lesson.content_id), "reason": "operator action"})
            return result

    def reject_lesson(self, lesson_id: str, *, actor: str, reason: str) -> Lesson:
        return self._end_lesson(lesson_id, "rejected", actor, reason)

    def revoke_lesson(self, lesson_id: str, *, actor: str, reason: str) -> Lesson:
        return self._end_lesson(lesson_id, "revoked", actor, reason)

    def snapshot(self, *, enabled: bool = False) -> MemorySnapshot:
        with self.store.atomic() as db:
            policy = self.policy
            revision = db.execute("SELECT revision FROM memory_meta WHERE client_id=? AND scope=?", self._key).fetchone()[0]
            lessons: list[Lesson] = []
            if enabled:
                rows = db.execute("SELECT payload FROM memory_lessons WHERE client_id=? AND scope=? "
                                  "AND state='active' AND policy_binding=? ORDER BY lesson_id",
                                  (*self._key, policy.binding))
                for row in rows:
                    lesson = Lesson(**json.loads(row["payload"]))
                    self._eligible_verdict(db, lesson)
                    if not all((lesson.content_id, lesson.node_id, lesson.remote_version, lesson.reviewer)):
                        raise MemoryIntegrityError("active lesson lacks verified publication identity")
                    lessons.append(lesson)
                    if len(lessons) > self.max_eligible:
                        raise MemoryIntegrityError("eligible lesson set exceeds configured bound")
                if len({lesson.content_id for lesson in lessons}) != len(lessons):
                    raise MemoryIntegrityError("active lessons share a remote content ID")
            return MemorySnapshot(self.store.client_id, self.scope, policy.binding,
                                  revision if enabled else None, tuple(lessons), enabled)

    def guard(self, snapshot: MemorySnapshot) -> str | None:
        """Reentrant read, suitable for the client's inside-transaction guard."""
        if snapshot.client_id != self.store.client_id or snapshot.scope != self.scope:
            return "memory snapshot belongs to a different owner/scope"
        current = self.snapshot(enabled=snapshot.enabled)
        if current != snapshot:
            return "memory snapshot changed"
        return None

    def assert_current(self, snapshot: MemorySnapshot) -> None:
        reason = self.guard(snapshot)
        if reason:
            raise MemoryStale(reason)

    @staticmethod
    def _backend(backend: MemoryBackend | None) -> MemoryBackend:
        if (backend is None or getattr(backend, "capability_verified", False) is not True
                or not getattr(backend, "capability_evidence", "")):
            raise MemoryIntegrityError("private backend read-back/version/scoping capability is not verified")
        return backend

    async def _io(self, operation: Any) -> Any:
        return await asyncio.wait_for(operation, timeout=self.request_timeout)

    @staticmethod
    def _verify_document(document: RemoteContent, lesson: Lesson, *, expected_version: str | None = None) -> None:
        if not isinstance(document, RemoteContent):
            raise MemoryIntegrityError("backend returned an untyped content result")
        bounded_text(document.version, "remote version", 128)
        if (document.node_id != lesson.node_id or document.content_id != lesson.content_id
                or not isinstance(document.text, str) or len(document.text) > MAX_BODY_CHARS
                or body_digest(document.text) != lesson.digest
                or (expected_version is not None and document.version != expected_version)):
            raise MemoryIntegrityError("remote identity, body or version differs from approved content")

    def _publication_state(self, lesson_id: str, operation_id: str | None, state: str,
                           actor: str, error: str, *, receipt: UploadReceipt | None = None) -> Lesson:
        with self.store.atomic() as db:
            lesson = self._lesson(db, lesson_id)
            expected_state = "publishing" if receipt or state == "publication_indeterminate" else "uploaded_unverified"
            if lesson.operation_id != operation_id or lesson.state != expected_state:
                if receipt:
                    self._event(db, "lesson_publication_orphaned", actor,
                                {"lesson_id": lesson_id, **receipt.as_dict(), "operation_id": operation_id})
                return lesson
            result = replace(lesson, state=state, updated_at=_now(), last_error=error or None,
                             content_id=receipt.content_id if receipt else lesson.content_id,
                             node_id=receipt.node_id if receipt else lesson.node_id)
            self._put_lesson(db, result)
            self._bump(db)
            self._event(db, "lesson_publication_" + state, actor,
                        {"lesson_id": lesson_id, "operation_id": operation_id, "content_id": result.content_id,
                         "node_id": result.node_id, "error": error or None,
                         "orphan": state == "publication_failed" and bool(result.content_id)})
            return result

    async def publish(self, lesson_id: str, backend: MemoryBackend, *, actor: str,
                      poll_interval: float = 0.2, max_polls: int = 20) -> Lesson:
        """Upload once. Known IDs resume read-back; unknown outcomes never re-upload."""
        backend = self._backend(backend)
        bounded_text(actor, "actor")
        if (not math.isfinite(poll_interval) or poll_interval < 0
                or type(max_polls) is not int or not 1 <= max_polls <= 100):
            raise ValueError("publication polling must be bounded")
        if lesson_id in self._publishing:
            raise MemoryConflict("this lesson already has an in-flight publication")
        self._publishing.add(lesson_id)
        try:
            with self.store.atomic() as db:
                lesson = self._lesson(db, lesson_id)
                self._eligible_verdict(db, lesson)
                if lesson.state == "active":
                    return lesson
                if lesson.state == "publishing":
                    lesson = replace(lesson, state="publication_indeterminate", updated_at=_now(),
                                     last_error="upload outcome requires explicit reconciliation")
                    self._put_lesson(db, lesson)
                    self._bump(db)
                    self._event(db, "lesson_publication_indeterminate", actor,
                                {"lesson_id": lesson_id, "operation_id": lesson.operation_id})
                    return lesson
                if lesson.state not in {"approved", "uploaded_unverified"}:
                    raise MemoryConflict("publication requires approval or known uploaded content")
                upload = lesson.state == "approved"
                if upload:
                    lesson = replace(lesson, state="publishing", operation_id=str(uuid4()), updated_at=_now())
                    self._put_lesson(db, lesson)
                    self._bump(db)
                    self._event(db, "lesson_publication_started", actor,
                                {"lesson_id": lesson_id, "operation_id": lesson.operation_id, "digest": lesson.digest})
            if upload:
                try:
                    receipt = await self._io(backend.upload_raw(lesson.body, f"Reviewed precedent {lesson_id} v{lesson.version}"))
                    if not isinstance(receipt, UploadReceipt):
                        raise MemoryIntegrityError("backend returned an untyped upload receipt")
                    bounded_text(receipt.content_id, "content ID")
                    bounded_text(receipt.node_id, "node ID")
                except asyncio.CancelledError:
                    self._publication_state(lesson_id, lesson.operation_id, "publication_indeterminate", actor,
                                            "upload cancelled; remote outcome unknown")
                    raise
                except Exception as exc:
                    return self._publication_state(lesson_id, lesson.operation_id, "publication_indeterminate", actor,
                                                   f"{type(exc).__name__}: upload outcome unknown")
                lesson = self._publication_state(lesson_id, lesson.operation_id, "uploaded_unverified", actor,
                                                 "", receipt=receipt)
                if lesson.state != "uploaded_unverified":
                    return lesson
            return await self._finish_publication(lesson, backend, actor, poll_interval, max_polls)
        finally:
            self._publishing.discard(lesson_id)

    async def _finish_publication(self, lesson: Lesson, backend: MemoryBackend, actor: str,
                                  poll_interval: float, max_polls: int) -> Lesson:
        assert lesson.node_id and lesson.content_id
        try:
            for attempt in range(max_polls):
                current = self.get_lesson(lesson.lesson_id)
                if current.state != "uploaded_unverified" or current.operation_id != lesson.operation_id:
                    return current
                node = await self._io(backend.node(lesson.node_id))
                current = self.get_lesson(lesson.lesson_id)
                if current.state != "uploaded_unverified" or current.operation_id != lesson.operation_id:
                    return current
                if (not isinstance(node, NodeStatus) or node.node_id != lesson.node_id
                        or node.content_id != lesson.content_id):
                    raise MemoryIntegrityError("processing node identity changed")
                if node.status == "failed":
                    raise MemoryIntegrityError("remote processing failed")
                if node.status == "completed":
                    break
                if node.status != "processing":
                    raise MemoryIntegrityError("unknown remote processing status")
                if attempt + 1 < max_polls:
                    await asyncio.sleep(poll_interval)
            else:
                return self._publication_state(lesson.lesson_id, lesson.operation_id, "uploaded_unverified", actor,
                                               "processing timeout; verification remains pending")
            document = await self._io(backend.node_content(lesson.node_id))
            self._verify_document(document, lesson, expected_version=lesson.remote_version)
        except StorageFaultError:
            raise  # Owner fault is authoritative; do not retry any local write or remote I/O.
        except MemoryIntegrityError as exc:
            return self._publication_state(lesson.lesson_id, lesson.operation_id, "publication_failed", actor, str(exc))
        except asyncio.CancelledError:
            raise  # known remote IDs are durable; the next explicit publish resumes read-back
        except Exception as exc:
            return self._publication_state(lesson.lesson_id, lesson.operation_id, "uploaded_unverified", actor,
                                           f"{type(exc).__name__}: verification remains pending")
        with self.store.atomic() as db:
            current = self._lesson(db, lesson.lesson_id)
            if (current.state != "uploaded_unverified" or current.operation_id != lesson.operation_id
                    or current.content_id != document.content_id or current.node_id != document.node_id
                    or current.digest != lesson.digest):
                self._event(db, "lesson_activation_refused", actor,
                            {"lesson_id": lesson.lesson_id, "operation_id": lesson.operation_id})
                return current
            try:
                self._eligible_verdict(db, current)
            except MemoryConflict:
                result = replace(current, state="publication_failed", updated_at=_now(),
                                 last_error="verdict or policy changed before activation")
            else:
                active_rows = db.execute("SELECT payload FROM memory_lessons WHERE client_id=? AND scope=? "
                                         "AND state='active' AND lesson_id!=?",
                                         (*self._key, current.lesson_id)).fetchall()
                collision = any(json.loads(row["payload"])["content_id"] == current.content_id
                                for row in active_rows)
                result = replace(current, state="publication_failed" if collision else "active",
                                 remote_version=document.version, updated_at=_now(),
                                 last_error="remote content belongs to another active lesson" if collision else None)
            self._put_lesson(db, result)
            self._bump(db)
            self._event(db, "lesson_activated" if result.state == "active" else "lesson_activation_refused", actor,
                        {"lesson_id": lesson.lesson_id, "operation_id": lesson.operation_id,
                         "content_id": result.content_id, "remote_version": result.remote_version,
                         "digest": result.digest, "state": result.state})
            return result

    async def reconcile(self, lesson_id: str, backend: MemoryBackend, *, node_id: str, actor: str) -> Lesson:
        backend = self._backend(backend)
        bounded_text(actor, "actor")
        bounded_text(node_id, "node ID")
        with self.store.atomic() as db:
            lesson = self._lesson(db, lesson_id)
            self._eligible_verdict(db, lesson)
            if lesson.state != "publication_indeterminate":
                raise MemoryConflict("only an indeterminate publication can be reconciled")
        document = await self._io(backend.node_content(node_id))
        if not isinstance(document, RemoteContent) or document.node_id != node_id:
            raise MemoryIntegrityError("reconciliation returned a different node")
        bounded_text(document.content_id, "content ID")
        expected = replace(lesson, node_id=node_id, content_id=document.content_id)
        self._verify_document(document, expected)
        with self.store.atomic() as db:
            current = self._lesson(db, lesson_id)
            if current.state != "publication_indeterminate" or current.operation_id != lesson.operation_id:
                raise MemoryStale("lesson changed during reconciliation")
            self._eligible_verdict(db, current)
            # The document contains a unique lesson/version ID in the exact approved body.
            collision = db.execute("SELECT lesson_id FROM memory_lessons WHERE client_id=? AND scope=? "
                                   "AND lesson_id!=? AND state='active'", (*self._key, lesson_id)).fetchall()
            if any(self._lesson(db, row["lesson_id"]).content_id == document.content_id for row in collision):
                raise MemoryIntegrityError("remote content already belongs to a different active lesson")
            current = replace(current, state="uploaded_unverified", node_id=node_id,
                              content_id=document.content_id, remote_version=document.version, updated_at=_now())
            self._put_lesson(db, current)
            self._bump(db)
            self._event(db, "lesson_publication_reconciled", actor,
                        {"lesson_id": lesson_id, "operation_id": current.operation_id,
                         "content_id": current.content_id, "remote_version": document.version})
        return await self.publish(lesson_id, backend, actor=actor)

    def abandon(self, lesson_id: str, *, actor: str, reason: str) -> Lesson:
        bounded_text(actor, "actor")
        bounded_text(reason, "reason", 1000)
        with self.store.atomic() as db:
            lesson = self._lesson(db, lesson_id)
            if lesson.state != "publication_indeterminate":
                raise MemoryConflict("only an indeterminate publication can be abandoned")
            result = replace(lesson, state="publication_failed", updated_at=_now(), last_error=reason)
            self._put_lesson(db, result)
            self._bump(db)
            self._event(db, "lesson_publication_abandoned", actor,
                        {"lesson_id": lesson_id, "operation_id": lesson.operation_id, "possible_orphan": True})
            return result

    async def retrieve(self, query: str, backend: MemoryBackend | None = None, *,
                       enabled: bool = False, top_k: int = 3) -> RetrievedMemory:
        """Capture before I/O, validate scoped sources, then recheck the same snapshot."""
        if type(top_k) is not int or not 1 <= top_k <= 20:
            raise ValueError("top_k must be between 1 and 20")
        snapshot = self.snapshot(enabled=enabled)
        if not enabled:
            return RetrievedMemory(snapshot, (), (), "disabled")
        ids = tuple(lesson.content_id for lesson in snapshot.lessons)
        if not ids:
            return RetrievedMemory(snapshot, (), (), "none_eligible")
        backend = self._backend(backend)
        if not isinstance(query, str) or not query.strip():
            raise MemoryIntegrityError("retrieval query must contain text")
        response = await self._io(backend.search_context(query[:2000], content_ids=ids, top_k=top_k))
        self.assert_current(snapshot)
        if not isinstance(response, (tuple, list)) or len(response) > top_k:
            raise MemoryIntegrityError("search returned an invalid or oversized passage set")
        by_id = {lesson.content_id: lesson for lesson in snapshot.lessons}
        documents: dict[str, RemoteContent] = {}
        passages: list[RetrievedPrecedent] = []
        for item in response:
            if not isinstance(item, SearchPassage) or item.content_id not in by_id:
                raise MemoryIntegrityError("search returned content outside the explicit eligible scope")
            lesson = by_id[item.content_id]
            if (not isinstance(item.text, str) or not item.text.strip() or len(item.text) > MAX_BODY_CHARS
                    or normalize_passage(item.text) not in normalize_passage(lesson.body)
                    or (item.version is not None and item.version != lesson.remote_version)):
                raise MemoryIntegrityError("search passage does not match approved content/version")
            if item.content_id not in documents:
                document = await self._io(backend.node_content(lesson.node_id))
                self.assert_current(snapshot)
                self._verify_document(document, lesson, expected_version=lesson.remote_version)
                documents[item.content_id] = document
            passages.append(RetrievedPrecedent(lesson.lesson_id, lesson.version, lesson.digest,
                                               lesson.content_id, lesson.remote_version, item.text,
                                               item.source_version_id))
        self.assert_current(snapshot)
        return RetrievedMemory(snapshot, tuple(passages), ids, "returned" if passages else "none_returned")
