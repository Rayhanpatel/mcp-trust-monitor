"""Durable, revision-bound trust state for one managed client.

Every transition and its local audit event commit in one SQLite transaction
(REQ-TRU-04). Authorizing transitions must name the exact observed revision and,
optionally, the generation they were decided against (REQ-TRU-02). Restrictive
transitions fail closed.

Each audit event and each accepted observation also writes an outbox row in the
same transaction (REQ-AUD-01). Delivery to ClickHouse happens later, outside any
enforcement transaction (see `history.py`), so an analytics outage cannot erase or
delay a quarantine. Event IDs are generated once and never change on redelivery.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from contextlib import contextmanager
from urllib.parse import quote

from .revision import tool_metadata, server_revision


class TrustState(str, Enum):
    UNREVIEWED = "unreviewed"
    APPROVED = "approved"
    PENDING_REVIEW = "pending_review"
    QUARANTINED = "quarantined"


class TrustError(Exception):
    """A requested transition is not permitted."""


class StorageFaultError(TrustError):
    """Authoritative storage is unusable; this owner must close before recovery."""


class SchemaCompatibilityError(TrustError):
    """A database was produced by an unsupported newer schema."""


class StaleDecisionError(TrustError):
    """A decision no longer matches the server's current revision, policy, or generation."""


class ObservationRequiredError(TrustError):
    """Approval or restore attempted before a successful observation followed a failure."""


@dataclass(frozen=True)
class TrustRecord:
    client_id: str
    server_id: str
    state: TrustState
    observed_revision: str | None
    observed_tools: tuple[dict[str, Any], ...]
    approved_revision: str | None
    approved_policy_revision: str | None
    generation: int
    updated_at: str
    # Set by an observation failure; cleared only by a later successful observation.
    observation_failed_at: str | None = None
    # `live` or `synthetic_fixture`, from the last accepted observation (REQ-REV-03).
    origin: str | None = None
    launch_identity: str | None = None
    approved_launch_identity: str | None = None

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(tool["name"] for tool in self.observed_tools)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_records (
    client_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    state TEXT NOT NULL
        CHECK (state IN ('unreviewed', 'approved', 'pending_review', 'quarantined')),
    observed_revision TEXT,
    observed_tools TEXT NOT NULL DEFAULT '[]',
    approved_revision TEXT,
    approved_policy_revision TEXT,
    generation INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    observation_failed_at TEXT,
    origin TEXT,
    PRIMARY KEY (client_id, server_id)
);
CREATE TABLE IF NOT EXISTS trust_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    client_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT,
    revision TEXT,
    policy_revision TEXT,
    generation INTEGER,
    detail TEXT NOT NULL DEFAULT '{}',
    run_id TEXT,
    origin TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    run_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    server_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    generation INTEGER NOT NULL,
    endpoint TEXT,
    transport TEXT,
    server_name TEXT,
    server_version TEXT,
    protocol_version TEXT,
    origin TEXT NOT NULL,
    raw_metadata TEXT NOT NULL,
    reviewed_metadata TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    delivered_at TEXT
);
CREATE TABLE IF NOT EXISTS policy_activations (
    client_id TEXT PRIMARY KEY,
    policy_binding TEXT NOT NULL,
    activated_at TEXT NOT NULL
);
"""

# Columns added after M1. Stores created by M1 gain them on open; no row is rewritten,
# so trust state and the observation-recovery requirement carry over unchanged.
_MIGRATIONS = (
    ("trust_records", "observation_failed_at", "TEXT"),
    ("trust_records", "origin", "TEXT"),
    ("trust_events", "run_id", "TEXT"),
    ("trust_events", "origin", "TEXT"),
)
_MIGRATIONS += (("trust_records", "launch_identity", "TEXT"),
                ("trust_records", "approved_launch_identity", "TEXT"))
# Version 4 adds `policy_activations`, which carries authorization meaning (REQ-TRU-02/03):
# it is created with the version stamp in one transaction, and binaries that only know
# version 3 refuse an upgraded store instead of activating a policy without recording it.
SCHEMA_VERSION = 4


def inspect_schema(path: Path) -> int:
    """Read only, before journal changes, migrations, or owner markers."""
    if not Path(path).exists():
        return 0
    db = sqlite3.connect("file:" + quote(str(Path(path).resolve())) + "?mode=ro", uri=True)
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise SchemaCompatibilityError(f"unsupported schema {version}; maximum {SCHEMA_VERSION}")
        return version
    finally:
        db.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class HardDenyOutcome:
    """Result of applying one hard-deny assessment: applied, already_quarantined, or stale."""

    status: str
    record: TrustRecord | None
    reason: str | None = None
    requested_event_id: str | None = None
    applied_event_id: str | None = None


class TrustStore:
    def __init__(
        self, path: Path, client_id: str = "demo-client", *, run_id: str | None = None,
        strict_integrity: bool = False,
    ) -> None:
        self.path = Path(path)
        self.client_id = client_id
        self.run_id = run_id or f"run-{uuid.uuid4()}"
        self.strict_integrity = strict_integrity
        self.faulted = False
        self.on_fault: Callable[[BaseException], None] | None = None
        inspect_schema(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = sqlite3.connect(self.path, isolation_level=None, timeout=10.0)
        raw.row_factory = sqlite3.Row
        self._db = _GuardedConnection(raw, self)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            with self.atomic():
                for statement in _SCHEMA.split(";"):
                    if statement.strip():
                        self._db.execute(statement)
                for table, column, declaration in _MIGRATIONS:
                    columns = {row["name"] for row in self._db.execute(f"PRAGMA table_info({table})")}
                    if column not in columns:
                        self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
                self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        except BaseException:
            raw.close()
            raise

    def check_health(self) -> None:
        if self.faulted:
            raise StorageFaultError("storage_faulted; close, repair storage, and reopen")

    def _fault(self, exc: BaseException) -> None:
        self.faulted = True
        if self.on_fault is not None:
            self.on_fault(exc)

    @contextmanager
    def atomic(self):
        """Yield the shared connection; nested operations use atomic SAVEPOINTs."""
        self.check_health()
        nested = self._db.in_transaction
        name = "s_" + uuid.uuid4().hex
        self._db.execute(f"SAVEPOINT {name}" if nested else "BEGIN IMMEDIATE")
        try:
            yield self._db
            self._db.execute(f"RELEASE SAVEPOINT {name}" if nested else "COMMIT")
        except BaseException as exc:
            if isinstance(exc, sqlite3.Error):
                self._fault(exc)
            # Roll back even after the health latch was set. Never commit a partial action.
            raw = self._db.raw
            try:
                in_transaction = raw.in_transaction
            except sqlite3.Error:
                in_transaction = False
            if in_transaction:
                try:
                    raw.execute(f"ROLLBACK TO SAVEPOINT {name}" if nested else "ROLLBACK")
                    if nested:
                        raw.execute(f"RELEASE SAVEPOINT {name}")
                except sqlite3.Error:
                    pass
            raise

    def emit_event_in_transaction(self, db, server_id, event_type, actor, detail) -> str:
        if db is not self._db or not self._db.in_transaction:
            raise TrustError("event requires this store's active transaction")
        return self._insert_event(server_id=server_id or "@memory", event_type=event_type,
                                  actor=actor, detail=detail)

    def ensure_identity(self, server_id: str, identity: str) -> None:
        with self.atomic():
            current = self.get(server_id)
            if current is not None and current.launch_identity != identity:
                state = TrustState.PENDING_REVIEW if current.state is TrustState.APPROVED else current.state
                self._update(current, state=state, launch_identity=identity,
                             observation_failed_at=_now())
                new = self._require(server_id)
                self._event(new, "launch_identity_changed", "owner", current.state, new.state,
                            new.observed_revision, detail={"launch_identity": identity})

    def recover_owner(self) -> None:
        """Unclean-owner recovery for the whole state directory (REQ-ENF-07).

        The unclean marker belongs to the directory, not to a client ID, so every trust
        record in this database is recovered, whichever client opens it next: approved
        records move to pending review, quarantine is preserved, and every record needs
        a successful observation and explicit approval again. A later clean shutdown
        under any client ID therefore cannot discard another client's requirement.
        """
        with self.atomic():
            rows = self._db.execute(
                "SELECT * FROM trust_records ORDER BY client_id, server_id").fetchall()
            for current in [self._decode_record(row) for row in rows]:
                state = TrustState.PENDING_REVIEW if current.state is TrustState.APPROVED else current.state
                self._update(current, state=state, observation_failed_at=_now())
                new = self._require_scoped(current.client_id, current.server_id)
                self._event(new, "owner_recovered", "owner", current.state, new.state,
                            new.observed_revision, detail={"observation_required": True})

    def invalidate_policy(self, policy_binding: str) -> None:
        """Activate `policy_binding` for this client scope (REQ-TRU-02, REQ-TRU-03).

        The owner passes its decision binding: the policy binding plus the detector
        binding (REQ-DEC-06), so a detector-only change is a genuine change here.

        Approvals bound to another policy move to pending review. On a genuine policy
        change, every other record's generation also advances, with its state unchanged
        (quarantine stays quarantined) and a `decision_context_invalidated` event, so an
        approve or restore input prepared before the change is stale whatever the
        record's state. A genuine change is a binding different from the last binding
        activated for this client scope, in this owner lifetime or an earlier one.
        Reactivating the same binding, including the first activation on an owner
        reopen with an unchanged policy, changes no record. A store that has records but
        never recorded an activation (written before activations were recorded) cannot
        show its previous policy, so its first activation counts as a change: fail closed.
        """
        with self.atomic():
            records = self.records()
            previous_binding = self._last_activated_binding()
            changed = previous_binding != policy_binding and (
                previous_binding is not None or bool(records))
            for current in records:
                if current.state is TrustState.APPROVED and current.approved_policy_revision != policy_binding:
                    self.invalidate(current.server_id, actor="owner", reason="policy reloaded")
                elif changed:
                    # The state is unchanged; only decision inputs prepared before the
                    # change become stale (their generation no longer matches).
                    self._update(current)
                    new = self._require(current.server_id)
                    self._event(new, "decision_context_invalidated", "owner", current.state,
                                new.state, new.observed_revision, policy_revision=policy_binding,
                                detail={"reason": "policy_changed",
                                        "previous_policy_binding": previous_binding,
                                        "policy_binding": policy_binding})
                if self._policy_marker(current.server_id) == policy_binding:
                    continue
                self._insert_event(server_id=current.server_id, event_type="policy_reloaded",
                                   actor="owner", detail={"policy_binding": policy_binding})
            self._db.execute(
                "INSERT INTO policy_activations (client_id, policy_binding, activated_at)"
                " VALUES (?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET"
                " policy_binding = excluded.policy_binding, activated_at = excluded.activated_at"
                " WHERE policy_activations.policy_binding != excluded.policy_binding",
                (self.client_id, policy_binding, _now()))

    def _last_activated_binding(self) -> str | None:
        """The binding last activated for this client scope, if it is known.

        Stores written before activations were recorded fall back to the newest
        per-server `policy_reloaded` marker: every activation marks every existing
        record, so the newest marker is the last activation that had any record.
        """
        row = self._db.execute("SELECT policy_binding FROM policy_activations WHERE client_id = ?",
                               (self.client_id,)).fetchone()
        marker = self._policy_marker(None)
        if row is not None and marker is not None and marker != row["policy_binding"]:
            # Every activation that records a row also marks every record with the same
            # binding, so a newer marker that disagrees can only come from a writer that did
            # not record activations. Treat it as the last activation, so a change back to
            # the row's binding still counts as genuine and stales prepared decisions.
            return marker
        if row is not None:
            return row["policy_binding"]
        return marker

    def _policy_marker(self, server_id: str | None) -> str | None:
        query = ("SELECT detail FROM trust_events WHERE client_id=? AND event_type='policy_reloaded'"
                 " AND actor='owner'")
        params: list[Any] = [self.client_id]
        if server_id is not None:
            query += " AND server_id=?"
            params.append(server_id)
        previous = self._db.execute(query + " ORDER BY seq DESC LIMIT 1", params).fetchone()
        if previous is None:
            return None
        try:
            binding = json.loads(previous["detail"]).get("policy_binding")
        except (ValueError, TypeError, AttributeError) as exc:
            self._fault(exc)
            raise StorageFaultError("invalid authoritative policy activation event") from exc
        return binding if isinstance(binding, str) else None

    @classmethod
    def open_readonly(cls, path: Path, client_id: str = "default"):
        inspect_schema(path)
        raw = sqlite3.connect("file:" + quote(str(Path(path).resolve())) + "?mode=ro", uri=True)
        raw.row_factory = sqlite3.Row
        result = cls.__new__(cls)
        result.path, result.client_id = Path(path), client_id
        result.run_id = "readonly"
        result.strict_integrity = False
        result.faulted, result.on_fault = False, None
        result._db = _GuardedConnection(raw, result)
        return result

    def close(self) -> None:
        self._db.close()

    # Reads

    def get(self, server_id: str) -> TrustRecord | None:
        row = self._db.execute(
            "SELECT * FROM trust_records WHERE client_id = ? AND server_id = ?",
            (self.client_id, server_id),
        ).fetchone()
        return self._decode_record(row) if row else None

    def records(self) -> list[TrustRecord]:
        rows = self._db.execute(
            "SELECT * FROM trust_records WHERE client_id = ? ORDER BY server_id",
            (self.client_id,),
        ).fetchall()
        return [self._decode_record(row) for row in rows]

    def _decode_record(self, row):
        try:
            record = _record(row)
            if not isinstance(record.generation, int) or record.generation < 1:
                raise ValueError("invalid generation")
            for tool in record.observed_tools:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    raise ValueError("invalid stored tools")
            if self.strict_integrity and record.observed_revision is not None:
                if server_revision(record.observed_tools) != record.observed_revision:
                    raise ValueError('stored metadata does not match observed revision')
            return record
        except (ValueError, TypeError, KeyError) as exc:
            self._fault(exc)
            raise StorageFaultError("invalid authoritative trust record") from exc

    def events(self, server_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM trust_events WHERE client_id = ?"
        params: list[Any] = [self.client_id]
        if server_id is not None:
            query += " AND server_id = ?"
            params.append(server_id)
        rows = self._db.execute(query + " ORDER BY seq", params).fetchall()
        return [{**dict(row), "detail": json.loads(row["detail"])} for row in rows]

    # Transitions

    def record_observation(
        self,
        server_id: str,
        revision: str,
        tools: Iterable[Mapping[str, Any]],
        *,
        actor: str = "managed-client",
        provenance: Mapping[str, Any] | None = None,
    ) -> TrustRecord:
        """Record a complete tools/list observation (REQ-TRU-01, REQ-TRU-03, REQ-REV-03).

        `provenance` carries the endpoint identity, transport, server version, and
        origin. Every accepted observation is retained with its raw metadata.
        """
        tools_json = json.dumps([tool_metadata(tool) for tool in tools], sort_keys=True)
        provenance = dict(provenance or {})
        origin = provenance.get("origin")
        with self._transaction():
            current = self.get(server_id)
            if current is None:
                self._db.execute(
                    "INSERT INTO trust_records (client_id, server_id, state, observed_revision,"
                    " observed_tools, generation, updated_at, origin, launch_identity)"
                    " VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
                    (self.client_id, server_id, TrustState.UNREVIEWED.value, revision,
                     tools_json, _now(), origin, provenance.get("launch_identity")),
                )
                new = self._require(server_id)
                self._event(new, "observed_new", actor, None, new.state, revision)
                self._observation(new, tools_json, provenance)
                return new
            recovering = current.observation_failed_at is not None
            if current.observed_revision == revision and not recovering:
                self._observation(current, tools_json, provenance)
                return current
            # Metadata changed, or this observation follows a failure. Approval is never
            # restored here and quarantine is never lifted; a change invalidates approval.
            next_state = (
                TrustState.PENDING_REVIEW
                if current.state is TrustState.APPROVED
                else current.state
            )
            self._update(current, state=next_state, observed_revision=revision,
                         observed_tools=tools_json, observation_failed_at=None,
                         origin=origin or current.origin)
            new = self._require(server_id)
            self._observation(new, tools_json, provenance)
            if recovering:
                # Recovery evidence (REQ-REV-02): approval becomes possible again, not automatic.
                self._event(new, "observation_recovered", actor, current.state, new.state,
                            revision, detail={"failed_at": current.observation_failed_at,
                                              "unchanged": current.observed_revision == revision})
            if current.observed_revision != revision:
                self._event(new, "revision_changed", actor, current.state, new.state, revision,
                            detail={"previous_revision": current.observed_revision})
            return new

    def approve(
        self,
        server_id: str,
        *,
        revision: str,
        policy_revision: str,
        expected_generation: int | None,
        actor: str,
        restore: bool = False,
    ) -> TrustRecord:
        """Explicit operator approval of one exact revision under one policy revision.

        Refused (as is restore) while an observation failure has not been followed
        by a complete successful observation (REQ-REV-02).
        """
        with self._transaction():
            current = self.get(server_id)
            if current is None or current.observed_revision is None:
                raise StaleDecisionError(f"{server_id} has no observed revision to approve")
            if current.observation_failed_at is not None:
                raise ObservationRequiredError(
                    f"{server_id} had an observation failure at {current.observation_failed_at};"
                    " observe it successfully before approving or restoring"
                )
            if (
                current.state is TrustState.APPROVED
                and current.approved_revision == revision
                and current.approved_policy_revision == policy_revision
            ):
                return current  # Duplicate decision: no repeated side effects (REQ-TRU-06).
            if current.state is TrustState.QUARANTINED and not restore:
                raise TrustError(
                    f"{server_id} is quarantined; lifting it requires an explicit restore"
                )
            if current.observed_revision != revision:
                raise StaleDecisionError(
                    f"decision names revision {revision} but {server_id} is now at "
                    f"{current.observed_revision}"
                )
            if expected_generation is not None and expected_generation != current.generation:
                raise StaleDecisionError(
                    f"decision was made at generation {expected_generation} but {server_id} "
                    f"is now at generation {current.generation}"
                )
            self._update(current, state=TrustState.APPROVED, approved_revision=revision,
                         approved_policy_revision=policy_revision,
                         approved_launch_identity=current.launch_identity)
            new = self._require(server_id)
            event_type = "restored" if current.state is TrustState.QUARANTINED else "approved"
            self._event(new, event_type, actor, current.state, new.state, revision,
                        policy_revision=policy_revision)
            return new

    def quarantine(self, server_id: str, *, actor: str, reason: str) -> TrustRecord:
        """Server-scoped quarantine. Restrictive, so it applies regardless of revision."""
        with self._transaction():
            current = self.get(server_id)
            if current is None:
                self._db.execute(
                    "INSERT INTO trust_records (client_id, server_id, state, generation,"
                    " updated_at) VALUES (?, ?, ?, 1, ?)",
                    (self.client_id, server_id, TrustState.QUARANTINED.value, _now()),
                )
                new = self._require(server_id)
                self._event(new, "quarantined", actor, None, new.state, None,
                            detail={"reason": reason})
                return new
            if current.state is TrustState.QUARANTINED:
                return current
            self._update(current, state=TrustState.QUARANTINED)
            new = self._require(server_id)
            self._event(new, "quarantined", actor, current.state, new.state,
                        current.observed_revision, detail={"reason": reason})
            return new

    def record_observation_failure(
        self, server_id: str, *, actor: str, error: str
    ) -> TrustRecord | None:
        """A connection, initialization, or tools/list failure (REQ-REV-02).

        In one transaction: an approved server moves to pending review,
        `observation_failed_at` is set, the generation is bumped, and
        `observation_failed` is recorded. Quarantine and other states are preserved.
        Every session of this managed client then blocks, because they all authorize
        against this record, and approve/restore are refused until a later
        successful observation clears `observation_failed_at`.
        """
        detail = {"error": error[:500]}
        with self._transaction():
            current = self.get(server_id)
            if current is None:
                self._insert_event(server_id=server_id, event_type="observation_failed",
                                   actor=actor, detail=detail)
                return None
            next_state = (
                TrustState.PENDING_REVIEW
                if current.state is TrustState.APPROVED
                else current.state
            )
            self._update(current, state=next_state, observation_failed_at=_now())
            new = self._require(server_id)
            self._event(new, "observation_failed", actor, current.state, new.state,
                        current.observed_revision, detail=detail)
            return new

    def invalidate(self, server_id: str, *, actor: str, reason: str) -> TrustRecord:
        """Move an approved server back to pending review."""
        with self._transaction():
            current = self._require(server_id)
            if current.state is not TrustState.APPROVED:
                return current
            self._update(current, state=TrustState.PENDING_REVIEW)
            new = self._require(server_id)
            self._event(new, "approval_invalidated", actor, current.state, new.state,
                        current.observed_revision, detail={"reason": reason})
            return new

    def record_event(
        self, server_id: str, event_type: str, *, actor: str, detail: Mapping[str, Any]
    ) -> None:
        """Append an event that does not change trust state, such as a blocked call."""
        with self._transaction():
            record = self.get(server_id)
            state = record.state.value if record else None
            self._insert_event(
                server_id=server_id, event_type=event_type, actor=actor, from_state=state,
                to_state=state, revision=record.observed_revision if record else None,
                policy_revision=record.approved_policy_revision if record else None,
                generation=record.generation if record else None,
                origin=record.origin if record else None, detail=detail,
            )

    def apply_hard_deny(
        self,
        server_id: str,
        *,
        revision: str,
        generation: int,
        policy_revision: str,
        active_policy_revision: str,
        detection: Mapping[str, Any],
        actor: str = "hard-deny-detector",
        context_guard: Callable[[], str | None] | None = None,
    ) -> HardDenyOutcome:
        """Apply a deterministic hard-deny match (REQ-DEC-01), atomically and only if current.

        The match is applied only when the assessed revision, generation, and policy
        revision are all still current. Otherwise it is recorded as
        `assessment_stale` and nothing changes; the caller obtains a new assessment.
        `quarantine_requested` and `quarantine_applied` are distinct records
        (REQ-AUD-02); a duplicate request on a quarantined server changes nothing.
        """
        detail = {"assessed_revision": revision, "assessed_generation": generation,
                  "assessed_policy_revision": policy_revision, **dict(detection)}
        with self._transaction():
            current = self.get(server_id)
            if current is None:
                stale = "no trust record"
            elif current.observed_revision != revision:
                stale = f"revision is now {current.observed_revision}"
            elif current.generation != generation:
                stale = f"generation is now {current.generation}"
            elif policy_revision != active_policy_revision:
                stale = "active policy revision changed"
            else:
                stale = context_guard() if context_guard is not None else None
            if stale is not None:
                state = current.state if current else None
                self._insert_event(
                    server_id=server_id, event_type="assessment_stale", actor=actor,
                    from_state=state.value if state else None,
                    to_state=state.value if state else None,
                    revision=current.observed_revision if current else None,
                    policy_revision=policy_revision,
                    generation=current.generation if current else None,
                    origin=current.origin if current else None,
                    detail={**detail, "reason": stale})
                return HardDenyOutcome("stale", current, stale)
            assert current is not None
            requested = self._event(current, "quarantine_requested", actor, current.state,
                                    current.state, revision, policy_revision=policy_revision,
                                    detail=detail)
            if current.state is TrustState.QUARANTINED:
                return HardDenyOutcome("already_quarantined", current,
                                       requested_event_id=requested)
            self._update(current, state=TrustState.QUARANTINED)
            new = self._require(server_id)
            applied = self._event(new, "quarantine_applied", actor, current.state, new.state,
                                  revision, policy_revision=policy_revision,
                                  detail={"policy_ids": list(detection.get("policy_ids", [])),
                                          "assessed_generation": generation,
                                          "quarantine_requested_event_id": requested})
            return HardDenyOutcome("applied", new, requested_event_id=requested,
                                   applied_event_id=applied)

    def record_assessment_if_current(self, server_id: str, *, revision: str, generation: int,
                                     policy_revision: str, active_policy_revision: str,
                                     detail: Mapping[str, Any], actor: str = "model-reviewer",
                                     context_guard: Callable[[], str | None] | None = None):
        with self.atomic():
            current = self.get(server_id)
            stale = ("revision or generation changed" if current is None or
                     current.observed_revision != revision or current.generation != generation
                     else "policy changed" if policy_revision != active_policy_revision else None)
            if stale is None and context_guard is not None:
                stale = context_guard()
            event_id = self._insert_event(
                server_id=server_id, event_type="assessment_stale" if stale else ("hard_deny_scan_clean" if actor == "hard-deny-detector" else "model_assessment_recorded"),
                actor=actor, revision=revision, generation=generation, policy_revision=policy_revision,
                detail={**dict(detail), **({"reason": stale} if stale else {})})
            return AssessmentOutcome("stale" if stale else "recorded", event_id, stale)

    # Outbox (REQ-AUD-01)

    def pending_outbox(self, limit: int = 500) -> list[dict[str, Any]]:
        """Pending rows in commit order; `seq` is the local order, sent as a column."""
        rows = self._db.execute(
            "SELECT seq, event_id, payload, attempts FROM outbox WHERE status = 'pending'"
            " ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [{"event_id": row["event_id"],
                 "payload": {**json.loads(row["payload"]), "seq": row["seq"]},
                 "attempts": row["attempts"]} for row in rows]

    def delivered_payloads(self, limit: int) -> list[dict[str, Any]]:
        rows = self._db.execute(
            "SELECT seq, payload FROM outbox WHERE status = 'delivered' ORDER BY seq LIMIT ?",
            (limit,)).fetchall()
        return [{**json.loads(row["payload"]), "seq": row["seq"]} for row in rows]

    def mark_delivered(self, event_ids: Iterable[str]) -> None:
        with self._transaction():
            self._db.executemany(
                "UPDATE outbox SET status = 'delivered', delivered_at = ?, last_error = NULL"
                " WHERE event_id = ?", [(_now(), event_id) for event_id in event_ids])

    def mark_delivery_failed(self, event_ids: Iterable[str], error: str) -> None:
        with self._transaction():
            self._db.executemany(
                "UPDATE outbox SET attempts = attempts + 1, last_error = ?"
                " WHERE event_id = ? AND status = 'pending'",
                [(error[:500], event_id) for event_id in event_ids])

    def outbox_status(self) -> dict[str, Any]:
        counts = {row["status"]: row["n"] for row in self._db.execute(
            "SELECT status, count(*) AS n FROM outbox GROUP BY status")}
        error = self._db.execute(
            "SELECT last_error FROM outbox WHERE status = 'pending' AND last_error IS NOT NULL"
            " ORDER BY seq DESC LIMIT 1").fetchone()
        return {"pending": counts.get("pending", 0), "delivered": counts.get("delivered", 0),
                "last_error": error["last_error"] if error else None}

    def reviewed_tools_for_revision(
        self, server_id: str, revision: str
    ) -> tuple[dict[str, Any], ...] | None:
        """The reviewed metadata recorded for one revision, if it was ever observed."""
        row = self._db.execute(
            "SELECT reviewed_metadata FROM observations WHERE client_id = ? AND server_id = ?"
            " AND revision = ? ORDER BY ts DESC LIMIT 1",
            (self.client_id, server_id, revision)).fetchone()
        return tuple(json.loads(row["reviewed_metadata"])) if row else None

    def observation(self, observation_id: str) -> dict[str, Any] | None:
        """One retained observation of this client scope, by ID."""
        row = self._db.execute("SELECT * FROM observations WHERE client_id = ? AND observation_id = ?",
                               (self.client_id, observation_id)).fetchone()
        return dict(row) if row else None

    def observations(self, server_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM observations WHERE client_id = ?"
        params: list[Any] = [self.client_id]
        if server_id is not None:
            query += " AND server_id = ?"
            params.append(server_id)
        return [dict(row) for row in self._db.execute(query + " ORDER BY ts", params)]

    # Internals

    def _transaction(self):
        return self.atomic()

    def _require(self, server_id: str) -> TrustRecord:
        record = self.get(server_id)
        if record is None:
            raise TrustError(f"no trust record for {server_id}")
        return record

    def _require_scoped(self, client_id: str, server_id: str) -> TrustRecord:
        """A record of any client scope in this database (directory-wide recovery)."""
        row = self._db.execute(
            "SELECT * FROM trust_records WHERE client_id = ? AND server_id = ?",
            (client_id, server_id)).fetchone()
        if row is None:
            raise TrustError(f"no trust record for {client_id}/{server_id}")
        return self._decode_record(row)

    def _update(self, current: TrustRecord, **changes: Any) -> None:
        values = {
            "state": current.state.value,
            "observed_revision": current.observed_revision,
            "observed_tools": json.dumps(list(current.observed_tools), sort_keys=True),
            "approved_revision": current.approved_revision,
            "approved_policy_revision": current.approved_policy_revision,
            "observation_failed_at": current.observation_failed_at,
            "origin": current.origin,
            "launch_identity": current.launch_identity,
            "approved_launch_identity": current.approved_launch_identity,
        }
        for key, value in changes.items():
            values[key] = value.value if isinstance(value, TrustState) else value
        cursor = self._db.execute(
            "UPDATE trust_records SET state = ?, observed_revision = ?, observed_tools = ?,"
            " approved_revision = ?, approved_policy_revision = ?, observation_failed_at = ?,"
            " origin = ?, launch_identity = ?, approved_launch_identity = ?, generation = ?, updated_at = ? WHERE client_id = ? AND server_id = ?"
            " AND generation = ?",
            (values["state"], values["observed_revision"], values["observed_tools"],
             values["approved_revision"], values["approved_policy_revision"],
             values["observation_failed_at"], values["origin"], values["launch_identity"],
             values["approved_launch_identity"], current.generation + 1, _now(),
             current.client_id, current.server_id, current.generation),
        )
        if cursor.rowcount != 1:
            raise StaleDecisionError(f"{current.server_id} changed during the transition")

    def _event(
        self,
        record: TrustRecord,
        event_type: str,
        actor: str,
        from_state: TrustState | None,
        to_state: TrustState | None,
        revision: str | None,
        *,
        policy_revision: str | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> str:
        return self._insert_event(
            server_id=record.server_id, event_type=event_type, actor=actor,
            from_state=from_state.value if from_state else None,
            to_state=to_state.value if to_state else None, revision=revision,
            policy_revision=policy_revision, generation=record.generation,
            origin=record.origin, detail=detail or {}, client_id=record.client_id,
        )

    def _insert_event(self, *, server_id: str, event_type: str, actor: str,
                      from_state: str | None = None, to_state: str | None = None,
                      revision: str | None = None, policy_revision: str | None = None,
                      generation: int | None = None, origin: str | None = None,
                      detail: Mapping[str, Any], client_id: str | None = None) -> str:
        """Insert one audit event and its outbox row; return the stable event ID.
        The caller holds the transaction. Events belong to the record's client scope."""
        row = {
            "event_id": str(uuid.uuid4()), "run_id": self.run_id, "ts": _now(),
            "client_id": client_id or self.client_id, "server_id": server_id,
            "event_type": event_type,
            "actor": actor, "from_state": from_state, "to_state": to_state,
            "revision": revision, "policy_revision": policy_revision,
            "generation": generation, "origin": origin,
            "detail": json.dumps(dict(detail), sort_keys=True),
        }
        self._db.execute(
            "INSERT INTO trust_events (event_id, ts, client_id, server_id, event_type, actor,"
            " from_state, to_state, revision, policy_revision, generation, detail, run_id,"
            " origin) VALUES (:event_id, :ts, :client_id, :server_id, :event_type, :actor,"
            " :from_state, :to_state, :revision, :policy_revision, :generation, :detail,"
            " :run_id, :origin)", row)
        self._enqueue(row)
        return row["event_id"]

    def _observation(self, record: TrustRecord, tools_json: str,
                     provenance: Mapping[str, Any]) -> str:
        """Retain one accepted observation with provenance (REQ-REV-03); return its ID.

        The caller holds the transaction. `raw_metadata` is the complete tool list as
        received (already JSON-serializable); `reviewed_metadata` is the digested subset.
        Never given authentication headers, environment, or credential-bearing URLs.
        """
        row = {
            "observation_id": str(uuid.uuid4()), "ts": _now(), "run_id": self.run_id,
            "client_id": self.client_id, "server_id": record.server_id,
            "revision": record.observed_revision, "generation": record.generation,
            "endpoint": provenance.get("endpoint"), "transport": provenance.get("transport"),
            "server_name": provenance.get("server_name"),
            "server_version": provenance.get("server_version"),
            "protocol_version": provenance.get("protocol_version"),
            "origin": provenance.get("origin") or "unrecorded",
            "raw_metadata": provenance.get("raw_tools_json") or tools_json,
            "reviewed_metadata": tools_json,
        }
        self._db.execute(
            "INSERT INTO observations (observation_id, ts, run_id, client_id, server_id,"
            " revision, generation, endpoint, transport, server_name, server_version,"
            " protocol_version, origin, raw_metadata, reviewed_metadata)"
            " VALUES (:observation_id, :ts, :run_id, :client_id, :server_id, :revision,"
            " :generation, :endpoint, :transport, :server_name, :server_version,"
            " :protocol_version, :origin, :raw_metadata, :reviewed_metadata)", row)
        self._enqueue({
            "event_id": row["observation_id"], "run_id": self.run_id, "ts": row["ts"],
            "client_id": self.client_id, "server_id": record.server_id,
            "event_type": "observation_recorded", "actor": "observer",
            "from_state": record.state.value, "to_state": record.state.value,
            "revision": record.observed_revision, "policy_revision": None,
            "generation": record.generation, "origin": row["origin"],
            "detail": json.dumps({k: row[k] for k in (
                "observation_id", "endpoint", "transport", "server_name", "server_version",
                "protocol_version", "raw_metadata")}, sort_keys=True),
        })
        return row["observation_id"]

    def _enqueue(self, payload: Mapping[str, Any]) -> None:
        self._db.execute(
            "INSERT INTO outbox (event_id, created_at, payload) VALUES (?, ?, ?)",
            (payload["event_id"], _now(), json.dumps(dict(payload), sort_keys=True)))


class _Transaction:
    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    def __enter__(self) -> None:
        self._db.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type: Any, *_: Any) -> None:
        self._db.execute("ROLLBACK" if exc_type else "COMMIT")


def _record(row: sqlite3.Row) -> TrustRecord:
    return TrustRecord(
        client_id=row["client_id"],
        server_id=row["server_id"],
        state=TrustState(row["state"]),
        observed_revision=row["observed_revision"],
        observed_tools=tuple(json.loads(row["observed_tools"])),
        approved_revision=row["approved_revision"],
        approved_policy_revision=row["approved_policy_revision"],
        generation=row["generation"],
        updated_at=row["updated_at"],
        observation_failed_at=row["observation_failed_at"] if "observation_failed_at" in row.keys() else None,
        origin=row["origin"] if "origin" in row.keys() else None,
        launch_identity=row["launch_identity"] if "launch_identity" in row.keys() else None,
        approved_launch_identity=row["approved_launch_identity"] if "approved_launch_identity" in row.keys() else None,
    )


@dataclass(frozen=True)
class AssessmentOutcome:
    status: str
    event_id: str
    reason: str | None = None


class _GuardedConnection:
    """Latch SQL failures for all paths, including additive registries and reads."""
    def __init__(self, raw, owner):
        self.raw, self.owner = raw, owner

    def __getattr__(self, name):
        if name != 'close':
            self.owner.check_health()
        try:
            return getattr(self.raw, name)
        except sqlite3.Error as exc:
            self.owner._fault(exc)
            raise StorageFaultError('authoritative connection failed') from exc

    def execute(self, *args, **kwargs):
        return self._run("execute", *args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._run("executemany", *args, **kwargs)

    def executescript(self, script):
        raise TrustError("executescript implicitly commits; execute each statement inside atomic()")

    def _run(self, method, *args, **kwargs):
        self.owner.check_health()
        try:
            return _GuardedCursor(getattr(self.raw, method)(*args, **kwargs), self.owner)
        except sqlite3.Error as exc:
            self.owner._fault(exc)
            raise StorageFaultError("authoritative storage operation failed; action uncommitted") from exc


class _GuardedCursor:
    def __init__(self, cursor, owner):
        self.cursor, self.owner = cursor, owner

    def __getattr__(self, name):
        return getattr(self.cursor, name)

    def _fetch(self, method, *args):
        self.owner.check_health()
        try:
            return getattr(self.cursor, method)(*args)
        except sqlite3.Error as exc:
            self.owner._fault(exc)
            raise StorageFaultError('authoritative read failed') from exc

    def fetchone(self):
        return self._fetch('fetchone')

    def fetchall(self):
        return self._fetch('fetchall')

    def fetchmany(self, *args):
        return self._fetch('fetchmany', *args)

    def __iter__(self):
        return self

    def __next__(self):
        self.owner.check_health()
        try:
            return next(self.cursor)
        except sqlite3.Error as exc:
            self.owner._fault(exc)
            raise StorageFaultError('authoritative read failed') from exc
