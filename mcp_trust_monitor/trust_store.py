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
from typing import Any, Iterable, Mapping

from .revision import tool_metadata


class TrustState(str, Enum):
    UNREVIEWED = "unreviewed"
    APPROVED = "approved"
    PENDING_REVIEW = "pending_review"
    QUARANTINED = "quarantined"


class TrustError(Exception):
    """A requested transition is not permitted."""


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
"""

# Columns added after M1. Stores created by M1 gain them on open; no row is rewritten,
# so trust state and the observation-recovery requirement carry over unchanged.
_MIGRATIONS = (
    ("trust_records", "observation_failed_at", "TEXT"),
    ("trust_records", "origin", "TEXT"),
    ("trust_events", "run_id", "TEXT"),
    ("trust_events", "origin", "TEXT"),
)
SCHEMA_VERSION = 2


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
        self, path: Path, client_id: str = "demo-client", *, run_id: str | None = None
    ) -> None:
        self.path = Path(path)
        self.client_id = client_id
        # Correlates this process's events and observations in the history store.
        self.run_id = run_id or f"run-{uuid.uuid4()}"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Autocommit mode; transitions open explicit IMMEDIATE transactions.
        self._db = sqlite3.connect(self.path, isolation_level=None, timeout=10.0)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)
        # Re-check inside one IMMEDIATE transaction so concurrent openers cannot both add
        # a column. Existing rows are never rewritten.
        with self._transaction():
            for table, column, declaration in _MIGRATIONS:
                columns = {row["name"] for row in self._db.execute(f"PRAGMA table_info({table})")}
                if column not in columns:
                    self._db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
            self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def close(self) -> None:
        self._db.close()

    # Reads

    def get(self, server_id: str) -> TrustRecord | None:
        row = self._db.execute(
            "SELECT * FROM trust_records WHERE client_id = ? AND server_id = ?",
            (self.client_id, server_id),
        ).fetchone()
        return _record(row) if row else None

    def records(self) -> list[TrustRecord]:
        rows = self._db.execute(
            "SELECT * FROM trust_records WHERE client_id = ? ORDER BY server_id",
            (self.client_id,),
        ).fetchall()
        return [_record(row) for row in rows]

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
                    " observed_tools, generation, updated_at, origin)"
                    " VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
                    (self.client_id, server_id, TrustState.UNREVIEWED.value, revision,
                     tools_json, _now(), origin),
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
                         approved_policy_revision=policy_revision)
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
                stale = None
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

    def observations(self, server_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM observations WHERE client_id = ?"
        params: list[Any] = [self.client_id]
        if server_id is not None:
            query += " AND server_id = ?"
            params.append(server_id)
        return [dict(row) for row in self._db.execute(query + " ORDER BY ts", params)]

    # Internals

    def _transaction(self) -> "_Transaction":
        return _Transaction(self._db)

    def _require(self, server_id: str) -> TrustRecord:
        record = self.get(server_id)
        if record is None:
            raise TrustError(f"no trust record for {server_id}")
        return record

    def _update(self, current: TrustRecord, **changes: Any) -> None:
        values = {
            "state": current.state.value,
            "observed_revision": current.observed_revision,
            "observed_tools": json.dumps(list(current.observed_tools), sort_keys=True),
            "approved_revision": current.approved_revision,
            "approved_policy_revision": current.approved_policy_revision,
            "observation_failed_at": current.observation_failed_at,
            "origin": current.origin,
        }
        for key, value in changes.items():
            values[key] = value.value if isinstance(value, TrustState) else value
        cursor = self._db.execute(
            "UPDATE trust_records SET state = ?, observed_revision = ?, observed_tools = ?,"
            " approved_revision = ?, approved_policy_revision = ?, observation_failed_at = ?,"
            " origin = ?, generation = ?, updated_at = ? WHERE client_id = ? AND server_id = ?"
            " AND generation = ?",
            (values["state"], values["observed_revision"], values["observed_tools"],
             values["approved_revision"], values["approved_policy_revision"],
             values["observation_failed_at"], values["origin"], current.generation + 1, _now(),
             self.client_id, current.server_id, current.generation),
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
            origin=record.origin, detail=detail or {},
        )

    def _insert_event(self, *, server_id: str, event_type: str, actor: str,
                      from_state: str | None = None, to_state: str | None = None,
                      revision: str | None = None, policy_revision: str | None = None,
                      generation: int | None = None, origin: str | None = None,
                      detail: Mapping[str, Any]) -> str:
        """Insert one audit event and its outbox row; return the stable event ID.
        The caller holds the transaction."""
        row = {
            "event_id": str(uuid.uuid4()), "run_id": self.run_id, "ts": _now(),
            "client_id": self.client_id, "server_id": server_id, "event_type": event_type,
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
        observation_failed_at=row["observation_failed_at"],
        origin=row["origin"],
    )
