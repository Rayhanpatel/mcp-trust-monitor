"""Durable, revision-bound trust state for one managed client.

Every transition and its local audit event commit in one SQLite transaction
(REQ-TRU-04). Authorizing transitions must name the exact observed revision and,
optionally, the generation they were decided against (REQ-TRU-02). Restrictive
transitions fail closed.
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
    detail TEXT NOT NULL DEFAULT '{}'
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class TrustStore:
    def __init__(self, path: Path, client_id: str = "demo-client") -> None:
        self.path = Path(path)
        self.client_id = client_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Autocommit mode; transitions open explicit IMMEDIATE transactions.
        self._db = sqlite3.connect(self.path, isolation_level=None, timeout=10.0)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)

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
    ) -> TrustRecord:
        """Record a complete tools/list observation (REQ-TRU-01, REQ-TRU-03)."""
        tools_json = json.dumps([tool_metadata(tool) for tool in tools], sort_keys=True)
        with self._transaction():
            current = self.get(server_id)
            if current is None:
                self._db.execute(
                    "INSERT INTO trust_records (client_id, server_id, state, observed_revision,"
                    " observed_tools, generation, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?)",
                    (self.client_id, server_id, TrustState.UNREVIEWED.value, revision,
                     tools_json, _now()),
                )
                new = self._require(server_id)
                self._event(new, "observed_new", actor, None, new.state, revision)
                return new
            if current.observed_revision == revision:
                return current
            # Metadata changed. Approval is invalidated; quarantine is never lifted here.
            next_state = (
                TrustState.PENDING_REVIEW
                if current.state is TrustState.APPROVED
                else current.state
            )
            self._update(current, state=next_state, observed_revision=revision,
                         observed_tools=tools_json)
            new = self._require(server_id)
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
        """Explicit operator approval of one exact revision under one policy revision."""
        with self._transaction():
            current = self.get(server_id)
            if current is None or current.observed_revision is None:
                raise StaleDecisionError(f"{server_id} has no observed revision to approve")
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

        In one transaction: an approved server moves to pending review (bumping the
        generation) and `observation_failed` is recorded. Quarantine and other states
        are preserved. Every session of this managed client then blocks, because
        they all authorize against this record.
        """
        detail = {"error": error[:500]}
        with self._transaction():
            current = self.get(server_id)
            if current is None:
                self._db.execute(
                    "INSERT INTO trust_events (event_id, ts, client_id, server_id, event_type,"
                    " actor, detail) VALUES (?, ?, ?, ?, 'observation_failed', ?, ?)",
                    (str(uuid.uuid4()), _now(), self.client_id, server_id, actor,
                     json.dumps(detail)))
                return None
            if current.state is TrustState.APPROVED:
                self._update(current, state=TrustState.PENDING_REVIEW)
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
            self._db.execute(
                "INSERT INTO trust_events (event_id, ts, client_id, server_id, event_type,"
                " actor, from_state, to_state, revision, policy_revision, generation, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), _now(), self.client_id, server_id, event_type, actor,
                 record.state.value if record else None, record.state.value if record else None,
                 record.observed_revision if record else None,
                 record.approved_policy_revision if record else None,
                 record.generation if record else None, json.dumps(dict(detail))),
            )

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
        }
        for key, value in changes.items():
            values[key] = value.value if isinstance(value, TrustState) else value
        cursor = self._db.execute(
            "UPDATE trust_records SET state = ?, observed_revision = ?, observed_tools = ?,"
            " approved_revision = ?, approved_policy_revision = ?, generation = ?,"
            " updated_at = ? WHERE client_id = ? AND server_id = ? AND generation = ?",
            (values["state"], values["observed_revision"], values["observed_tools"],
             values["approved_revision"], values["approved_policy_revision"],
             current.generation + 1, _now(), self.client_id, current.server_id,
             current.generation),
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
    ) -> None:
        self._db.execute(
            "INSERT INTO trust_events (event_id, ts, client_id, server_id, event_type, actor,"
            " from_state, to_state, revision, policy_revision, generation, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), _now(), self.client_id, record.server_id, event_type, actor,
             from_state.value if from_state else None, to_state.value if to_state else None,
             revision, policy_revision, record.generation, json.dumps(dict(detail or {}))),
        )


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
    )
