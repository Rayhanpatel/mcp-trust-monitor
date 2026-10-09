"""Local outbox atomicity, bounded ClickHouse delivery, deduplicated reads, M1 stores.

REQ-AUD-01, REQ-REV-03. Delivery tests use a scripted client or a local socket that
never answers; they test our delivery logic, not ClickHouse. The live write and
read-back is `python -m mcp_trust_monitor demo-m2`.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
import time

import pytest

from mcp_trust_monitor import history
from mcp_trust_monitor.trust_store import (ObservationRequiredError, TrustState, TrustStore)

POLICY = "demo-workspace-policy@2#sha256:test"
TOOLS_A = [{"name": "t", "description": "A", "inputSchema": {"type": "object"}}]
TOOLS_B = [{"name": "t", "description": "B", "inputSchema": {"type": "object"}}]
SECRETS = {"CLICKHOUSE_HOST": "h7qx2-k9zr.synthetic-ch.invalid", "CLICKHOUSE_PORT": "8443",
           "CLICKHOUSE_USER": "u5_smoke_vq", "CLICKHOUSE_PASSWORD": "Zq9!Xv7#Lm2$Pw4%Tr8&",
           "CLICKHOUSE_DATABASE": "mcp_trust_monitor"}


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "trust.sqlite3", run_id="run-test")


def pending_record(store) -> object:
    a = store.record_observation("s", "rev-a", TOOLS_A, provenance={"origin": "synthetic_fixture"})
    store.approve("s", revision="rev-a", policy_revision=POLICY,
                  expected_generation=a.generation, actor="test")
    return store.record_observation("s", "rev-b", TOOLS_B,
                                    provenance={"origin": "synthetic_fixture"})


def outbox_ids(store) -> set[str]:
    return {row["event_id"] for row in store.pending_outbox(limit=10_000)}


def test_every_event_and_observation_has_exactly_one_outbox_row(store):
    pending_record(store)
    event_ids = {event["event_id"] for event in store.events()}
    observation_ids = {row["observation_id"] for row in store.observations()}
    assert outbox_ids(store) == event_ids | observation_ids
    payloads = [row["payload"] for row in store.pending_outbox(limit=10_000)]
    assert {p["run_id"] for p in payloads} == {"run-test"}
    assert all(p["origin"] == "synthetic_fixture" for p in payloads
               if p["event_type"] == "observation_recorded")


def test_quarantine_and_its_outbox_rows_commit_together(store, monkeypatch):
    record = pending_record(store)
    before = outbox_ids(store)
    real = store._enqueue
    calls = {"n": 0}

    def fail_on_second(payload):
        calls["n"] += 1
        if calls["n"] == 2:  # after quarantine_requested was enqueued
            raise RuntimeError("disk full")
        real(payload)

    monkeypatch.setattr(store, "_enqueue", fail_on_second)
    with pytest.raises(RuntimeError):
        store.apply_hard_deny("s", revision=record.observed_revision,
                              generation=record.generation, policy_revision="ctx",
                              active_policy_revision="ctx", detection={"policy_ids": ["POL-002"]})
    assert store.get("s").state is TrustState.PENDING_REVIEW
    assert store.get("s").generation == record.generation
    assert not [e for e in store.events("s") if e["event_type"].startswith("quarantine")]
    assert outbox_ids(store) == before


def test_observation_row_transition_and_outbox_commit_together(store, monkeypatch):
    record = pending_record(store)
    observations = len(store.observations())
    monkeypatch.setattr(store, "_enqueue", lambda payload: (_ for _ in ()).throw(OSError("io")))
    with pytest.raises(OSError):
        store.record_observation("s", "rev-c", TOOLS_A)
    assert store.get("s").observed_revision == record.observed_revision
    assert len(store.observations()) == observations


class ScriptedClickHouse:
    def __init__(self, failures: int = 0, error: str = "HTTP 503: unavailable"):
        self.failures, self.error = failures, error
        self.inserts: list[list[dict]] = []

    def execute(self, sql, *, body=None, params=None):
        if body is None:
            return ""  # DDL
        if self.failures:
            self.failures -= 1
            raise RuntimeError(self.error)
        self.inserts.append([json.loads(line) for line in body.splitlines()])
        return ""


def test_delivery_retries_with_bounded_backoff_then_succeeds(store):
    pending_record(store)
    total = len(outbox_ids(store))
    clickhouse, sleeps = ScriptedClickHouse(failures=2), []
    result = history.deliver_pending(store, clickhouse, "db", secrets=[], attempts=3,
                                     backoff_seconds=0.5, sleep=sleeps.append)
    assert result.ok and result.delivered == total
    assert sleeps == [0.5, 1.0]
    assert store.outbox_status()["pending"] == 0


def test_failed_delivery_stays_pending_and_never_touches_trust_state(store):
    record = pending_record(store)
    store.apply_hard_deny("s", revision=record.observed_revision, generation=record.generation,
                          policy_revision="ctx", active_policy_revision="ctx",
                          detection={"policy_ids": ["POL-002"]})
    pending = len(outbox_ids(store))
    secret = SECRETS["CLICKHOUSE_PASSWORD"]
    error = "HTTP 401: " + "x" * 285 + secret + " trailing"  # secret crosses the 300 cutoff
    clickhouse = ScriptedClickHouse(failures=99, error=error)
    result = history.deliver_pending(store, clickhouse, "db",
                                     secrets=history.secrets_of(SECRETS), attempts=2,
                                     backoff_seconds=0, sleep=lambda s: None)
    assert not result.ok and result.pending == pending and result.delivered == 0
    status = store.outbox_status()
    assert status["pending"] == pending
    assert all(secret[i:i + 6] not in status["last_error"] for i in range(len(secret) - 5))
    attempts = {row["attempts"] for row in store.pending_outbox(limit=10_000)}
    assert attempts == {1}
    assert store.get("s").state is TrustState.QUARANTINED  # quarantine is unaffected

    # A later run delivers the same events.
    retry = history.deliver_pending(store, ScriptedClickHouse(), "db", secrets=[],
                                    sleep=lambda s: None)
    assert retry.ok and retry.delivered == pending


def test_lost_acknowledgement_resends_identical_rows_and_reads_deduplicate(store, monkeypatch):
    pending_record(store)
    clickhouse = ScriptedClickHouse()
    real_mark = store.mark_delivered
    monkeypatch.setattr(store, "mark_delivered",
                        lambda ids: (_ for _ in ()).throw(sqlite3.OperationalError("locked")))
    with pytest.raises(sqlite3.OperationalError):
        history.deliver_pending(store, clickhouse, "db", secrets=[], sleep=lambda s: None)
    monkeypatch.setattr(store, "mark_delivered", real_mark)
    assert history.deliver_pending(store, clickhouse, "db", secrets=[], sleep=lambda s: None).ok
    first, second = clickhouse.inserts
    assert first == second  # stable event IDs and identical payloads on redelivery

    class Reader:
        def execute(self, sql, *, body=None, params=None):
            if "uniqExact" in sql:
                return json.dumps({"raw_rows": 2 * len(first), "events": len(first)})
            return "\n".join(json.dumps(row) for row in first + second)

    read = history.read_history(Reader(), "db", "run-test")
    assert read["raw_rows"] == 2 * len(first)
    assert [row["event_id"] for row in read["timeline"]] == [row["event_id"] for row in first]


def test_http_timeout_is_bounded(store):
    pending_record(store)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    accepted: list[socket.socket] = []
    threading.Thread(target=lambda: accepted.append(listener.accept()[0]), daemon=True).start()
    settings = {**SECRETS, "CLICKHOUSE_HOST": "127.0.0.1",
                "CLICKHOUSE_PORT": str(listener.getsockname()[1])}
    client = history.ClickHouseHTTP(settings, timeout_seconds=0.5)
    started = time.monotonic()
    result = history.deliver_pending(store, client, "db", secrets=history.secrets_of(settings),
                                     attempts=2, backoff_seconds=0.1, sleep=time.sleep)
    assert time.monotonic() - started < 5
    assert not result.ok and result.pending > 0
    listener.close()


M1_SCHEMA = """
CREATE TABLE trust_records (client_id TEXT NOT NULL, server_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('unreviewed','approved','pending_review','quarantined')),
  observed_revision TEXT, observed_tools TEXT NOT NULL DEFAULT '[]', approved_revision TEXT,
  approved_policy_revision TEXT, generation INTEGER NOT NULL, updated_at TEXT NOT NULL,
  {extra} PRIMARY KEY (client_id, server_id));
CREATE TABLE trust_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
  ts TEXT NOT NULL, client_id TEXT NOT NULL, server_id TEXT NOT NULL, event_type TEXT NOT NULL,
  actor TEXT NOT NULL, from_state TEXT, to_state TEXT, revision TEXT, policy_revision TEXT,
  generation INTEGER, detail TEXT NOT NULL DEFAULT '{{}}');
"""


@pytest.mark.parametrize("with_failure_column", [True, False])
def test_approved_m1_store_keeps_trust_and_recovery_state(tmp_path, with_failure_column):
    path = tmp_path / "m1.sqlite3"
    db = sqlite3.connect(path)
    db.executescript(M1_SCHEMA.format(
        extra="observation_failed_at TEXT," if with_failure_column else ""))
    failed_at = "2026-10-09T20:00:00.000+00:00" if with_failure_column else None
    columns = "client_id, server_id, state, observed_revision, observed_tools, generation, updated_at"
    values = ["demo-client", "s", "quarantined", "rev-a", json.dumps(TOOLS_A), 7, "t"]
    if with_failure_column:
        columns += ", observation_failed_at"
        values.append(failed_at)
    db.execute(f"INSERT INTO trust_records ({columns}) VALUES ({', '.join('?' * len(values))})",
               values)
    db.execute("INSERT INTO trust_events (event_id, ts, client_id, server_id, event_type, actor)"
               " VALUES ('legacy-1', 't', 'demo-client', 's', 'quarantined', 'operator')")
    db.commit()
    db.close()

    store = TrustStore(path)
    record = store.get("s")
    assert (record.state, record.generation, record.observed_revision) == (
        TrustState.QUARANTINED, 7, "rev-a")
    assert record.observation_failed_at == failed_at
    if with_failure_column:
        with pytest.raises(ObservationRequiredError):
            store.approve("s", revision="rev-a", policy_revision=POLICY,
                          expected_generation=7, actor="op", restore=True)
    assert [e["event_id"] for e in store.events("s")] == ["legacy-1"]
    store.record_observation("s", "rev-a", TOOLS_A)  # new events now reach the outbox
    assert store.get("s").state is TrustState.QUARANTINED
    assert store.outbox_status()["pending"] >= 1
    store.close()
    TrustStore(path).close()  # reopening an already-migrated store is a no-op
