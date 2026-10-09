"""Bounded delivery of outbox events to ClickHouse, and deduplicated history reads.

Delivery runs outside every enforcement transaction (REQ-AUD-01): it reads pending
outbox rows, inserts them as JSONEachRow, and marks them delivered only after the
insert succeeds. A failure keeps them pending locally with a sanitized error, and
callers report a nonzero result. Event IDs are fixed at creation, so a retry after
an ambiguous failure can duplicate rows in ClickHouse; reads deduplicate by event
ID in SQL (`LIMIT 1 BY event_id`) and again in Python, because MergeTree does not
enforce uniqueness. Standard library only. No value from settings is ever printed.
"""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .trust_store import TrustStore

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ("CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD",
            "CLICKHOUSE_DATABASE")
TABLE = "trust_history"
REDACTED = "<redacted>"


class HistoryClient(Protocol):
    def execute(self, sql: str, *, body: str | None = None,
                params: Mapping[str, str] | None = None) -> str: ...


class SettingsMissing(Exception):
    pass


def load_settings(env_file: Path = REPO_ROOT / ".env") -> dict[str, str]:
    values: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.removeprefix("export ").split("=", 1)
            values[key.strip()] = value.strip().strip("'\"")
    for key in REQUIRED:
        if os.environ.get(key):
            values[key] = os.environ[key]
    missing = [key for key in REQUIRED if not values.get(key)]
    if missing:
        raise SettingsMissing(f"missing {', '.join(missing)}")
    return values


def secrets_of(settings: Mapping[str, str]) -> list[str]:
    return [settings.get("CLICKHOUSE_HOST", ""), settings.get("CLICKHOUSE_USER", ""),
            settings.get("CLICKHOUSE_PASSWORD", "")]


def sanitize(text: str, secrets: list[str]) -> str:
    """Redact the complete string before any truncation."""
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


class ClickHouseHTTP:
    def __init__(self, settings: Mapping[str, str], timeout_seconds: float = 20.0) -> None:
        host = settings["CLICKHOUSE_HOST"]
        if "://" in host or "/" in host:
            raise ValueError("CLICKHOUSE_HOST must be a bare hostname without scheme or path")
        self.base = f"https://{host}:{settings['CLICKHOUSE_PORT']}/"
        self.database = settings["CLICKHOUSE_DATABASE"]
        self.headers = {"X-ClickHouse-User": settings["CLICKHOUSE_USER"],
                        "X-ClickHouse-Key": settings["CLICKHOUSE_PASSWORD"]}
        self.secrets = secrets_of(settings)
        self.timeout = timeout_seconds  # per socket operation; retries are bounded by callers
        self.context = ssl.create_default_context()

    def execute(self, sql: str, *, body: str | None = None,
                params: Mapping[str, str] | None = None) -> str:
        query = {"database": self.database, "date_time_input_format": "best_effort",
                 **(params or {})}
        if body is not None:
            query["query"] = sql
        data = (body if body is not None else sql).encode("utf-8")
        request = urllib.request.Request(self.base + "?" + urllib.parse.urlencode(query),
                                         data=data, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=self.context) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            # Redact the complete body before taking the first line or truncating.
            body_text = sanitize(exc.read().decode("utf-8", "replace"), self.secrets)
            lines = body_text.strip().splitlines()
            raise RuntimeError(f"HTTP {exc.code}: {(lines[0] if lines else '')[:300]}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(sanitize(f"{type(exc).__name__}: {exc}", self.secrets)) from None


def table_ddl(database: str) -> list[str]:
    return [
        f"CREATE TABLE IF NOT EXISTS `{database}`.{TABLE} ("
        " event_id String, run_id String, seq UInt64, ts DateTime64(3, 'UTC'), client_id String,"
        " server_id String, event_type LowCardinality(String), actor String,"
        " from_state Nullable(String), to_state Nullable(String), revision Nullable(String),"
        " policy_revision Nullable(String), generation Nullable(Int64),"
        " origin Nullable(String), detail String"
        ") ENGINE = MergeTree ORDER BY (run_id, seq, event_id)",
        # Tables created before `seq` existed gain it; nothing else changes.
        f"ALTER TABLE `{database}`.{TABLE} ADD COLUMN IF NOT EXISTS seq UInt64 AFTER run_id",
    ]


@dataclass
class DeliveryResult:
    delivered: int
    pending: int
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.pending == 0 and self.error is None


def deliver_pending(
    store: TrustStore,
    client: HistoryClient,
    database: str,
    *,
    secrets: list[str],
    batch_size: int = 500,
    max_batches: int = 20,
    attempts: int = 3,
    backoff_seconds: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> DeliveryResult:
    """Deliver pending outbox rows in bounded batches with bounded retries."""
    delivered = 0
    table_ready = False
    for _ in range(max_batches):
        batch = store.pending_outbox(limit=batch_size)
        if not batch:
            break
        ids = [row["event_id"] for row in batch]
        body = "\n".join(json.dumps(row["payload"], sort_keys=True) for row in batch)
        error = None
        for attempt in range(attempts):
            try:
                if not table_ready:
                    for statement in table_ddl(database):
                        client.execute(statement)
                    table_ready = True
                client.execute(f"INSERT INTO `{database}`.{TABLE} FORMAT JSONEachRow", body=body)
                error = None
                break
            except Exception as exc:  # network, HTTP, or timeout: keep pending
                error = sanitize(f"{type(exc).__name__}: {exc}", secrets)[:300]
                if attempt + 1 < attempts:
                    sleep(backoff_seconds * 2 ** attempt)
        if error is not None:
            store.mark_delivery_failed(ids, error)
            return DeliveryResult(delivered, store.outbox_status()["pending"], error)
        store.mark_delivered(ids)
        delivered += len(ids)
    return DeliveryResult(delivered, store.outbox_status()["pending"])


def read_history(client: HistoryClient, database: str, run_id: str) -> dict[str, Any]:
    """Raw row count, distinct events, and the deduplicated timeline for one run."""
    params = {"param_run": run_id}
    counts = json.loads(client.execute(
        f"SELECT count() AS raw_rows, uniqExact(event_id) AS events FROM `{database}`.{TABLE}"
        " WHERE run_id = {run:String} FORMAT JSONEachRow", params=params).strip() or "{}")
    lines = client.execute(
        "SELECT event_id, seq, toString(ts) AS ts, server_id, event_type, actor, from_state,"
        " to_state, revision, generation, origin, detail"
        f" FROM `{database}`.{TABLE} WHERE run_id = {{run:String}}"
        " ORDER BY seq, event_id LIMIT 1 BY event_id FORMAT JSONEachRow", params=params)
    seen: set[str] = set()
    events = []
    for line in lines.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row["event_id"] in seen:
            continue
        seen.add(row["event_id"])
        events.append(row)
    return {"raw_rows": int(counts.get("raw_rows", 0)), "events": int(counts.get("events", 0)),
            "timeline": events}
