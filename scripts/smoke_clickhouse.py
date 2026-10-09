#!/usr/bin/env python3
"""M0 ClickHouse smoke test over the HTTPS interface. Standard library only.

Reads CLICKHOUSE_* from the environment, falling back to the repository's .env.
Every check compares the server's answer with an expected value; an unexpected
answer counts as a failure exactly like an error. Output never contains
credential values or the hostname: error text is sanitized before printing.
Makes no persistent change; the write check uses a session-scoped temporary table.

Run from the repository root: uv run python scripts/smoke_clickhouse.py
Exit status: 0 all checks passed, 1 any check failed, 2 settings missing.
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol

REQUIRED = ("CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD",
            "CLICKHOUSE_DATABASE")
REDACTED = "<redacted>"


class Client(Protocol):
    def query(self, sql: str, **params: str) -> str: ...


@dataclass(frozen=True)
class Check:
    label: str
    sql: str
    expected: str  # human-readable expectation, printed on mismatch
    accept: Callable[[str], bool]
    params: dict[str, str] = field(default_factory=dict)


def equals(value: str) -> Callable[[str], bool]:
    return lambda result: result == value


def build_checks(database: str, session: str) -> list[Check]:
    in_session = {"session_id": session}
    return [
        Check("SELECT 1", "SELECT 1", "'1'", equals("1")),
        Check("server version", "SELECT version()", "a version such as '26.6.1'",
              lambda result: re.fullmatch(r"\d+(\.\d+)+", result) is not None),
        Check("database exists", "SELECT count() FROM system.databases WHERE name = {db:String}",
              "'1'", equals("1"), {"param_db": database}),
        Check("create temporary table", "CREATE TEMPORARY TABLE m0_smoke (id UInt8, note String)",
              "empty response", equals(""), in_session),
        Check("insert JSONEachRow", 'INSERT INTO m0_smoke FORMAT JSONEachRow {"id": 1, "note": "m0"}',
              "empty response", equals(""), in_session),
        Check("read back", "SELECT count() FROM m0_smoke WHERE note = 'm0'", "'1'", equals("1"),
              in_session),
        Check("CREATE TABLE privilege on database", f"CHECK GRANT CREATE TABLE ON `{database}`.*",
              "'1'", equals("1")),
        Check("INSERT privilege on database", f"CHECK GRANT INSERT ON `{database}`.*", "'1'",
              equals("1")),
    ]


def sanitize(text: str, secrets: list[str]) -> str:
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


def run_checks(client: Client, checks: list[Check], secrets: list[str],
               out: Callable[[str], None] = print) -> int:
    failures = 0
    for check in checks:
        started = time.perf_counter()
        try:
            result = client.query(check.sql, **check.params)
            if check.accept(result):
                status = f"ok -> {result!r}" if result else "ok"
            else:
                failures += 1
                status = f"UNEXPECTED result {result[:80]!r}; expected {check.expected}"
        except urllib.error.HTTPError as exc:
            failures += 1
            body = exc.read().decode("utf-8", "replace").strip().splitlines()
            status = f"FAILED HTTP {exc.code}: {(body[0] if body else '')[:200]}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            failures += 1
            status = f"FAILED {type(exc).__name__}: {str(exc)[:200]}"
        elapsed = (time.perf_counter() - started) * 1000
        out(sanitize(f"{check.label:38} {status}  ({elapsed:.0f} ms)", secrets))
    return failures


def load_settings() -> dict[str, str]:
    values: dict[str, str] = {}
    env_file = Path(__file__).resolve().parents[1] / ".env"
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
    return values


class ClickHouse:
    def __init__(self, settings: dict[str, str]) -> None:
        host = settings["CLICKHOUSE_HOST"]
        if "://" in host or "/" in host:
            raise ValueError("CLICKHOUSE_HOST must be a bare hostname without scheme or path")
        self.base = f"https://{host}:{settings['CLICKHOUSE_PORT']}/"
        self.headers = {"X-ClickHouse-User": settings["CLICKHOUSE_USER"],
                        "X-ClickHouse-Key": settings["CLICKHOUSE_PASSWORD"]}
        self.context = ssl.create_default_context()

    def query(self, sql: str, **params: str) -> str:
        url = self.base + "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, data=sql.encode("utf-8"), headers=self.headers,
                                         method="POST")
        with urllib.request.urlopen(request, timeout=60, context=self.context) as response:
            return response.read().decode("utf-8").strip()


def main(settings: dict[str, str] | None = None, client: Client | None = None,
         out: Callable[[str], None] = print) -> int:
    settings = load_settings() if settings is None else settings
    missing = [key for key in REQUIRED if not settings.get(key)]
    if missing:
        out(f"BLOCKED: missing {', '.join(missing)}")
        return 2
    secrets = [settings["CLICKHOUSE_HOST"], settings["CLICKHOUSE_USER"],
               settings["CLICKHOUSE_PASSWORD"]]
    if client is None:
        try:
            client = ClickHouse(settings)
        except ValueError as exc:
            out(sanitize(f"FAILED: {exc}", secrets))
            return 1
    checks = build_checks(settings["CLICKHOUSE_DATABASE"], f"m0-smoke-{uuid.uuid4()}")
    failures = run_checks(client, checks, secrets, out)
    out(json.dumps({"checks": len(checks), "failures": failures}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
