#!/usr/bin/env python3
"""M0 ClickHouse smoke test over the HTTPS interface. Standard library only.

Reads CLICKHOUSE_* from the environment, falling back to the repository's .env.
Prints check results only: never credential values or the hostname. Makes no
persistent change; the write check uses a session-scoped temporary table.

Run from the repository root: uv run python scripts/smoke_clickhouse.py
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

REQUIRED = ("CLICKHOUSE_HOST", "CLICKHOUSE_PORT", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD",
            "CLICKHOUSE_DATABASE")


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
            raise SystemExit("CLICKHOUSE_HOST must be a bare hostname without scheme or path")
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


def main() -> int:
    settings = load_settings()
    missing = [key for key in REQUIRED if not settings.get(key)]
    if missing:
        print(f"BLOCKED: missing {', '.join(missing)}")
        return 2
    client = ClickHouse(settings)
    database = settings["CLICKHOUSE_DATABASE"]
    session = f"m0-smoke-{uuid.uuid4()}"
    checks = [
        ("SELECT 1", "SELECT 1", {}),
        ("server version", "SELECT version()", {}),
        ("database exists", "SELECT count() FROM system.databases WHERE name = {db:String}",
         {"param_db": database}),
        ("create temporary table", "CREATE TEMPORARY TABLE m0_smoke (id UInt8, note String)",
         {"session_id": session}),
        ("insert JSONEachRow", 'INSERT INTO m0_smoke FORMAT JSONEachRow {"id": 1, "note": "m0"}',
         {"session_id": session}),
        ("read back", "SELECT count() FROM m0_smoke WHERE note = 'm0'", {"session_id": session}),
        ("CREATE TABLE privilege on database", f"CHECK GRANT CREATE TABLE ON `{database}`.*", {}),
        ("INSERT privilege on database", f"CHECK GRANT INSERT ON `{database}`.*", {}),
    ]
    failures = 0
    for label, sql, params in checks:
        started = time.perf_counter()
        try:
            result = client.query(sql, **params)
            status = f"ok -> {result!r}" if result else "ok"
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace").strip().splitlines()
            status = f"FAILED HTTP {exc.code}: {(body[0] if body else '')[:200]}"
            failures += 1
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            status = f"FAILED {type(exc).__name__}: {str(exc)[:200]}"
            failures += 1
        print(f"{label:38} {status}  ({(time.perf_counter() - started) * 1000:.0f} ms)")
    print(json.dumps({"checks": len(checks), "failures": failures}))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
