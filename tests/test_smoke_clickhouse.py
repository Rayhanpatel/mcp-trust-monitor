"""Validation and sanitization in scripts/smoke_clickhouse.py.

These tests drive the script's checks with a scripted client: they verify that
unexpected answers fail the smoke test, not that ClickHouse works. The live check
is `uv run python scripts/smoke_clickhouse.py`. Settings are injected, so the real
.env is never read and no network request is made.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import urllib.error

import pytest

from conftest import REPO_ROOT

_spec = importlib.util.spec_from_file_location(
    "smoke_clickhouse", REPO_ROOT / "scripts" / "smoke_clickhouse.py")
smoke = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = smoke  # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(smoke)

# Synthetic values only; never real credentials.
SETTINGS = {
    "CLICKHOUSE_HOST": "h7qx2-k9zr.synthetic-ch.invalid",
    "CLICKHOUSE_PORT": "8443",
    "CLICKHOUSE_USER": "u5_smoke_vq",
    "CLICKHOUSE_PASSWORD": "Zq9!Xv7#Lm2$Pw4%Tr8&",
    "CLICKHOUSE_DATABASE": "mcp_trust_monitor",
}
CORRECT = {
    "SELECT 1": "1",
    "server version": "26.6.1.2326",
    "database exists": "1",
    "create temporary table": "",
    "insert JSONEachRow": "",
    "read back": "1",
    "CREATE TABLE privilege on database": "1",
    "INSERT privilege on database": "1",
}


class ScriptedClient:
    def __init__(self, overrides=None):
        checks = smoke.build_checks(SETTINGS["CLICKHOUSE_DATABASE"], "session")
        assert {check.label for check in checks} == set(CORRECT)
        self.labels = {check.sql: check.label for check in checks}
        self.answers = {**CORRECT, **(overrides or {})}

    def query(self, sql, **params):
        answer = self.answers[self.labels[sql]]
        if isinstance(answer, Exception):
            raise answer
        return answer


def run(overrides=None):
    lines = []
    status = smoke.main(settings=dict(SETTINGS), client=ScriptedClient(overrides), out=lines.append)
    return status, "\n".join(lines)


def test_expected_answers_pass():
    status, output = run()
    assert status == 0
    assert '"failures": 0' in output


@pytest.mark.parametrize("label, answer", [
    ("SELECT 1", "0"),
    ("SELECT 1", ""),
    ("server version", ""),
    ("database exists", "0"),
    ("create temporary table", "unexpected"),
    ("insert JSONEachRow", "unexpected"),
    ("read back", "0"),
    ("CREATE TABLE privilege on database", "0"),
    ("INSERT privilege on database", "0"),
])
def test_unexpected_answer_fails_with_nonzero_status(label, answer):
    status, output = run({label: answer})
    assert status == 1
    assert '"failures": 1' in output
    failing = [line for line in output.splitlines() if line.startswith(label)]
    assert len(failing) == 1 and "UNEXPECTED" in failing[0]


def test_errors_are_sanitized():
    body = (f"Code: 516. {SETTINGS['CLICKHOUSE_USER']}: Authentication failed for "
            f"{SETTINGS['CLICKHOUSE_HOST']} with {SETTINGS['CLICKHOUSE_PASSWORD']}").encode()
    status, output = run({
        "SELECT 1": urllib.error.HTTPError("https://example.invalid/", 401, "Unauthorized", {},
                                           io.BytesIO(body)),
        "database exists": urllib.error.URLError(f"cannot reach {SETTINGS['CLICKHOUSE_HOST']}"),
    })
    assert status == 1
    assert '"failures": 2' in output
    for key in ("CLICKHOUSE_HOST", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD"):
        assert SETTINGS[key] not in output
    assert "<redacted>" in output


def leaked_fragments(output: str, secret: str, size: int = 6) -> list[str]:
    return [secret[i:i + size] for i in range(len(secret) - size + 1)
            if secret[i:i + size] in output]


def straddle(cutoff: int, secret: str, prefix_len: int = 0) -> str:
    """Filler that places `secret` across the truncation `cutoff`, 8 characters before it."""
    return "x" * (cutoff - 8 - prefix_len) + secret + " trailing text"


@pytest.mark.parametrize("secret_key", ["CLICKHOUSE_PASSWORD", "CLICKHOUSE_HOST"])
@pytest.mark.parametrize("where", ["unexpected-result", "http-error-body", "connection-error"])
def test_secrets_crossing_truncation_boundaries_are_fully_redacted(where, secret_key):
    """Redaction happens on complete strings before any truncation (80 or 200 chars)."""
    secret = SETTINGS[secret_key]
    if where == "unexpected-result":
        overrides = {"SELECT 1": straddle(80, secret)}
    elif where == "http-error-body":
        body = straddle(200, secret).encode()
        overrides = {"SELECT 1": urllib.error.HTTPError("https://example.invalid/", 500, "Error",
                                                        {}, io.BytesIO(body))}
    else:
        prefix = "<urlopen error "  # str(URLError(reason)) wraps the reason
        overrides = {"SELECT 1": urllib.error.URLError(straddle(200, secret, len(prefix)))}

    status, output = run(overrides)
    assert status == 1
    assert leaked_fragments(output, secret) == []
    # The secret starts 8 characters before the cutoff, so truncation now cuts the
    # redaction marker ("<redacted>" -> "<redacte") instead of the secret.
    assert "x<redacte" in output


def test_missing_settings_block_without_contacting_anything():
    lines = []
    settings = {**SETTINGS, "CLICKHOUSE_PASSWORD": ""}
    assert smoke.main(settings=settings, client=None, out=lines.append) == 2
    assert lines == ["BLOCKED: missing CLICKHOUSE_PASSWORD"]
