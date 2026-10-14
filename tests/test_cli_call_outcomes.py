"""Separate-process CLI: a dispatched call with an unknown outcome is not a refusal.

REQ-ENF-05/REQ-ENF-08: `call` exits 3 only for a refusal before dispatch. A request
that was handed to the transport, and so may have taken effect, exits 4 and says so; it is never
retried automatically.
"""
import json
import subprocess
import sys
from pathlib import Path

from conftest import POLICY_PATH, REPO_ROOT

HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"


def cli(config, *args):
    return subprocess.run([sys.executable, "-m", "mcp_trust_monitor", "--config", str(config), *args],
                          capture_output=True, text=True, timeout=120, cwd=str(REPO_ROOT))


def last_json(stream):
    return json.loads([line for line in stream.splitlines() if line.startswith("{")][-1])


def test_cli_reports_a_dispatched_unknown_outcome_distinctly_from_a_refusal(tmp_path):
    settings = tmp_path / "server.json"
    settings.write_text(json.dumps({"call_delay": 5}))
    log = tmp_path / "calls.jsonl"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "state_dir": "state", "policy_path": str(POLICY_PATH), "timeout_seconds": 1,
        "servers": [{"server_id": "local", "command": sys.executable,
                     "args": [str(HELPER), str(settings), str(log)], "cwd": str(tmp_path),
                     "origin": "synthetic_fixture"}]}))
    observed = json.loads(cli(config, "observe", "local").stdout)
    approved = cli(config, "approve", "local", "--revision", observed["observed_revision"],
                   "--generation", str(observed["generation"]))
    assert approved.returncode == 0, approved.stderr

    unknown = cli(config, "call", "local", "effect", "--refresh")
    assert unknown.returncode == 4, (unknown.returncode, unknown.stderr[-500:])
    assert last_json(unknown.stderr) == {"error": "ToolOutcomeUnknown", "dispatched": True}
    assert len(log.read_text().splitlines()) == 1

    refused = cli(config, "call", "local", "effect")  # a new process has no fresh session
    assert refused.returncode == 3
    assert last_json(refused.stderr) == {"error": "CallBlocked", "reason": "session_refresh_required"}
    assert len(log.read_text().splitlines()) == 1
