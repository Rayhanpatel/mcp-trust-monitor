"""The module entry point is the library CLI; historical demos never write foreign state.

REQ-LIB-04: one owning process per state directory. The historical hackathon CLI
(`python -m mcp_trust_monitor.historical_demo`) acquires the same owner lock as the
library before any write, operates only on directories marked as demo state, reads
status without ownership, and has no checkout-relative defaults when installed.
Real subprocesses, real stdio demo servers, real SQLite state; nothing is mocked
except where the package root is (to stand in for an installed site-packages).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor import historical_demo as cli
from mcp_trust_monitor.config import ConfigurationError, MonitorConfig
from mcp_trust_monitor.managed_client import CallBlocked, trust_db_path
from mcp_trust_monitor.ownership import StateOwner
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.trust_store import TrustState, TrustStore

from conftest import CONTROL, FIXTURE_PATH, LOOKUP, POLICY_PATH, REPO_ROOT

CLI_MODULE = "mcp_trust_monitor.historical_demo"
MARKER = "historical-demo-state"
ARGS = {"title": "Annual report"}
CREDENTIAL_PREFIXES = ("CLICKHOUSE_", "SENSO_", "OPENAI_")


def run_module(module: str, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(CREDENTIAL_PREFIXES)}
    return subprocess.run([sys.executable, "-m", module, *args], cwd=cwd, env=environment,
                          capture_output=True, text=True, timeout=120)


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return run_module(CLI_MODULE, *args)


def paths(state: Path) -> list[str]:
    return ["--state-dir", str(state), "--policy", str(POLICY_PATH), "--fixture", str(FIXTURE_PATH)]


def snapshot(root: Path, *, skip_bytes: tuple[str, ...] = ()) -> dict[str, str]:
    """Every entry below root, with file contents hashed."""
    result = {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = "symlink"
        elif path.is_dir():
            result[name] = "directory"
        elif name.endswith(skip_bytes):
            result[name] = "file"
        else:
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def read_state(state: Path, server_id: str = LOOKUP, client_id: str = "demo-client"):
    store = TrustStore.open_readonly(trust_db_path(state), client_id=client_id)
    try:
        return store.get(server_id), store.events(server_id)
    finally:
        store.close()


def library_config(state: Path) -> MonitorConfig:
    return MonitorConfig(state, POLICY_PATH, {sid: demo.server_config(sid, state, FIXTURE_PATH)
                                              for sid in demo.DEMO_SERVERS})


def test_module_entry_point_is_the_generic_library_cli(tmp_path):
    completed = run_module("mcp_trust_monitor", "--help", cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert "--config" in completed.stdout
    assert "--state-dir" not in completed.stdout and "demo-m2" not in completed.stdout

    # Without a configuration it refuses before touching any state anywhere.
    package_state = REPO_ROOT / "runtime" / "state" / "trust.sqlite3"
    existed = package_state.exists()
    refused = run_module("mcp_trust_monitor", "status", cwd=tmp_path)
    assert refused.returncode == 2
    assert "--config" in refused.stderr and "Traceback" not in refused.stderr
    assert list(tmp_path.iterdir()) == []
    assert package_state.exists() == existed


def test_historical_module_says_plainly_what_it_is():
    completed = run_cli("--help")
    assert completed.returncode == 0, completed.stderr
    assert "Historical hackathon demonstrations" in completed.stdout
    assert "NOT the library CLI" in completed.stdout
    assert "dedicated demo state" in completed.stdout


@pytest.mark.anyio
async def test_historical_approve_is_not_a_second_writer_beside_a_library_owner(tmp_path):
    """The reviewed defect: a foreign approval the owner then dispatched under."""
    state = tmp_path / "library-state"
    async with TrustMonitor(library_config(state)) as monitor:
        observed = await monitor.observe(LOOKUP)
        assert observed.state is TrustState.UNREVIEWED
        events_before = monitor.events(LOOKUP)

        cli_run = await asyncio.to_thread(
            run_cli, *paths(state), "--client-id", "default",
            "approve", LOOKUP, "--revision", observed.observed_revision)

        after = monitor.status(LOOKUP)
        added = [event["event_type"] for event in monitor.events(LOOKUP)[len(events_before):]]
        try:
            await monitor.call_tool(LOOKUP, "lookup_document", ARGS)
            dispatch = "dispatched"
        except CallBlocked as blocked:
            dispatch = f"blocked: {blocked.reason}"
        outcome = {
            "cli_exit": cli_run.returncode,
            "state": after.state,
            "generation": after.generation,
            "approved_revision": after.approved_revision,
            "events_added_by_cli": added,
            "owner_dispatch": dispatch,
            "server_received_calls": len(demo.received_requests(state, LOOKUP)),
        }
        assert outcome == {
            "cli_exit": 2,
            "state": TrustState.UNREVIEWED,
            "generation": observed.generation,
            "approved_revision": None,
            "events_added_by_cli": [],
            "owner_dispatch": "blocked: unreviewed",
            "server_received_calls": 0,
        }
        assert "refused" in cli_run.stderr and "mcp-trust-monitor --config" in cli_run.stderr
        assert "Traceback" not in cli_run.stderr
    assert not (state / MARKER).exists()


@pytest.mark.parametrize("command", [
    ("approve", LOOKUP, "--revision", "{revision}"),
    ("quarantine", LOOKUP, "--reason", "second writer"),
    ("observe", CONTROL),
    ("mutate", "--scenario", "private-content-demand"),
    ("--env-file", "{absent}", "deliver"),
], ids=["approve", "quarantine", "observe", "mutate", "deliver"])
def test_owned_demo_state_refuses_historical_writers_and_changes_nothing(tmp_path, command):
    state = tmp_path / "demo-state"
    assert cli.main([*paths(state), "observe", LOOKUP]) == 0
    record_before, events_before = read_state(state)
    values = {"revision": record_before.observed_revision, "absent": str(tmp_path / "absent.env")}

    owner = StateOwner(state)
    owner.acquire()
    try:
        before = snapshot(state)
        refused = run_cli(*paths(state), *(part.format(**values) for part in command))
        after = snapshot(state)
    finally:
        owner.release(clean=True)

    assert refused.returncode == 2, refused.stdout + refused.stderr
    assert "owned by another process" in refused.stderr
    assert "Traceback" not in refused.stderr
    assert after == before
    assert read_state(state) == (record_before, events_before)
    # The first historical command marked the fresh directory as demo state.
    assert json.loads((state / MARKER).read_text()) == {"purpose": "historical-demo"}


@pytest.mark.anyio
async def test_unmarked_library_state_is_refused_without_any_write(tmp_path):
    state = tmp_path / "library-state"
    async with TrustMonitor(library_config(state)) as monitor:
        observed = await monitor.observe(LOOKUP)
    before = snapshot(state)
    database = (state / "trust.sqlite3").read_bytes()

    for command in (["approve", LOOKUP, "--revision", observed.observed_revision],
                    ["quarantine", LOOKUP],
                    ["observe", LOOKUP],
                    ["mutate", "--baseline"],
                    ["status"],
                    ["received", LOOKUP]):
        refused = run_cli(*paths(state), "--client-id", "default", *command)
        assert refused.returncode == 2, (command, refused.stdout, refused.stderr)
        assert f"no {MARKER} marker" in refused.stderr
        assert "mcp-trust-monitor --config" in refused.stderr
        assert "Traceback" not in refused.stderr
        assert snapshot(state) == before, command
    assert (state / "trust.sqlite3").read_bytes() == database
    assert not (state / MARKER).exists()


def test_installed_package_has_no_default_paths_and_creates_nothing(tmp_path, monkeypatch, capsys):
    assert cli.checkout_root(REPO_ROOT) == REPO_ROOT.resolve()
    # An installed package root: even checkout-like files inside site-packages do not count.
    site = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    (site / "fixtures").mkdir(parents=True)
    (site / "policies").mkdir()
    (site / "pyproject.toml").write_text("[project]\nname = 'stray'\n")
    shutil.copy(FIXTURE_PATH, site / "fixtures" / "tool_changes.json")
    shutil.copy(POLICY_PATH, site / "policies" / "demo-policy.json")
    for directory in ("cwd", "system-temp"):
        (tmp_path / directory).mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "system-temp"))
    monkeypatch.setattr(cli, "PACKAGE_ROOT", site)
    assert cli.checkout_root() is None
    before = snapshot(tmp_path)

    cases = {
        ("status",): ["--state-dir", "--policy"],
        ("observe", LOOKUP): ["--state-dir", "--policy", "--fixture"],
        ("approve", LOOKUP, "--revision", "r"): ["--state-dir", "--policy"],
        ("quarantine", LOOKUP): ["--state-dir"],
        ("mutate", "--baseline"): ["--state-dir"],
        ("deliver",): ["--state-dir", "--env-file"],
        ("senso-upload",): ["--policy", "--env-file"],
        ("evaluate",): ["--policy", "--fixture", "--env-file"],
        ("review", LOOKUP, "--model"): ["--state-dir", "--policy", "--fixture", "--env-file"],
        ("demo",): ["--policy", "--fixture"],
        ("demo-m2",): ["--policy", "--fixture", "--env-file"],
        ("demo-m3",): ["--policy", "--fixture", "--env-file"],
    }
    for argv, flags in cases.items():
        assert cli.main(list(argv)) == 2, argv
        captured = capsys.readouterr()
        assert "not running from a source checkout" in captured.err
        assert all(flag in captured.err for flag in flags), (argv, captured.err)
        assert "Traceback" not in captured.err + captured.out
    assert snapshot(tmp_path) == before

    # Explicit paths need no checkout. A read-only status of absent state creates nothing.
    explicit = ["--state-dir", str(tmp_path / "explicit"), "--policy", str(POLICY_PATH)]
    assert cli.main([*explicit, "status"]) == 0
    assert "no trust records" in capsys.readouterr().out
    assert snapshot(tmp_path) == before


def test_status_of_absent_state_reports_no_records_and_creates_nothing(tmp_path):
    state = tmp_path / "never-created"
    completed = run_cli(*paths(state), "status")
    assert completed.returncode == 0, completed.stderr
    assert not state.exists()
    assert "no trust records" in completed.stdout


def test_readonly_status_coexists_with_an_owner_and_never_writes(tmp_path):
    state = tmp_path / "demo-state"
    assert cli.main([*paths(state), "observe", LOOKUP]) == 0
    owner = StateOwner(state)
    owner.acquire()
    store = TrustStore(trust_db_path(state))  # the owner's open writable store
    try:
        # Readers take read marks in the shared-memory index; that is not a state write.
        before = snapshot(state, skip_bytes=("-shm",))
        completed = run_cli(*paths(state), "status")
        after = snapshot(state, skip_bytes=("-shm",))
        record = store.get(LOOKUP)
    finally:
        store.close()
        owner.release(clean=True)
    assert completed.returncode == 0, completed.stderr
    assert f"{LOOKUP}: unreviewed  generation={record.generation}" in completed.stdout
    assert f"observed revision: {record.observed_revision}" in completed.stdout
    assert after == before


def test_historical_writer_recovers_after_an_unclean_owner_exit(tmp_path):
    """Exactly as the library owner: an unclean marker forces recovery before anything else."""
    state = tmp_path / "demo-state"
    assert cli.main([*paths(state), "observe", LOOKUP]) == 0
    observed, _ = read_state(state)
    assert cli.main([*paths(state), "approve", LOOKUP, "--revision",
                     observed.observed_revision]) == 0
    assert read_state(state)[0].state is TrustState.APPROVED
    assert not (state / "owner.unclean").exists()  # every command released cleanly

    (state / "owner.unclean").write_text('{"pid": 0}')  # an owner died without releasing
    assert cli.main([*paths(state), "observe", CONTROL]) == 0

    recovered, events = read_state(state)
    assert recovered.state is TrustState.PENDING_REVIEW
    assert recovered.observation_failed_at is not None
    assert "owner_recovered" in [event["event_type"] for event in events]
    assert not (state / "owner.unclean").exists()


@pytest.mark.anyio
async def test_library_owner_refuses_historical_demo_state_without_any_write(tmp_path):
    """Isolation in both directions: the library never owns a marked demo directory."""
    state = tmp_path / "demo-state"
    cli.claim_demo_state(state)
    before = snapshot(state)
    with pytest.raises(ConfigurationError, match="historical demo"):
        async with TrustMonitor(library_config(state)):
            pass
    assert snapshot(state) == before  # no owner lock, marker or database was created
