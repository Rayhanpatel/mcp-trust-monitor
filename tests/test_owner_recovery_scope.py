"""Real-crash regression: unclean-owner recovery covers the whole state directory.

REQ-ENF-07: the unclean-owner marker belongs to the state directory, so recovery must
cover every trust record in it, not only the client ID that happens to open it next.
A different client opening and closing cleanly must not discard another client's
requirement for a successful observation followed by explicit approval.
"""
import asyncio
import dataclasses
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import POLICY_PATH
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import CallBlocked, ServerConfig
from mcp_trust_monitor.sdk import TrustMonitor
from mcp_trust_monitor.trust_store import ObservationRequiredError, TrustState

pytestmark = pytest.mark.anyio

REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"

OWNER = r"""
import asyncio, sys
from pathlib import Path
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import ServerConfig
from mcp_trust_monitor.sdk import TrustMonitor

state, policy, helper, settings, log = map(Path, sys.argv[1:6])

async def main():
    profile = ServerConfig("custom/local", sys.executable, (str(helper), str(settings), str(log)),
                           origin="synthetic_fixture")
    config = MonitorConfig(state, policy, {"custom/local": profile}, client_id="alpha",
                           poll_interval=60, timeout_seconds=5)
    async with TrustMonitor(config) as monitor:
        record = await monitor.observe("custom/local")
        await monitor.approve("custom/local", revision=record.observed_revision,
                              expected_generation=record.generation, actor="operator")
        print("READY", flush=True)
        await asyncio.Event().wait()

asyncio.run(main())
"""


def configuration(tmp_path, client_id):
    settings = tmp_path / "server.json"
    settings.write_text("{}")
    log = tmp_path / "calls.jsonl"
    profile = ServerConfig("custom/local", sys.executable, (str(HELPER), str(settings), str(log)),
                           origin="synthetic_fixture")
    return MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": profile},
                         client_id=client_id, poll_interval=60, timeout_seconds=5), settings, log


def calls(log):
    return len(log.read_text().splitlines()) if log.exists() else 0


def crash_owner(tmp_path, settings, log):
    """Run a real owner process for client `alpha`, approve, then SIGKILL it."""
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    owner = subprocess.Popen(
        [sys.executable, "-c", OWNER, str(tmp_path / "state"), str(POLICY_PATH), str(HELPER),
         str(settings), str(log)],
        stdout=subprocess.PIPE, text=True, env=env, cwd=str(REPO_ROOT))
    try:
        assert owner.stdout.readline().strip() == "READY"
    finally:
        os.kill(owner.pid, signal.SIGKILL)
        owner.wait(timeout=10)
    assert (tmp_path / "state" / "owner.unclean").exists()


async def test_other_client_cannot_clear_crashed_clients_recovery_requirement(tmp_path):
    alpha, settings, log = configuration(tmp_path, "alpha")
    beta = dataclasses.replace(alpha, client_id="beta")
    crash_owner(tmp_path, settings, log)

    async with TrustMonitor(beta) as monitor:
        assert monitor.status() == ()  # beta has no records of its own
    assert not (tmp_path / "state" / "owner.unclean").exists()  # clean beta shutdown

    async with TrustMonitor(alpha) as monitor:
        record = monitor.status("custom/local")
        assert record.state is TrustState.PENDING_REVIEW
        assert record.observation_failed_at is not None
        assert any(event["event_type"] == "owner_recovered" for event in monitor.events("custom/local"))

        # Blocked before any launch, and approval is refused until a fresh observation.
        with pytest.raises(CallBlocked) as refused:
            await monitor.observe_and_call("custom/local", "effect")
        assert refused.value.reason == "pending_review"
        with pytest.raises(ObservationRequiredError):
            await monitor.approve("custom/local", revision=record.observed_revision,
                                  expected_generation=record.generation, actor="operator")

        observed = await monitor.observe("custom/local")
        assert observed.state is TrustState.PENDING_REVIEW
        assert observed.observation_failed_at is None
        with pytest.raises(CallBlocked):
            await monitor.call_tool("custom/local", "effect")
        assert calls(log) == 0

        await monitor.approve("custom/local", revision=observed.observed_revision,
                              expected_generation=observed.generation, actor="operator")
        result = await monitor.call_tool("custom/local", "effect")
        assert not result.isError and calls(log) == 1


async def test_recovery_preserves_quarantine_of_every_client(tmp_path):
    alpha, settings, log = configuration(tmp_path, "alpha")
    beta = dataclasses.replace(alpha, client_id="beta")
    async with TrustMonitor(beta) as monitor:
        record = await monitor.observe("custom/local")
        await monitor.quarantine("custom/local", actor="operator", reason="test")
    crash_owner(tmp_path, settings, log)

    async with TrustMonitor(alpha) as monitor:
        assert monitor.status("custom/local").state is TrustState.PENDING_REVIEW
    async with TrustMonitor(beta) as monitor:
        recovered = monitor.status("custom/local")
        assert recovered.state is TrustState.QUARANTINED
        assert recovered.generation > record.generation
        assert recovered.observation_failed_at is not None
