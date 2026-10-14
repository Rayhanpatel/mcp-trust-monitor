"""Real-stdio regressions for monitor scheduling.

REQ-MON-01/REQ-ENF-04: queued and active observations are coalesced per server, so a
slow or continuously notifying server occupies at most one observation worker and
cannot starve unrelated servers; a notification during an active observation still
causes one follow-up observation. REQ-MON-02/REQ-ENF-08: automatic assessment of an
unchanged failed context is bounded, with backoff, a context-change reset and an
explicit manual reset. Metadata observation is never suppressed by that budget.
"""
import asyncio
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import POLICY_PATH
from mcp_trust_monitor.config import MonitorConfig
from mcp_trust_monitor.managed_client import CallBlocked, ServerConfig
from mcp_trust_monitor.sdk import TrustMonitor

pytestmark = pytest.mark.anyio

HELPER = Path(__file__).parent / "helpers" / "monitored_server.py"


def profile(tmp_path, server_id, **settings):
    stem = server_id.replace("/", "__")
    path = tmp_path / f"{stem}.json"
    path.write_text(json.dumps(settings))
    log = tmp_path / f"{stem}.jsonl"
    server = ServerConfig(server_id, sys.executable, (str(HELPER), str(path), str(log)),
                          origin="synthetic_fixture")
    return server, path, log


async def approve(monitor, server_id):
    record = await monitor.observe(server_id)
    await monitor.approve(server_id, revision=record.observed_revision,
                          expected_generation=record.generation, actor="operator")


async def until(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError("condition did not become true")
        await asyncio.sleep(0.01)


async def call_when_validated(monitor, server_id, seconds=5.0):
    """Call once the session is validated. A monitor refresh briefly invalidates the
    session it refreshes; retry a refusal only for that reason, never after dispatch."""
    end = time.monotonic() + seconds
    while True:
        await until(lambda: monitor.catalog(server_id), seconds)
        try:
            return await monitor.call_tool(server_id, "effect", {})
        except CallBlocked as blocked:
            if blocked.reason != "session_not_validated" or time.monotonic() > end:
                raise


def instrument_observations(monitor):
    """Count concurrent and total monitor observations per server."""
    active, peak, total = {}, {}, {}
    original = monitor.observe

    async def observe(server_id):
        active[server_id] = active.get(server_id, 0) + 1
        peak[server_id] = max(peak.get(server_id, 0), active[server_id])
        total[server_id] = total.get(server_id, 0) + 1
        try:
            return await original(server_id)
        finally:
            active[server_id] -= 1

    monitor.observe = observe
    return peak, total


async def test_slow_notifying_server_occupies_at_most_one_worker(tmp_path):
    noisy, _, _ = profile(tmp_path, "noisy", list_delay=0.4, notify_during_list=True)
    quiet, _, quiet_log = profile(tmp_path, "quiet")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"noisy": noisy, "quiet": quiet},
                           poll_interval=0.25, timeout_seconds=5, max_concurrency=4)
    async with TrustMonitor(config) as monitor:
        await approve(monitor, "quiet")
        peak, total = instrument_observations(monitor)
        await monitor.start_monitor()
        await asyncio.sleep(0.5)
        samples = empty = stale = 0
        end = time.monotonic() + 3
        while time.monotonic() < end:
            samples += 1
            empty += not monitor.catalog("quiet")
            stale += monitor.health()["servers"]["quiet"]["freshness"] == "session_stale"
            await asyncio.sleep(0.05)
        result = await call_when_validated(monitor, "quiet")
        await monitor.stop_monitor()
        assert peak.get("noisy") == 1, peak
        # Its notifications during tools/list still caused follow-up observations.
        assert total.get("noisy", 0) >= 4, total
        assert total.get("quiet", 0) >= 4, total
        # Each observation briefly withdraws a server's own catalog while it refreshes;
        # starvation shows as an expired session and a mostly empty catalog.
        assert stale == 0, f"quiet session expired in {stale}/{samples} samples"
        assert empty <= samples // 4, (empty, samples)
        assert not result.isError and quiet_log.exists()


async def test_failed_assessment_of_unchanged_context_is_bounded(tmp_path):
    server, _, _ = profile(tmp_path, "custom/local")
    attempts = []

    async def reviewer(monitor, server_id):
        attempts.append(monitor.status(server_id).observed_revision)
        return SimpleNamespace(outcome="failed")  # e.g. a persistent provider refusal

    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": server},
                           poll_interval=0.1, timeout_seconds=5, reviewer=reviewer)
    async with TrustMonitor(config) as monitor:
        peak, observations = instrument_observations(monitor)
        await monitor.start_monitor()
        await until(lambda: any(e["event_type"] == "assessment_retries_exhausted"
                                for e in monitor.events("custom/local")), 10)
        exhausted_at = observations.get("custom/local", 0)
        await asyncio.sleep(1.0)
        await monitor.stop_monitor()
        assert len(set(attempts)) == 1
        assert 1 <= len(attempts) <= 3, len(attempts)  # default budget, not one per poll
        # Observation was never suppressed by the assessment budget.
        assert observations.get("custom/local", 0) > exhausted_at, observations
        exhausted = [e for e in monitor.events("custom/local")
                     if e["event_type"] == "assessment_retries_exhausted"]
        assert len(exhausted) == 1
        assert monitor.health()["errors"].get("@review:custom/local") == "retries_exhausted"


async def test_retry_budget_resets_on_context_change_and_explicit_reset(tmp_path):
    server, settings, _ = profile(tmp_path, "custom/local")
    attempts = []

    async def reviewer(monitor, server_id):
        attempts.append(monitor.status(server_id).observed_revision)
        return SimpleNamespace(outcome="failed")

    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": server},
                           poll_interval=0.1, timeout_seconds=5, reviewer=reviewer,
                           review_max_attempts=2)
    async with TrustMonitor(config) as monitor:
        await monitor.start_monitor()
        await until(lambda: len(attempts) == 2)
        await asyncio.sleep(1.0)
        assert len(attempts) == 2  # budget for the first revision exhausted

        settings.write_text(json.dumps({"description": "A changed local test effect."}))
        await until(lambda: len(set(attempts)) == 2)  # new revision: fresh budget
        await until(lambda: len(attempts) == 4)
        await asyncio.sleep(1.0)
        assert len(attempts) == 4

        monitor.reset_review_retries("custom/local")  # explicit operator reset
        await until(lambda: len(attempts) == 6)
        await asyncio.sleep(1.0)
        assert len(attempts) == 6
        await monitor.stop_monitor()


async def test_review_budget_configuration_is_validated(tmp_path):
    server, _, _ = profile(tmp_path, "custom/local")
    config = MonitorConfig(tmp_path / "state", POLICY_PATH, {"custom/local": server})
    assert config.review_max_attempts == 3
    for value in (0, -1, 1.5, True, None):
        with pytest.raises(Exception):
            replace(config, review_max_attempts=value)
