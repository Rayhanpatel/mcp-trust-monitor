"""Automatic review after a detector reload uses the new decision context (REQ-MON-02, REQ-DEC-06).

Corrective follow-up: the scheduler keyed its retry budget on the policy binding alone.
A detector reload under an unchanged policy reset the budget while the old detector's
scan was still running; that scan then returned stale under the same key and used up
the new detector's budget, so with `review_max_attempts=1` the new detector never ran
until a manual `reset_review_retries`. The key is now the activated decision binding.

Each test uses a real stdio server (its own call log is independent evidence that no
tool call was made) and local fake detectors whose scans block on an event.
"""
from __future__ import annotations

import asyncio
import sys
import threading
from pathlib import Path

import pytest

from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor
from mcp_trust_monitor.detector import DetectorError, DetectorResult, Evidence, HardDenyMatch
from mcp_trust_monitor.trust_store import TrustState

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tests" / "helpers" / "monitored_server.py"
POLICY = ROOT / "policies" / "demo-policy.json"
SERVER, HELD = "scheduling/test", "scheduling/held"
POLL = 0.15
WAIT = 10.0


class Detector:
    """A local fake detector; `scan` runs in a worker thread and can be held."""

    def __init__(self, version: str, *, blocked: bool = False, outcome: str = "clean"):
        self.rules_digest = "sha256:" + version * 64
        self.started, self.release = threading.Event(), threading.Event()
        self.outcome, self.calls = outcome, 0
        if not blocked:
            self.release.set()

    def validate(self, path):
        return None

    def scan(self, tools, path):
        self.calls += 1
        self.started.set()
        assert self.release.wait(WAIT)
        if self.outcome == "fail":
            raise DetectorError("synthetic scanner failure")
        matches = ()
        if self.outcome == "match":
            tool = tools[0]
            text = "local"
            start = tool["description"].index(text)
            matches = (HardDenyMatch("synthetic-rule", "POL-001",
                                     Evidence(tool["name"], "description", start, start + len(text), text)),)
        return DetectorResult(matches, self.rules_digest, "synthetic", len(tools))


def environment(tmp_path: Path, detector: Detector, servers=(SERVER,)):
    (tmp_path / "settings.json").write_text("{}")
    calls = tmp_path / "calls.jsonl"
    profiles = {sid: ServerConfig(sid, sys.executable,
                                  (str(HELPER), str(tmp_path / "settings.json"), str(calls)),
                                  origin="synthetic_fixture") for sid in servers}
    return MonitorConfig(tmp_path / "state", POLICY, profiles, poll_interval=POLL,
                         timeout_seconds=5, detector=detector, review_max_attempts=1), calls


async def until(predicate, what: str):
    deadline = asyncio.get_running_loop().time() + WAIT
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.01)


def events(monitor, kind: str, server_id: str = SERVER):
    return [event for event in monitor.events(server_id) if event["event_type"] == kind]


async def approve(monitor, server_id: str = SERVER):
    record = await monitor.observe(server_id)
    return await monitor.approve(server_id, revision=record.observed_revision,
                                 expected_generation=record.generation, actor="synthetic-operator")


async def reload_during_old_scan(monitor, old: Detector, new: Detector):
    """Start monitoring, hold the old detector's scan, reload the new one, release it."""
    resets = []
    original = monitor._loop.reset_review_retries
    await monitor.start_monitor()
    await until(old.started.is_set, "the old detector's scan to start")
    await monitor.reload_policy(POLICY, new)
    monitor._loop.reset_review_retries = lambda *args: resets.append(args) or original(*args)
    old.release.set()
    return resets


def clean_scans_by(monitor, detector: Detector):
    return [event for event in events(monitor, "hard_deny_scan_clean")
            if event["detail"].get("rules_digest") == detector.rules_digest]


async def test_new_detector_runs_after_reload_during_an_old_scan(tmp_path):
    old, new = Detector("1", blocked=True), Detector("2")
    config, calls = environment(tmp_path, old)
    async with TrustMonitor(config) as monitor:
        approved = await approve(monitor)
        resets = await reload_during_old_scan(monitor, old, new)
        await until(lambda: clean_scans_by(monitor, new), "the new detector's automatic scan")
        # The old scan was discarded as stale, and charged nothing to the new context.
        assert [event["detail"]["reason"] for event in events(monitor, "assessment_stale")
                if event["detail"].get("rules_digest") == old.rules_digest]
        assert events(monitor, "assessment_retries_exhausted") == []
        assert "@review:" + SERVER not in monitor.health()["errors"]
        assert resets == []  # no manual retry reset was needed
        assert new.calls >= 1 and old.calls == 1
        # Approval invalidation is preserved: a clean scan never approves.
        current = monitor.status(SERVER)
        assert current.state is TrustState.PENDING_REVIEW
        assert current.generation > approved.generation
        assert events(monitor, "approval_invalidated")
        await monitor.stop_monitor()
    assert not calls.exists()  # the server never received a tools/call


async def test_new_detector_hard_denial_applies_and_quarantine_is_preserved(tmp_path):
    old, new = Detector("1", blocked=True), Detector("2", outcome="match")
    config, calls = environment(tmp_path, old, servers=(SERVER, HELD))
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        await approve(monitor, HELD)
        held = await monitor.quarantine(HELD, actor="operator", reason="held across the reload")
        await reload_during_old_scan(monitor, old, new)
        await until(lambda: any(event["detail"].get("rules_digest") == new.rules_digest
                                for event in events(monitor, "quarantine_requested")),
                    "the new detector's hard denial")
        assert monitor.status(SERVER).state is TrustState.QUARANTINED
        assert events(monitor, "quarantine_applied")
        # The quarantine made before the reload stays; only its generation advanced.
        after = monitor.status(HELD)
        assert after.state is TrustState.QUARANTINED and after.generation > held.generation
        assert events(monitor, "decision_context_invalidated", HELD)
        assert events(monitor, "assessment_retries_exhausted") == []
        await monitor.stop_monitor()
    assert not calls.exists()


async def test_the_new_context_keeps_its_own_bounded_retry_budget(tmp_path):
    old, new = Detector("1", blocked=True), Detector("2", outcome="fail")
    config, calls = environment(tmp_path, old)
    async with TrustMonitor(config) as monitor:
        await approve(monitor)
        resets = await reload_during_old_scan(monitor, old, new)
        await until(lambda: events(monitor, "assessment_retries_exhausted"),
                    "the new context's retry budget to be used")
        exhausted, = events(monitor, "assessment_retries_exhausted")
        assert exhausted["detail"]["policy_binding"] == monitor.decision_binding
        assert exhausted["detail"]["last_outcome"] == "failed"
        await asyncio.sleep(8 * POLL)  # several more polls: no further automatic attempt
        assert new.calls == 1 and resets == []
        assert len(events(monitor, "detector_failed")) == 1
        assert len(events(monitor, "assessment_retries_exhausted")) == 1
        assert monitor.health()["errors"]["@review:" + SERVER] == "retries_exhausted"
        assert monitor.status(SERVER).state is TrustState.PENDING_REVIEW
        # An explicit reset still re-arms exactly one more bounded attempt.
        monitor.reset_review_retries(SERVER)
        await until(lambda: new.calls == 2, "the re-armed attempt")
        await monitor.stop_monitor()
    assert not calls.exists()
