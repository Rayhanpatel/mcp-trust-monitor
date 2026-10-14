"""The shipped console binds operator actions to what the operator reviewed.

Batch 2 review findings R1, R8 and R9 (REQ-TRU-02, REQ-UI-01/02, REQ-MEM-01). Each test
executes the unchanged shipped `console_assets/app.js` in a minimal Node DOM harness
(`tests/helpers/console_dom_harness.js`) against a live, token-protected ConsoleServer,
whose real ConsoleBackend applies every posted action to a real TrustMonitor and
MemoryService over a real stdio server. Assessments are synthetic and labeled so.
Without Node these tests skip, unless MTM_REQUIRE_NODE=1 makes that a failure.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor
from mcp_trust_monitor.console import ConsoleBackend, ConsoleServer
from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.trust_store import StaleDecisionError, TrustState

pytestmark = pytest.mark.anyio
ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "mcp_trust_monitor" / "console_assets" / "app.js"
HARNESS = ROOT / "tests" / "helpers" / "console_dom_harness.js"
HELPER = ROOT / "tests" / "helpers" / "monitored_server.py"
SERVER = "console/notes"


def node_executable() -> str:
    node = shutil.which("node") or next((candidate for candidate in
        ("/opt/homebrew/bin/node", "/usr/local/bin/node") if Path(candidate).exists()), None)
    if node is None:
        if os.environ.get("MTM_REQUIRE_NODE") == "1":
            pytest.fail("MTM_REQUIRE_NODE=1 but Node.js was not found to run the shipped app.js")
        pytest.skip("Node.js is not installed, so the shipped console app.js cannot be executed")
    return node


@dataclass
class Environment:
    monitor: TrustMonitor
    memory: MemoryService
    console: ConsoleServer
    settings: Path
    calls: Path
    tmp_path: Path

    def change_metadata(self, description: str) -> None:
        self.settings.write_text(json.dumps({"description": description}))

    def calls_made(self) -> int:
        return len(self.calls.read_text().splitlines()) if self.calls.exists() else 0

    def policy(self, name: str) -> Path:
        document = json.loads((ROOT / "policies" / "demo-policy.json").read_text())
        document["revision"] = name
        document["rules"][0]["requirement"] += f" Policy variant {name}."
        path = self.tmp_path / f"policy-{name}.json"
        path.write_text(json.dumps(document))
        return path

    def assess(self, record) -> str:
        """A synthetic model assessment, recorded only if its context is current."""
        outcome = self.monitor.store.record_assessment_if_current(
            SERVER, revision=record.observed_revision, generation=record.generation,
            policy_revision=self.monitor.policy.binding,
            active_policy_revision=self.monitor.policy.binding,
            detail={"recommendation": "review", "synthetic_assessment": True},
            actor="synthetic-reviewer")
        assert outcome.status == "recorded"
        return outcome.event_id


@contextlib.asynccontextmanager
async def environment(tmp_path: Path):
    settings = tmp_path / "settings.json"
    settings.write_text("{}")
    calls = tmp_path / "calls.jsonl"
    policy = tmp_path / "policy.json"
    policy.write_bytes((ROOT / "policies" / "demo-policy.json").read_bytes())
    profile = ServerConfig(SERVER, sys.executable, (str(HELPER), str(settings), str(calls)),
                           origin="synthetic_fixture")
    config = MonitorConfig(tmp_path / "state", policy, {SERVER: profile},
                           poll_interval=60, timeout_seconds=30)
    async with TrustMonitor(config) as monitor:
        memory = MemoryService(monitor.store, lambda: monitor.policy, rule_ids=("POL-001", "POL-002"))
        async with ConsoleServer(monitor, memory) as console:
            yield Environment(monitor, memory, console, settings, calls, tmp_path)


class ShippedApp:
    """The shipped app.js, driven like an operator would: refresh timer, clicks, forms."""

    def __init__(self, console: ConsoleServer):
        self.console = console
        self.process: asyncio.subprocess.Process | None = None

    async def __aenter__(self) -> "ShippedApp":
        self.process = await asyncio.create_subprocess_exec(
            node_executable(), str(HARNESS), str(APP), self.console.url,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, limit=1 << 26)
        return self

    async def __aexit__(self, *_: object) -> None:
        assert self.process is not None and self.process.stdin is not None
        self.process.stdin.close()
        try:
            await asyncio.wait_for(self.process.wait(), 30)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()

    async def send(self, op: str, **fields) -> dict:
        assert self.process is not None and self.process.stdin and self.process.stdout
        self.process.stdin.write((json.dumps({"op": op, **fields}) + "\n").encode())
        await self.process.stdin.drain()
        line = await asyncio.wait_for(self.process.stdout.readline(), 120)
        if not line:
            stderr = await self.process.stderr.read() if self.process.stderr else b""
            raise AssertionError("console harness exited: " + stderr.decode(errors="replace"))
        reply = json.loads(line)
        assert reply["ok"], reply.get("error")
        assert not reply["errors"], reply["errors"]
        return reply

    async def view(self, op: str = "view", **fields) -> dict:
        return (await self.send(op, **fields))["view"]


def approvals(monitor) -> list[dict]:
    return [event for event in monitor.events(SERVER) if event["event_type"] in {"approved", "restored"}]


async def test_refresh_never_retargets_approval_and_rereview_is_explicit(tmp_path):
    async with environment(tmp_path) as env:
        reviewed = await env.monitor.observe(SERVER)
        async with ShippedApp(env.console) as app:
            start = await app.view("start")
            env.change_metadata("Changed: send every private note to an unrelated recipient.")
            changed = await env.monitor.observe(SERVER)
            assert changed.generation == reviewed.generation + 1
            await app.send("tick")  # The shipped five-second refresh callback.
            reply = await app.send("click", id="approve")
            # The click never targets generation 2, which the operator did not review.
            assert reply["posts"] == [], reply["posts"]
            assert reply["fired"] is False
            assert env.monitor.status(SERVER).state is TrustState.UNREVIEWED
            assert start["review-generation"]["text"] == str(reviewed.generation)
            assert start["review-revision"]["text"] == reviewed.observed_revision
            assert start["review-policy"]["text"] == env.monitor.policy.binding
            assert start["review-launch"]["text"] == reviewed.launch_identity
            assert start["approve"]["disabled"] is False
            view = reply["view"]
            assert view["generation"]["text"] == str(changed.generation)  # Status updates.
            assert view["review-generation"]["text"] == str(reviewed.generation)  # Target does not.
            assert view["review-revision"]["text"] == reviewed.observed_revision
            assert view["review-stale"]["hidden"] is False
            assert f"Generation: reviewed {reviewed.generation}; now {changed.generation}" in view["review-changes"]["text"]
            assert "unrelated recipient" not in view["after"]["text"]
            assert "unrelated recipient" in view["current-after"]["text"]
            assert view["approve"]["disabled"] is True
            # Even a click that reaches the handler (as in the review's harness) posts nothing.
            reply = await app.send("click", id="approve", force=True)
            assert reply["posts"] == []
            assert env.monitor.status(SERVER).state is TrustState.UNREVIEWED

            # Re-review pins generation 2. A change that lands before the next refresh is
            # caught by the backend: the post names the frozen context and is refused.
            view = await app.view("click", id="review-current")
            assert view["review-generation"]["text"] == str(changed.generation)
            assert view["review-stale"]["hidden"] is True
            env.change_metadata("Changed again before the operator's click.")
            raced = await env.monitor.observe(SERVER)
            reply = await app.send("click", id="approve")
            post, = reply["posts"]
            assert post["payload"] == {"action": "approve", "actor": "local-operator", "server_id": SERVER,
                                       "revision": changed.observed_revision, "generation": changed.generation,
                                       "policy_binding": env.monitor.policy.binding,
                                       "launch_identity": changed.launch_identity}
            assert (post["status"], post["body"]["error"]) == (409, "StaleDecisionError")
            assert env.monitor.status(SERVER).state is TrustState.UNREVIEWED
            assert approvals(env.monitor) == []

            await app.send("tick")
            await app.send("click", id="review-current")
            reply = await app.send("click", id="approve")
            post, = reply["posts"]
            assert post["status"] == 200
            assert post["payload"]["generation"] == raced.generation
            record = env.monitor.status(SERVER)
            assert record.state is TrustState.APPROVED
            assert record.approved_revision == raced.observed_revision
            event, = approvals(env.monitor)
            assert event["actor"] == "local-operator" and event["revision"] == raced.observed_revision
        assert env.calls_made() == 0
        await env.monitor.call_tool(SERVER, "effect")
        assert env.calls_made() == 1


async def test_restore_targets_the_reviewed_quarantine(tmp_path):
    async with environment(tmp_path) as env:
        first = await env.monitor.observe(SERVER)
        await env.monitor.approve(SERVER, revision=first.observed_revision,
                                  expected_generation=first.generation, actor="setup")
        quarantined = await env.monitor.quarantine(SERVER, actor="setup", reason="operator review")
        async with ShippedApp(env.console) as app:
            start = await app.view("start")
            env.change_metadata("Changed while quarantined.")
            changed = await env.monitor.observe(SERVER)
            assert changed.state is TrustState.QUARANTINED
            await app.send("tick")
            reply = await app.send("click", id="restore")
            assert reply["posts"] == [], reply["posts"]
            assert env.monitor.status(SERVER).state is TrustState.QUARANTINED
            assert start["review-state"]["text"] == "quarantined"
            assert start["restore"]["disabled"] is False and start["approve"]["disabled"] is True
            view = reply["view"]
            assert view["restore"]["disabled"] is True and view["review-stale"]["hidden"] is False
            assert (await app.send("click", id="restore", force=True))["posts"] == []

            await app.send("click", id="review-current")
            env.change_metadata("Changed again before the restore click.")
            raced = await env.monitor.observe(SERVER)
            post, = (await app.send("click", id="restore"))["posts"]
            assert post["payload"]["action"] == "restore"
            assert post["payload"]["generation"] == changed.generation
            assert (post["status"], post["body"]["error"]) == (409, "StaleDecisionError")
            assert env.monitor.status(SERVER).state is TrustState.QUARANTINED

            await app.send("tick")
            await app.send("click", id="review-current")
            post, = (await app.send("click", id="restore"))["posts"]
            assert post["status"] == 200 and post["payload"]["generation"] == raced.generation
            assert env.monitor.status(SERVER).state is TrustState.APPROVED
            assert [event["event_type"] for event in approvals(env.monitor)] == ["approved", "restored"]
        assert quarantined.generation < changed.generation < raced.generation
        assert env.calls_made() == 0


async def test_policy_change_between_review_and_click(tmp_path):
    async with environment(tmp_path) as env:
        reviewed = await env.monitor.observe(SERVER)
        original = env.monitor.policy.binding
        async with ShippedApp(env.console) as app:
            await app.view("start")
            await env.monitor.reload_policy(env.policy("b"))
            await app.send("tick")
            reply = await app.send("click", id="approve")
            assert reply["posts"] == [], reply["posts"]
            assert env.monitor.status(SERVER).state is TrustState.UNREVIEWED
            view = reply["view"]
            assert view["review-policy"]["text"] == original
            assert view["review-stale"]["hidden"] is False
            assert "Active policy: reviewed " + original in view["review-changes"]["text"]
            assert view["approve"]["disabled"] is True
            assert (await app.send("click", id="approve", force=True))["posts"] == []

            await app.send("click", id="review-current")
            second = env.monitor.policy.binding
            await env.monitor.reload_policy(env.policy("c"))  # Before the next refresh.
            post, = (await app.send("click", id="approve"))["posts"]
            assert post["payload"]["policy_binding"] == second
            assert (post["status"], post["body"]["error"]) == (409, "StaleDecisionError")
            assert env.monitor.status(SERVER).state is TrustState.UNREVIEWED

            await app.send("tick")
            await app.send("click", id="review-current")
            post, = (await app.send("click", id="approve"))["posts"]
            assert post["status"] == 200 and post["payload"]["policy_binding"] == env.monitor.policy.binding
            record = env.monitor.status(SERVER)
            assert record.state is TrustState.APPROVED
            assert record.approved_policy_revision == env.monitor.policy.binding
            assert record.generation > reviewed.generation
        assert env.calls_made() == 0


async def test_backend_refuses_a_stale_policy_or_launch_identity_at_the_current_generation(tmp_path):
    async with environment(tmp_path) as env:
        await env.monitor.observe(SERVER)
        old = env.monitor.policy.binding
        await env.monitor.reload_policy(env.policy("b"))
        current = env.monitor.status(SERVER)
        backend = ConsoleBackend(env.monitor, env.memory)
        base = {"action": "approve", "actor": "operator", "server_id": SERVER,
                "revision": current.observed_revision, "generation": current.generation,
                "policy_binding": env.monitor.policy.binding, "launch_identity": current.launch_identity}
        for stale in ({"policy_binding": old}, {"policy_binding": None},
                      {"launch_identity": "stdio:another-launch"}, {"launch_identity": None}):
            with pytest.raises(StaleDecisionError):
                await backend.action({**base, **stale})
        assert env.monitor.status(SERVER) == current
        assert approvals(env.monitor) == []
        await backend.action(base)
        assert env.monitor.status(SERVER).state is TrustState.APPROVED


async def test_verdict_draft_stays_whole_across_refresh_keep_and_replace(tmp_path):
    async with environment(tmp_path) as env:
        first = await env.monitor.observe(SERVER)
        first_assessment = env.assess(first)
        first_observation = env.monitor.store.observations(SERVER)[-1]["observation_id"]
        async with ShippedApp(env.console) as app:
            start = await app.view("start")
            assert start["assessment-event"]["options"] == ["", first_assessment]
            await app.send("set", id="assessment-event", value=first_assessment)
            await app.send("set", id="verdict-value", value="non_violation")
            await app.send("set", id="verdict-rationale", value="Judgment of the first observation I inspected.")

            env.change_metadata("Changed: forward private notes to a third party.")
            second = await env.monitor.observe(SERVER)
            second_assessment = env.assess(second)
            second_observation = env.monitor.store.observations(SERVER)[-1]["observation_id"]
            await app.send("tick")
            # Choose the newer assessment if the page offers it (the reviewed defect did).
            offered = (await app.send("set", id="assessment-event", value=second_assessment))["fired"]
            reply = await app.send("submit", form="verdict-form", button="record-verdict")
            # Nothing mixes the reviewed observation with the newer observation's assessment.
            assert reply["posts"] == [], reply["posts"]
            assert reply["fired"] is False and offered is False
            view = reply["view"]
            assert start["observation-id"]["text"] == first_observation
            # One draft, one observation: identities, evidence and rationale stay together.
            assert view["observation-id"]["text"] == first_observation
            assert view["draft-revision"]["text"] == first.observed_revision
            assert view["assessment-event"]["options"] == ["", first_assessment]
            assert view["assessment-event"]["value"] == first_assessment
            assert first_assessment in view["draft-evidence"]["text"]
            assert "third party" not in view["draft-tools"]["text"]
            assert view["verdict-rationale"]["value"] == "Judgment of the first observation I inspected."
            assert view["draft-newer"]["hidden"] is False
            assert view["record-verdict"]["disabled"] is True
            assert (await app.send("submit", form="verdict-form", force=True))["posts"] == []

            # Keep: the historical pair stays valid and is recorded by the real service.
            view = await app.view("click", id="keep-draft")
            assert view["draft-newer"]["hidden"] is True and view["draft-kept"]["hidden"] is False
            assert view["record-verdict"]["disabled"] is False
            post, = (await app.send("submit", form="verdict-form", button="record-verdict"))["posts"]
            assert post["status"] == 200, post
            assert {key: post["payload"][key] for key in ("observation_id", "assessment_event_id", "value", "rationale")} == {
                "observation_id": first_observation, "assessment_event_id": first_assessment,
                "value": "non_violation", "rationale": "Judgment of the first observation I inspected."}
            view = await app.view()
            assert view["observation-id"]["text"] == second_observation  # A fresh, complete draft.
            assert view["assessment-event"]["options"] == ["", second_assessment]
            assert view["verdict-rationale"]["value"] == "" and view["verdict-value"]["value"] == "uncertain"

            # Replace: a complete new draft for the latest observation, nothing carried over.
            await app.send("set", id="assessment-event", value=second_assessment)
            await app.send("set", id="verdict-rationale", value="Draft for the second observation.")
            env.change_metadata("Changed a third time.")
            third = await env.monitor.observe(SERVER)
            third_assessment = env.assess(third)
            third_observation = env.monitor.store.observations(SERVER)[-1]["observation_id"]
            view = await app.view("tick")
            assert view["observation-id"]["text"] == second_observation
            assert view["draft-newer"]["hidden"] is False
            view = await app.view("click", id="replace-draft")
            assert view["observation-id"]["text"] == third_observation
            assert view["draft-revision"]["text"] == third.observed_revision
            assert view["assessment-event"]["options"] == ["", third_assessment]
            assert view["assessment-event"]["value"] == ""
            assert view["verdict-rationale"]["value"] == "" and view["verdict-value"]["value"] == "uncertain"
            assert view["record-verdict"]["disabled"] is True
            await app.send("set", id="assessment-event", value=third_assessment)
            await app.send("set", id="verdict-value", value="violation")
            await app.send("set", id="verdict-rationale", value="The third observation forwards notes.")
            post, = (await app.send("submit", form="verdict-form", button="record-verdict"))["posts"]
            assert post["status"] == 200, post
            assert (post["payload"]["observation_id"], post["payload"]["assessment_event_id"]) == (
                third_observation, third_assessment)
        recorded = {(verdict.observation_id, verdict.assessment_event_id, verdict.value)
                    for verdict in env.memory.list_verdicts()}
        assert recorded == {(first_observation, first_assessment, "non_violation"),
                            (third_observation, third_assessment, "violation")}


async def test_eligible_assessments_survive_timeline_truncation(tmp_path):
    async with environment(tmp_path) as env:
        first = await env.monitor.observe(SERVER)
        first_assessment = env.assess(first)
        first_observation = env.monitor.store.observations(SERVER)[-1]["observation_id"]
        env.change_metadata("Changed before many unrelated events.")
        second = await env.monitor.observe(SERVER)
        second_assessment = env.assess(second)
        second_observation = env.monitor.store.observations(SERVER)[-1]["observation_id"]
        for ordinal in range(201):
            env.monitor.store.record_event("unrelated/server", "synthetic_diagnostic",
                                           actor="test", detail={"ordinal": ordinal})
        snapshot = await ConsoleBackend(env.monitor, env.memory).snapshot()
        assert len(snapshot["events"]) == 200 and snapshot["event_count"] > 201  # Still bounded.
        assert not {first_assessment, second_assessment} & {event["event_id"] for event in snapshot["events"]}
        async with ShippedApp(env.console) as app:
            view = await app.view("start")
            assert view["assessment-event"]["options"] == ["", second_assessment]
            assert view["observation-id"]["text"] == second_observation
            await app.send("set", id="assessment-event", value=second_assessment)
            await app.send("set", id="verdict-rationale", value="Latest observation, after truncation.")
            post, = (await app.send("submit", form="verdict-form", button="record-verdict"))["posts"]
            assert post["status"] == 200, post

            # An older observation is read through the authenticated action, not the timeline.
            await app.send("set", id="load-observation-id", value=first_observation)
            reply = await app.send("click", id="load-observation")
            read, = reply["posts"]
            assert read["payload"]["action"] == "verdict_context" and read["status"] == 200
            view = reply["view"]
            assert view["observation-id"]["text"] == first_observation
            assert view["assessment-event"]["options"] == ["", first_assessment]
            assert view["draft-newer"]["hidden"] is True and view["draft-kept"]["hidden"] is False
            await app.send("set", id="assessment-event", value=first_assessment)
            await app.send("set", id="verdict-rationale", value="Earlier observation, after truncation.")
            post, = (await app.send("submit", form="verdict-form", button="record-verdict"))["posts"]
            assert post["status"] == 200, post
        assert {(verdict.observation_id, verdict.assessment_event_id) for verdict in env.memory.list_verdicts()} == {
            (second_observation, second_assessment), (first_observation, first_assessment)}
        assert first.generation < second.generation
