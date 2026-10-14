import asyncio
import json
import threading
from pathlib import Path

import pytest

from mcp_trust_monitor import MonitorConfig, TrustMonitor
from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from conftest import LOOKUP, POLICY_PATH, FIXTURE_PATH

pytestmark = pytest.mark.anyio


class PolicySource:
    def __init__(self, path=POLICY_PATH):
        self.path = path

    def search_context(self, query, content_ids, max_results=20):
        return {"results": [{"content_id": content_ids[0], "chunk_text": self.path.read_text()}]}


class Assessor:
    started = None
    release = None

    def __init__(self, key, model, **kwargs):
        self.kwargs = kwargs

    def assess(self, context, previous, policy):
        assert "untrusted_precedents" in self.kwargs["input_builder"](context, previous, policy)
        assert "precedent_ids" in self.kwargs["schema_builder"](context.rule_ids)["required"]
        if self.started:
            self.started.set()
            assert self.release.wait(5)
        return {"server_id": context.server_id, "revision": context.revision,
            "generation": context.generation, "recommendation": "review", "policy_ids": [],
            "source_content_ids": list(context.source_content_ids), "evidence": [],
            "explanation": "No current policy violation found; explicit approval remains necessary.",
            "precedent_ids": []}

    def response_metadata(self):
        return {"response_id": "test-response", "model": "test", "usage": {"total_tokens": 1}}


def config(env, policy=POLICY_PATH):
    return MonitorConfig(env.state_dir, policy,
        {LOOKUP: demo.server_config(LOOKUP, env.state_dir, FIXTURE_PATH)})


def adapter(source=None):
    return OpenAIReviewer(api_key="test-key", model="test", senso_client=source or PolicySource(),
        policy_content_ids=("policy-source",), assessor_factory=Assessor)


async def test_review_records_guarded_evidence_and_never_approves(env):
    async with TrustMonitor(config(env)) as monitor:
        before = await monitor.observe(LOOKUP)
        result = await adapter()(monitor, LOOKUP)
        assert result.stage == "completed", result
        assert result.outcome == "unreviewed"
        assert result.memory_status == "disabled"
        assert monitor.status(LOOKUP).generation == before.generation
        event = next(e for e in monitor.events() if e["event_id"] == result.assessment_event_id)
        assert event["event_type"] == "model_assessment_recorded"
        assert event["detail"]["response"]["response_id"] == "test-response"


async def test_policy_reload_uses_new_public_path(env, tmp_path):
    path = tmp_path / "policy.json"
    policy = json.loads(POLICY_PATH.read_text())
    policy["revision"] = "new"
    path.write_text(json.dumps(policy))
    async with TrustMonitor(config(env)) as monitor:
        await monitor.observe(LOOKUP)
        await monitor.reload_policy(path)
        result = await adapter(PolicySource(path))(monitor, LOOKUP)
        assert result.stage == "completed", result


async def test_quarantine_during_model_rejects_stale_review(env):
    started, release = threading.Event(), threading.Event()
    Assessor.started, Assessor.release = started, release
    try:
        async with TrustMonitor(config(env)) as monitor:
            await monitor.observe(LOOKUP)
            task = asyncio.create_task(adapter()(monitor, LOOKUP))
            assert await asyncio.to_thread(started.wait, 5)
            await monitor.quarantine(LOOKUP, actor="operator", reason="independent decision")
            release.set()
            result = await task
            assert result.outcome == "stale"
            assert monitor.status(LOOKUP).state.value == "quarantined"
            assert not any(e["event_type"] == "model_assessment_recorded" for e in monitor.events())
    finally:
        release.set()
        Assessor.started = Assessor.release = None
