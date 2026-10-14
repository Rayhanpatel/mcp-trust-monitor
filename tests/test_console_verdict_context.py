"""`MemoryService.verdict_context` offers exactly what `record_verdict` accepts (R9, REQ-MEM-01).

The console reads verdict choices from the store for one observation, so a bounded
timeline can never hide a valid assessment. Both use one eligibility rule; this test
checks parity over accepted, wrong-server, wrong-generation, wrong-policy, malformed
policy-prefix and stale assessment records.
"""
from __future__ import annotations

import pytest

from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.memory.types import MemoryIntegrityError
from mcp_trust_monitor.policy import PolicyRef
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.trust_store import TrustStore

POLICY = PolicyRef("verdict-context", "1", "digest")


def observe(store, server_id, description):
    tools = ({"name": "notes", "description": description, "inputSchema": {"type": "object"}},)
    record = store.record_observation(server_id, server_revision(tools), tools,
                                      provenance={"origin": "synthetic_fixture"})
    return record, store.observations(server_id)[-1]["observation_id"]


def assess(store, record, policy_revision, *, active=None, actor="synthetic-reviewer"):
    return store.record_assessment_if_current(
        record.server_id, revision=record.observed_revision, generation=record.generation,
        policy_revision=policy_revision, active_policy_revision=active or policy_revision,
        detail={"synthetic_assessment": True}, actor=actor).event_id


def test_verdict_context_matches_record_verdict_exactly(tmp_path):
    store = TrustStore(tmp_path / "trust.sqlite3")
    try:
        memory = MemoryService(store, POLICY, rule_ids=("POL-001",))
        binding = POLICY.binding
        record, first = observe(store, "s", "Read notes.")
        other, _ = observe(store, "t", "Another server.")
        candidates = [
            assess(store, record, binding),                                   # accepted
            assess(store, record, binding + "|rules=sha256:x", actor="hard-deny-detector"),  # accepted
            assess(store, record, "other-policy@1#x"),                        # other policy
            assess(store, record, binding + "x"),                             # not a binding prefix
            assess(store, record, binding, active="other-policy@1#x"),        # recorded stale
            assess(store, other, binding),                                    # other server
        ]
        requested = store.apply_hard_deny("s", revision=record.observed_revision,
            generation=record.generation, policy_revision=binding + "|rules=sha256:x",
            active_policy_revision=binding + "|rules=sha256:x",
            detection={"policy_ids": ["POL-001"], "synthetic": True}).requested_event_id
        candidates.append(requested)                                          # accepted
        _, second = observe(store, "s", "Changed notes.")                     # New generation.
        results = {}
        for observation_id in (first, second):
            offered = {event["event_id"] for event in memory.verdict_context(observation_id)["assessments"]}
            accepted = set()
            for event_id in candidates:
                try:
                    memory.record_verdict(observation_id=observation_id, assessment_event_id=event_id,
                                          value="uncertain", actor="operator", rationale="parity check")
                except MemoryIntegrityError:
                    continue
                accepted.add(event_id)
            assert offered == accepted
            results[observation_id] = accepted
        assert results[first] == {candidates[0], candidates[1], requested}
        assert results[second] == set()  # The second observation has no assessment of its own.
        context = memory.verdict_context(first)
        assert context["observation"]["server_id"] == "s"
        assert context["observation"]["reviewed_tools"][0]["description"] == "Read notes."
        assert context["policy_binding"] == binding
        assert len(memory.verdict_context(first, limit=1)["assessments"]) == 1
        with pytest.raises(MemoryIntegrityError):
            memory.verdict_context("missing")
        with pytest.raises(ValueError):
            memory.verdict_context(first, limit=0)
    finally:
        store.close()


def test_verdict_context_follows_the_active_policy(tmp_path):
    store = TrustStore(tmp_path / "trust.sqlite3")
    active = {"policy": POLICY}
    try:
        memory = MemoryService(store, lambda: active["policy"], rule_ids=("POL-001",))
        record, observation = observe(store, "s", "Read notes.")
        event_id = assess(store, record, POLICY.binding)
        assert [e["event_id"] for e in memory.verdict_context(observation)["assessments"]] == [event_id]
        active["policy"] = PolicyRef("verdict-context", "2", "digest-2")
        assert memory.verdict_context(observation)["assessments"] == []
        with pytest.raises(MemoryIntegrityError):
            memory.record_verdict(observation_id=observation, assessment_event_id=event_id,
                                  value="uncertain", actor="operator", rationale="old policy")
    finally:
        store.close()
