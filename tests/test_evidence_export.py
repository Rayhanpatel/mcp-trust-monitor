from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from conftest import LOOKUP
from mcp_trust_monitor import TrustMonitor
from mcp_trust_monitor.assessor import ModelError
from mcp_trust_monitor.evidence import export_decision_records
from mcp_trust_monitor.memory import MemoryService, SearchPassage
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from mcp_trust_monitor.senso import SensoError
from mcp_trust_monitor.trust_store import TrustStore
from test_memory_service import active
from test_openai_reviewer_adapter import Assessor, PolicySource, config

REV = "sha256:" + "1" * 64
POLICY = "customer@one#sha256:" + "2" * 64
RULES = "sha256:" + "3" * 64
LAUNCH = "sha256:" + "4" * 64
LESSON = "sha256:" + "5" * 64
SECRET = "sk-test-DoNotExportThisSyntheticCredential"
KEY = b"synthetic-operator-pseudonym-key-for-tests-only"


def event(kind="model_assessment_recorded", **overrides):
    return {"event_id": str(uuid4()), "run_id": str(uuid4()), "ts": "2026-10-12T12:30:00+00:00",
            "server_id": "customer-server", "client_id": "customer-owner", "actor": "model-reviewer",
            "event_type": kind, "revision": REV, "generation": 2, "policy_revision": POLICY,
            "from_state": "pending_review", "to_state": "pending_review", "origin": "synthetic_fixture",
            "detail": {}, **overrides}


def monitor(events, observations=()):
    return SimpleNamespace(events=lambda: events,
                           store=SimpleNamespace(observations=lambda: list(observations)))


def test_real_store_export_links_records_and_never_mutates(tmp_path):
    store = TrustStore(tmp_path / "trust.sqlite3")
    try:
        record = store.record_observation("customer-server", REV,
            [{"name": "private_tool", "description": SECRET, "inputSchema": {}}],
            provenance={"endpoint": "stdio:customer-server#" + LAUNCH, "transport": "stdio",
                        "origin": "synthetic_fixture", "server_name": SECRET,
                        "raw_tools_json": json.dumps({"metadata": SECRET})})
        detail = {"assessed_revision": REV, "assessed_generation": record.generation,
            "recommendation": "quarantine", "policy_ids": ["EXT-1"], "explanation": SECRET,
            "source_content_ids": ["customer-policy-source"],
            "policy": {"policy_id": "customer", "revision": "one", "policy_digest": "sha256:" + "2" * 64,
                       "content_ids": ["customer-policy-source"], "passages": [SECRET]},
            "policy_context": POLICY + "|rules=" + RULES + "|senso=customer-policy-source"}
        assessed = store.record_assessment_if_current("customer-server", revision=REV,
            generation=record.generation, policy_revision=POLICY, active_policy_revision=POLICY,
            detail=detail)
        applied = store.apply_hard_deny("customer-server", revision=REV, generation=record.generation,
            policy_revision=POLICY, active_policy_revision=POLICY,
            detection={**detail, "assessment_event_id": assessed.event_id}, actor="model-reviewer")
        adapter = SimpleNamespace(store=store, events=store.events)
        before = store.events(), store.outbox_status(), store.get("customer-server")
        exported = export_decision_records(adapter)
        # Deterministic for the same records under one operator key; the export ID is
        # random per export and deliberately not derived from the key.
        keyed = export_decision_records(adapter, pseudonym_key=KEY)
        again = export_decision_records(adapter, pseudonym_key=KEY)
        assert {**keyed, "pseudonymization": None} == {**again, "pseudonymization": None}
        assert before == (store.events(), store.outbox_status(), store.get("customer-server"))
        assert exported["schema_version"] == 2
        # Records follow the store's event order, so the raw IDs map to pseudonyms by position.
        raw_events = store.events()
        assert len(raw_events) == len(exported["records"])
        pid = {raw["event_id"]: row["event_id"] for raw, row in zip(raw_events, exported["records"])}
        rows = {item["event_id"]: item for item in exported["records"]}
        assert len(rows) == len(raw_events)
        model = rows[pid[assessed.event_id]]
        assert model["decision"]["recommendation"] == "quarantine"
        assert model["decision"]["validation"] == "accepted"
        assert model["decision"]["action"] == "none"
        assert model["decision"]["action_applied"] is False
        assert model["context"]["rules_digest"] == RULES
        assert model["context"]["policy_digest"] == "sha256:" + "2" * 64
        assert model["launch_identity"] == LAUNCH
        assert model["observation_id"] == exported["observations"][0]["observation_id"]
        assert model["observation_association"] == "latest_preceding_matching_revision"
        requested, applied_row = rows[pid[applied.requested_event_id]], rows[pid[applied.applied_event_id]]
        assert requested["links"]["assessment_event_id"] == pid[assessed.event_id]
        assert requested["decision"]["action_applied"] is False
        assert applied_row["links"]["quarantine_requested_event_id"] == pid[applied.requested_event_id]
        assert applied_row["decision"]["action_applied"] is True
        serialized = json.dumps(exported)
        assert SECRET not in serialized
        for raw in [*raw_events, *store.observations()]:
            assert raw.get("event_id", raw.get("observation_id")) not in serialized
    finally:
        store.close()


def test_policy_and_precedent_requested_returned_cited_id_sets_stay_separate():
    detail = {"policy_requested_content_ids": ["policy-a", "policy-b"],
        "policy": {"content_ids": ["policy-a", "policy-b"]}, "source_content_ids": ["policy-b"],
        "precedent_ids": ["lesson-a"], "memory": {
            "status": "returned", "requested_content_ids": ["memory-a", "memory-b", "memory-c"],
            "snapshot": {"enabled": True, "scope": "tenant", "registry_revision": 7,
                         "lessons": [{"body": SECRET}]},
            "passages": [{"lesson_id": "lesson-a", "version": 2, "digest": LESSON,
                          "content_id": "memory-a", "remote_version": "v3", "text": SECRET},
                         {"lesson_id": "lesson-b", "version": 1, "digest": LESSON,
                          "content_id": "memory-b", "remote_version": "v1", "text": SECRET}]}}
    row = export_decision_records(monitor([event(detail=detail)]))["records"][0]
    policy, memory = row["retrieval"]["policy"], row["retrieval"]["memory"]
    assert len(policy["requested_content_ids"]) == len(policy["returned_content_ids"]) == 2
    assert policy["cited_content_ids"] == policy["returned_content_ids"][1:]
    assert policy["requested_ids_basis"] == "explicit"
    assert len(memory["requested_content_ids"]) == 3
    assert len(memory["returned_content_ids"]) == 2
    assert memory["cited_lesson_ids"] == [memory["returned_lessons"][0]["lesson_id"]]
    assert memory["returned_lessons"][0]["version"] == 2
    assert memory["returned_lessons"][0]["digest"] == LESSON
    assert memory["registry_revision"] == 7
    assert SECRET not in json.dumps(row)


@pytest.mark.parametrize("count,level", [(0, "independent_counter_verified_blocked"),
    (None, "verification_failed"), (True, "verification_failed"), (-1, "verification_failed")])
def test_independent_verification_requires_actual_linked_complete_counter_evidence(count, level):
    applied = event("quarantine_applied", generation=3)
    verified = event("verified_blocked", generation=3, detail={"verified": True,
        "quarantine_applied_event_id": applied["event_id"], "blocked_reason": "quarantined",
        "state_after": "quarantined", "applied_generation": 3, "generation_after": 3,
        "received_before": count, "received_after": count,
        "client_dispatches_before": 1, "client_dispatches_after": 1})
    row = export_decision_records(monitor([applied, verified]))["records"][1]
    assert row["evidence"]["verification_level"] == level
    if count == 0 and type(count) is int:
        altered = deepcopy(applied)
        altered["server_id"] = "unrelated-server"
        row = export_decision_records(monitor([altered, verified]))["records"][1]
        assert row["evidence"]["verification_level"] == "verification_failed"


def test_local_block_dispatch_start_and_unknown_outcome_are_distinct():
    events = [event("call_blocked", detail={"reason": "quarantined"}),
              event("call_dispatch_started", detail={"call_id": "one-call"}),
              event("call_completed", detail={"call_id": "one-call", "outcome": "outcome_unknown"})]
    rows = export_decision_records(monitor(events))["records"]
    assert rows[0]["evidence"]["verification_level"] == "verification_unavailable"
    assert rows[0]["evidence"]["dispatch_status"] == "locally_refused_before_dispatch"
    assert rows[1]["evidence"]["dispatch_status"] == "dispatch_started"
    assert rows[2]["evidence"]["dispatch_status"] == "outcome_unknown"
    assert rows[1]["links"]["call_id"] == rows[2]["links"]["call_id"]
    assert all(row["evidence"]["received_before"] is None for row in rows)


def test_free_text_and_credential_identifiers_cannot_escape_allowlist():
    dirty = event("unknown-" + SECRET, server_id="https://user:" + SECRET + "@example.invalid",
        actor="Bearer " + SECRET, client_id=SECRET, revision=SECRET, policy_revision=SECRET,
        origin=SECRET, detail={"observation_id": [SECRET], "call_id": SECRET,
            "recommendation": SECRET, "error_type": SECRET, "error": SECRET,
            "explanation": SECRET, "arguments": {"password": SECRET}, "metadata": SECRET,
            "policy": {"policy_id": SECRET, "revision": SECRET, "content_ids": [SECRET]},
            "source_content_ids": [SECRET], "policy_ids": [SECRET], "reason": SECRET,
            "response": {"response_id": SECRET, "model": SECRET,
                         "usage": {"input_tokens": SECRET, "output_tokens": True}},
            "memory": {"requested_content_ids": [SECRET], "passages": [{"lesson_id": SECRET,
                         "version": SECRET, "digest": SECRET, "content_id": SECRET,
                         "remote_version": SECRET, "source_version_id": SECRET, "text": SECRET}]}})
    dirty["extra_unreviewed_key"] = SECRET
    exported = export_decision_records(monitor([dirty]))
    serialized = json.dumps(exported)
    assert SECRET not in serialized
    assert "https://user:" not in serialized
    row = exported["records"][0]
    # A UUID-shaped event ID is pseudonymized like every other identifier (schema 2).
    assert row["event_id"].startswith("pid:") and dirty["event_id"] not in serialized
    assert row["event_type"] == "unrecognized"
    assert row["decision"]["recommendation"] is None
    assert row["origin"] == "unrecorded"
    assert row["model_response"]["usage"]["output_tokens"] is None
    assert row["links"]["call_id"] == row["retrieval"]["policy"]["cited_content_ids"][0]


def test_failed_retrieval_does_not_fabricate_returned_or_cited_sources():
    failed = event("model_assessment_failed", detail={"stage": "retrieval", "error": SECRET,
        "policy_requested_content_ids": ["policy-a"], "error_type": "SensoError"})
    row = export_decision_records(monitor([failed]))["records"][0]
    assert row["decision"]["validation"] == "failed"
    assert row["decision"]["failure_stage"] == "retrieval"
    assert len(row["retrieval"]["policy"]["requested_content_ids"]) == 1
    assert row["retrieval"]["policy"]["returned_content_ids"] is None
    assert row["retrieval"]["policy"]["cited_content_ids"] is None
    assert row["launch_identity"] is None
    assert row["observation_association"] == "not_recorded"


def test_old_decision_uses_historical_launch_evidence_without_current_state():
    first = {"observation_id": str(uuid4()), "server_id": "customer-server", "revision": REV,
        "generation": 1, "ts": "2026-10-12T12:00:00+00:00", "endpoint": "stdio:old#" + LAUNCH,
        "transport": "stdio", "origin": "synthetic_fixture"}
    future = {**first, "observation_id": str(uuid4()), "ts": "2026-10-12T13:00:00+00:00",
              "endpoint": "stdio:new#" + RULES}
    exported = export_decision_records(monitor([event("approved")], [first, future]))
    row = exported["records"][0]
    assert row["launch_identity"] == LAUNCH
    assert row["observation_id"] == exported["observations"][0]["observation_id"]
    assert row["observation_id"] != exported["observations"][1]["observation_id"]
    assert first["observation_id"] not in json.dumps(exported)
    assert row["decision"]["recommendation"] is None
    assert row["decision"]["action"] == "operator_approval"


# Reviewer failure provenance: real stdio observation and store, local fakes only.

POLICY_SOURCE = "policy-source"


class ModelFails(Assessor):
    def assess(self, *args):
        raise ModelError("api_error", SECRET)


class PolicySourceFails(PolicySource):
    def search_context(self, query, content_ids, max_results=20):
        raise SensoError(SECRET)


def reviewer(*, assessor=Assessor, source=None, backend=None):
    return OpenAIReviewer(api_key="not-real", model="test", senso_client=source or PolicySource(),
        policy_content_ids=(POLICY_SOURCE,), assessor_factory=assessor,
        memory_enabled=backend is not None, memory_backend=backend)


def exports(owned):
    """Default export plus two operator-key exports, each record keyed by its raw event ID."""
    raw = owned.events()
    exported = export_decision_records(owned)
    keyed = export_decision_records(owned, pseudonym_key=KEY)
    again = export_decision_records(owned, pseudonym_key=KEY)
    assert keyed["records"] == again["records"] and keyed["observations"] == again["observations"]
    assert len(raw) == len(exported["records"]) == len(keyed["records"])
    rows = {item["event_id"]: row for item, row in zip(raw, exported["records"])}
    keyed_rows = {item["event_id"]: row for item, row in zip(raw, keyed["records"])}
    return raw, exported, rows, keyed_rows


def failure(raw, stage, count=1):
    found = [item for item in raw if item["event_type"] == "model_assessment_failed"
             and item["detail"]["stage"] == stage]
    assert len(found) == count, [item["detail"] for item in raw]
    return found


def assert_no_raw_identifiers(exported, raw, *values):
    serialized = json.dumps(exported)
    for value in (POLICY_SOURCE, LOOKUP, SECRET, "model-reviewer", "test-response", *values,
                  *(item["event_id"] for item in raw), *(item["run_id"] for item in raw)):
        assert not isinstance(value, str) or value not in serialized, value


@pytest.mark.anyio
async def test_reviewer_failures_export_known_policy_provenance(env):
    async with TrustMonitor(config(env)) as owned:
        await owned.observe(LOOKUP)
        model_failed = await reviewer(assessor=ModelFails)(owned, LOOKUP)
        retrieval_failed = await reviewer(source=PolicySourceFails())(owned, LOOKUP)
        succeeded = await reviewer()(owned, LOOKUP)
        assert (model_failed.stage, retrieval_failed.stage, succeeded.stage) == (
            "model", "retrieval", "completed")
        raw, exported, rows, keyed_rows = exports(owned)
    [model_event], [retrieval_event] = failure(raw, "model"), failure(raw, "retrieval")
    assert model_event["detail"]["policy_returned_content_ids"] == [POLICY_SOURCE]
    assert "policy" not in model_event["detail"]  # the failure record has no policy dict
    assert retrieval_event["detail"]["policy_returned_content_ids"] is None
    success_event = next(item for item in raw if item["event_id"] == succeeded.assessment_event_id)

    model, retrieval, success = (rows[item["event_id"]] for item in
                                 (model_event, retrieval_event, success_event))
    requested = success["retrieval"]["policy"]["requested_content_ids"]
    assert len(requested) == 1 and requested[0].startswith("pid:")
    # Failure after completed policy retrieval: returned is known, and nothing was cited.
    assert model["decision"]["failure_stage"] == "model"
    assert model["retrieval"]["policy"] == {"requested_content_ids": requested,
        "requested_ids_basis": "explicit", "returned_content_ids": requested,
        "cited_content_ids": None}
    # Failure before policy retrieval completed: returned stays unavailable.
    assert retrieval["decision"]["failure_stage"] == "retrieval"
    assert retrieval["retrieval"]["policy"] == {"requested_content_ids": requested,
        "requested_ids_basis": "explicit", "returned_content_ids": None,
        "cited_content_ids": None}
    # A successful record is unchanged: returned from policy.content_ids, cited separately.
    assert success["retrieval"]["policy"] == {"requested_content_ids": requested,
        "requested_ids_basis": "explicit", "returned_content_ids": requested,
        "cited_content_ids": requested}
    # Memory was disabled for every attempt; the failures now say so instead of null.
    for row in (model, retrieval, success):
        assert row["retrieval"]["memory"]["status"] == "disabled"
        assert row["retrieval"]["memory"]["enabled"] is False
    assert model["retrieval"]["memory"]["cited_lesson_ids"] is None
    assert retrieval["retrieval"]["memory"]["cited_lesson_ids"] is None
    assert retrieval["retrieval"]["memory"]["returned_content_ids"] is None
    assert success["retrieval"]["memory"]["cited_lesson_ids"] == []
    keyed_model = keyed_rows[model_event["event_id"]]["retrieval"]["policy"]
    assert keyed_model["returned_content_ids"] == keyed_model["requested_content_ids"]
    assert keyed_model["requested_content_ids"] != requested  # a different key, a different pseudonym
    assert_no_raw_identifiers(exported, raw)


@pytest.mark.anyio
async def test_memory_failures_export_known_status_enabled_and_policy_provenance(env):
    async with TrustMonitor(config(env)) as owned:
        await owned.observe(LOOKUP)
        memory = MemoryService(owned.store, lambda: owned.policy, rule_ids=("POL-001", "POL-002"))
        lesson, backend = await active(memory)
        not_attempted = await reviewer(source=PolicySourceFails(), backend=backend)(owned, LOOKUP)
        backend.search_results = [SearchPassage("foreign-content", lesson.body)]
        memory_failed = await reviewer(assessor=ModelFails, backend=backend)(owned, LOOKUP)
        backend.search_results = None
        model_failed = await reviewer(assessor=ModelFails, backend=backend)(owned, LOOKUP)
        assert [(item.stage, item.memory_status) for item in (not_attempted, memory_failed, model_failed)] == [
            ("retrieval", "not_attempted"), ("retrieval", "retrieval_failed"), ("model", "returned")]
        raw, exported, rows, keyed_rows = exports(owned)
    first, second = failure(raw, "retrieval", 2)
    [third] = failure(raw, "model")
    not_attempted_row, memory_failed_row, model_row = (rows[item["event_id"]] for item in (first, second, third))
    lesson_ids = model_row["retrieval"]["memory"]["requested_content_ids"]
    policy_ids = model_row["retrieval"]["policy"]["requested_content_ids"]
    assert len(lesson_ids) == len(policy_ids) == 1 and lesson_ids != policy_ids

    # Policy retrieval failed first: neither policy nor memory returned anything.
    assert not_attempted_row["retrieval"]["policy"]["returned_content_ids"] is None
    assert not_attempted_row["retrieval"]["memory"] == {
        "status": "not_attempted", "enabled": True, "scope_id": None, "registry_revision": None,
        "requested_content_ids": [], "returned_content_ids": None, "cited_lesson_ids": None,
        "returned_lessons": []}
    # Policy retrieval completed, memory retrieval failed: policy returned is known.
    assert memory_failed_row["retrieval"]["policy"]["returned_content_ids"] == policy_ids
    assert memory_failed_row["retrieval"]["policy"]["cited_content_ids"] is None
    assert memory_failed_row["retrieval"]["memory"]["status"] == "retrieval_failed"
    assert memory_failed_row["retrieval"]["memory"]["enabled"] is True
    assert memory_failed_row["retrieval"]["memory"]["requested_content_ids"] == lesson_ids
    assert memory_failed_row["retrieval"]["memory"]["returned_content_ids"] is None
    assert memory_failed_row["retrieval"]["memory"]["returned_lessons"] == []
    # Both retrievals completed, then the model failed: returned known, nothing cited.
    assert model_row["retrieval"]["policy"]["returned_content_ids"] == policy_ids
    assert model_row["retrieval"]["policy"]["cited_content_ids"] is None
    assert model_row["retrieval"]["memory"]["status"] == "returned"
    assert model_row["retrieval"]["memory"]["enabled"] is True
    assert model_row["retrieval"]["memory"]["returned_content_ids"] == lesson_ids
    assert model_row["retrieval"]["memory"]["cited_lesson_ids"] is None
    keyed = keyed_rows[second["event_id"]]["retrieval"]
    assert keyed["policy"]["returned_content_ids"] == keyed["policy"]["requested_content_ids"]
    assert keyed["memory"]["status"] == "retrieval_failed" and keyed["memory"]["enabled"] is True
    assert_no_raw_identifiers(exported, raw, lesson.content_id, lesson.node_id, lesson.lesson_id,
                              lesson.series_id, lesson.verdict_id, lesson.body, "foreign-content",
                              "opaque-version-uuid")


def test_failure_provenance_fallbacks_accept_only_known_shapes_and_vocabulary():
    base = {"stage": "model", "policy_requested_content_ids": ["policy-a"]}
    accepted = event("model_assessment_failed", detail={**base,
        "policy_returned_content_ids": ["policy-a"],
        "memory": {"status": "retrieval_failed", "enabled": True,
                   "requested_content_ids": ["memory-a"], "returned_content_ids": None}})
    malformed = [event("model_assessment_failed", detail={**base, "policy_returned_content_ids": value,
                       "memory": {"status": status, "enabled": enabled}})
                 for value, status, enabled in (("policy-a", SECRET, "true"), (["policy-a", 7], "Retrieval_Failed", 1),
                                                ({"policy-a": True}, "not attempted", None), (1, ["not_attempted"], 0))]
    # Success records keep their own sources: the policy dict wins and the snapshot wins.
    success = event(detail={**base, "policy": {"content_ids": ["policy-a"]},
        "policy_returned_content_ids": ["policy-b"], "source_content_ids": ["policy-a"],
        "memory": {"status": "none_eligible", "enabled": False, "snapshot": {"enabled": True}}})
    rows = export_decision_records(monitor([accepted, *malformed, success]))["records"]
    policy_a = rows[0]["retrieval"]["policy"]["requested_content_ids"]
    assert rows[0]["retrieval"]["policy"]["returned_content_ids"] == policy_a
    assert rows[0]["retrieval"]["memory"]["status"] == "retrieval_failed"
    assert rows[0]["retrieval"]["memory"]["enabled"] is True
    for row in rows[1:-1]:
        assert row["retrieval"]["policy"]["returned_content_ids"] is None
        assert row["retrieval"]["memory"]["status"] is None
        assert row["retrieval"]["memory"]["enabled"] is None
    assert rows[-1]["retrieval"]["policy"]["returned_content_ids"] == policy_a
    assert rows[-1]["retrieval"]["policy"]["cited_content_ids"] == policy_a
    assert rows[-1]["retrieval"]["memory"]["status"] == "none_eligible"
    assert rows[-1]["retrieval"]["memory"]["enabled"] is True
    assert SECRET not in json.dumps(rows)
