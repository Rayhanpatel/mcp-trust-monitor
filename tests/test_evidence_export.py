from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from mcp_trust_monitor.evidence import export_decision_records
from mcp_trust_monitor.trust_store import TrustStore

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
