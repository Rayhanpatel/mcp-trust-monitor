"""Trust state machine rules, checked directly against the persisted store."""

import pytest

from mcp_trust_monitor.trust_store import (ObservationRequiredError, StaleDecisionError,
                                           TrustError, TrustState, TrustStore)

POLICY = "demo-workspace-policy@2#sha256:test"
TOOLS_A = [{"name": "t", "description": "A", "inputSchema": {"type": "object"}}]
TOOLS_B = [{"name": "t", "description": "B", "inputSchema": {"type": "object"}}]


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "trust.sqlite3")


def approve(store, record, **overrides):
    decision = dict(revision=record.observed_revision, policy_revision=POLICY,
                    expected_generation=record.generation, actor="test")
    decision.update(overrides)
    return store.approve(record.server_id, **decision)


def test_first_observation_is_unreviewed_not_approved(store):
    """REQ-TRU-01"""
    record = store.record_observation("s", "rev-a", TOOLS_A)
    assert record.state is TrustState.UNREVIEWED
    assert record.approved_revision is None


def test_change_invalidates_approval_and_stale_decisions_cannot_authorize(store):
    """REQ-TRU-02, REQ-TRU-03"""
    a = store.record_observation("s", "rev-a", TOOLS_A)
    approved = approve(store, a)
    b = store.record_observation("s", "rev-b", TOOLS_B)
    assert b.state is TrustState.PENDING_REVIEW
    assert b.generation > approved.generation

    with pytest.raises(StaleDecisionError):  # decision about the old revision
        approve(store, a)
    with pytest.raises(StaleDecisionError):  # right revision, decided before a later change
        approve(store, b, expected_generation=b.generation - 1)
    assert store.get("s").state is TrustState.PENDING_REVIEW

    assert approve(store, b).state is TrustState.APPROVED


def test_returning_to_a_previously_approved_revision_does_not_restore_approval(store):
    """REQ-TRU-03, REQ-TRU-05"""
    approve(store, store.record_observation("s", "rev-a", TOOLS_A))
    store.record_observation("s", "rev-b", TOOLS_B)
    reverted = store.record_observation("s", "rev-a", TOOLS_A)
    assert reverted.state is TrustState.PENDING_REVIEW


def test_quarantine_persists_and_is_lifted_only_by_explicit_restore(store, tmp_path):
    """REQ-TRU-04"""
    approve(store, store.record_observation("s", "rev-a", TOOLS_A))
    store.quarantine("s", actor="test", reason="test")
    store.close()

    reopened = TrustStore(tmp_path / "trust.sqlite3")
    # Neither a new revision nor a return to the original revision lifts quarantine.
    assert reopened.record_observation("s", "rev-b", TOOLS_B).state is TrustState.QUARANTINED
    record = reopened.record_observation("s", "rev-a", TOOLS_A)
    assert record.state is TrustState.QUARANTINED
    with pytest.raises(TrustError):
        approve(reopened, record)

    restored = approve(reopened, record, restore=True)
    assert restored.state is TrustState.APPROVED
    assert [e["event_type"] for e in reopened.events("s")][-1] == "restored"


def test_duplicate_decisions_have_no_repeated_side_effects(store):
    """REQ-TRU-06"""
    a = store.record_observation("s", "rev-a", TOOLS_A)
    first = approve(store, a)
    events = len(store.events("s"))
    second = approve(store, a)
    assert second.generation == first.generation
    assert len(store.events("s")) == events

    quarantined = store.quarantine("s", actor="test", reason="first")
    events = len(store.events("s"))
    again = store.quarantine("s", actor="test", reason="retry")
    assert again.generation == quarantined.generation
    assert len(store.events("s")) == events


def test_observation_failure_invalidates_approval_and_preserves_quarantine(store):
    """REQ-REV-02: one transaction moves approved to pending review and records the failure."""
    approved = approve(store, store.record_observation("s", "rev-a", TOOLS_A))
    failed = store.record_observation_failure("s", actor="test", error="boom")
    assert failed.state is TrustState.PENDING_REVIEW
    assert failed.generation == approved.generation + 1
    assert failed.observed_revision == "rev-a"
    event = store.events("s")[-1]
    assert (event["event_type"], event["from_state"], event["to_state"]) == (
        "observation_failed", "approved", "pending_review")
    # A decision made before the failure is refused until fresh evidence exists...
    with pytest.raises(ObservationRequiredError):
        approve(store, approved)
    # ...and remains stale after it, because the generation has moved on.
    store.record_observation("s", "rev-a", TOOLS_A)
    with pytest.raises(StaleDecisionError):
        approve(store, approved)

    store.quarantine("s", actor="test", reason="test")
    assert store.record_observation_failure("s", actor="test", error="boom").state is (
        TrustState.QUARANTINED)

    assert store.record_observation_failure("unknown", actor="test", error="boom") is None
    assert store.events("unknown")[-1]["event_type"] == "observation_failed"


def test_approval_and_restore_require_a_successful_observation_after_failure(store, tmp_path):
    """REQ-REV-02: recovery needs fresh evidence first, then an explicit decision."""
    approve(store, store.record_observation("s", "rev-a", TOOLS_A))
    failed = store.record_observation_failure("s", actor="test", error="boom")
    assert failed.observation_failed_at is not None
    with pytest.raises(ObservationRequiredError):  # stored revision and current generation
        approve(store, failed)
    store.close()

    reopened = TrustStore(tmp_path / "trust.sqlite3")  # persisted across restart
    persisted = reopened.get("s")
    assert persisted.observation_failed_at == failed.observation_failed_at
    with pytest.raises(ObservationRequiredError):
        approve(reopened, persisted)

    # Unchanged metadata is recovery evidence: it clears the requirement, bumps the
    # generation so earlier decisions are stale, and never restores approval itself.
    recovered = reopened.record_observation("s", "rev-a", TOOLS_A)
    assert recovered.observation_failed_at is None
    assert recovered.state is TrustState.PENDING_REVIEW
    assert recovered.generation == persisted.generation + 1
    assert reopened.events("s")[-1]["event_type"] == "observation_recovered"
    with pytest.raises(StaleDecisionError):
        approve(reopened, persisted)

    # Another failure before approval re-arms the requirement.
    reopened.record_observation_failure("s", actor="test", error="again")
    with pytest.raises(ObservationRequiredError):
        approve(reopened, reopened.get("s"))
    assert approve(reopened, reopened.record_observation("s", "rev-a", TOOLS_A)).state is (
        TrustState.APPROVED)


def test_restore_of_quarantine_requires_a_successful_observation_after_failure(store):
    """REQ-REV-02, REQ-TRU-04: a failure keeps quarantine and also gates its restore."""
    approve(store, store.record_observation("s", "rev-a", TOOLS_A))
    store.quarantine("s", actor="test", reason="test")
    failed = store.record_observation_failure("s", actor="test", error="boom")
    assert failed.state is TrustState.QUARANTINED
    with pytest.raises(ObservationRequiredError):
        approve(store, failed, restore=True)
    recovered = store.record_observation("s", "rev-a", TOOLS_A)
    assert recovered.state is TrustState.QUARANTINED  # observation never lifts quarantine
    assert approve(store, recovered, restore=True).state is TrustState.APPROVED


def test_approval_records_policy_revision(store):
    """REQ-TRU-02: trust is scoped to the policy revision as well as the metadata revision."""
    record = approve(store, store.record_observation("s", "rev-a", TOOLS_A))
    assert record.approved_policy_revision == POLICY
