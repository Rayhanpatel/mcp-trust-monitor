"""Model review stage (M3): scoped Senso policy, OpenAI assessment, validation, apply.

`model_review` runs after the deterministic hard-deny stage (`review.review_server`),
so a Semgrep quarantine is already committed before any external service is
called. It assesses the server's current revision:

1. Retrieve the operator policy from Senso, scoped to the configured content IDs
   and verified against the policy file (REQ-SRC-01).
2. Ask the model for a `review` or `quarantine` recommendation (REQ-DEC-02).
3. Validate traceability (REQ-DEC-03).
4. Apply a validated quarantine through the same guarded transition as hard-deny
   matches, bound to the revision, generation, and policy context. Here the policy
   context also covers the Senso content IDs and the policy digest.

Model events (`model_assessment_recorded`, `model_assessment_rejected`,
`model_assessment_failed`) are distinct from Semgrep findings, and model-applied
quarantines carry actor `model-reviewer` and `source: model`. A model can never
approve, and a `review` never weakens an existing quarantine. Retrieval, model,
or validation failures leave the state exactly as it was: quarantine stays, and
other changed revisions stay blocked in `pending_review` (REQ-DEC-04).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .assessor import (AssessmentRejected, ModelError, ReviewContext, ValidatedAssessment,
                       validate_assessment)
from .managed_client import ManagedClient
from .policy import load_policy, policy_rule_ids
from .senso import RetrievedPolicy, SensoError
from .trust_store import HardDenyOutcome, TrustState

ACTOR = "model-reviewer"
ASSESSABLE = (TrustState.UNREVIEWED, TrustState.PENDING_REVIEW, TrustState.QUARANTINED)

Retriever = Callable[[], RetrievedPolicy]
Assess = Callable[[ReviewContext, Sequence[Mapping[str, Any]], RetrievedPolicy], Any]


def model_policy_context(policy_binding: str, content_ids: Sequence[str],
                         policy_digest: str) -> str:
    return (f"{policy_binding}|senso={','.join(sorted(content_ids))}"
            f"|policy-digest={policy_digest}")


@dataclass
class ModelReviewReport:
    server_id: str
    outcome: str  # quarantined | already_quarantined | pending_review | stale | failed | skipped
    stage: str | None = None  # where a failure happened: retrieval | model | validation
    error: str | None = None
    revision: str | None = None
    generation: int | None = None
    retrieved: dict[str, Any] | None = None
    raw: Any = None
    validated: ValidatedAssessment | None = None
    rejected: list[str] = field(default_factory=list)
    quarantine: HardDenyOutcome | None = None
    model: str | None = None
    response_id: str | None = None


async def model_review(
    client: ManagedClient,
    server_id: str,
    *,
    policy_path: Path,
    retrieve: Retriever,
    assess: Assess,
    configured_content_ids: Callable[[], Sequence[str]],
    model: str | None = None,
    response_id: Callable[[], str | None] = lambda: None,
) -> ModelReviewReport:
    record = client.store.get(server_id)
    report = ModelReviewReport(server_id, "skipped", model=model)
    if record is None or record.observed_revision is None or record.state not in ASSESSABLE:
        return report
    report.revision, report.generation = record.observed_revision, record.generation
    base = {"assessed_revision": record.observed_revision,
            "assessed_generation": record.generation, "model": model, "source": "model"}

    def failed(stage: str, error: str) -> ModelReviewReport:
        report.outcome, report.stage, report.error = "failed", stage, error[:500]
        client.store.record_event(server_id, "model_assessment_failed", actor=ACTOR,
                                  detail={**base, "stage": stage, "error": report.error,
                                          "state_unchanged": record.state.value})
        return report

    try:
        retrieved = await asyncio.to_thread(retrieve)
    except (SensoError, OSError, ValueError, KeyError) as exc:
        return failed("retrieval", f"{type(exc).__name__}: {exc}")
    report.retrieved = retrieved.as_dict()
    context = ReviewContext(server_id=server_id, revision=record.observed_revision,
                            generation=record.generation, tools=record.observed_tools,
                            rule_ids=tuple(sorted(policy_rule_ids(policy_path))),
                            source_content_ids=retrieved.content_ids)
    previous: Sequence[Mapping[str, Any]] = ()
    if record.approved_revision and record.approved_revision != record.observed_revision:
        previous = client.store.reviewed_tools_for_revision(
            server_id, record.approved_revision) or ()
    try:
        report.raw = await asyncio.to_thread(assess, context, previous, retrieved)
    except ModelError as exc:
        return failed("model", str(exc))
    finally:
        report.response_id = response_id()
    try:
        validated = validate_assessment(report.raw, context)
    except AssessmentRejected as exc:
        report.outcome, report.stage, report.rejected = "failed", "validation", list(exc.reasons)
        client.store.record_event(server_id, "model_assessment_rejected", actor=ACTOR,
                                  detail={**base, "reasons": report.rejected,
                                          "response_id": report.response_id,
                                          "state_unchanged": record.state.value})
        return report
    report.validated = validated
    assessed_context = model_policy_context(client.policy_revision, retrieved.content_ids,
                                            retrieved.policy_digest)
    detail = {**base, **validated.as_dict(), "policy": retrieved.as_dict(),
              "policy_context": assessed_context, "response_id": report.response_id}
    client.store.record_event(server_id, "model_assessment_recorded", actor=ACTOR, detail=detail)

    if validated.recommendation == "review":
        # Never weakens anything: a quarantine stays, a pending change stays blocked.
        report.outcome = ("already_quarantined" if record.state is TrustState.QUARANTINED
                          else "pending_review")
        return report
    if record.state is TrustState.QUARANTINED:
        report.outcome = "already_quarantined"  # e.g. a hard denial was applied first
        return report

    def active_context() -> str:
        policy = load_policy(policy_path)
        return model_policy_context(policy.binding, configured_content_ids(), policy.digest)

    outcome = await client.apply_hard_deny(
        server_id, revision=record.observed_revision, generation=record.generation,
        policy_context=assessed_context, active_policy_context=active_context,
        detection={**detail, "policy_ids": list(validated.policy_ids)}, actor=ACTOR)
    report.quarantine = outcome
    report.outcome = {"applied": "quarantined", "already_quarantined": "already_quarantined",
                      "stale": "stale"}[outcome.status]
    return report
