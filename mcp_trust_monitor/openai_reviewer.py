"""Optional OpenAI + scoped Senso review adapter, with guarded local decisions."""
from __future__ import annotations

import asyncio
import inspect
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Sequence

from .assessor import ReviewContext
from .async_assessor import AsyncOpenAIAssessor
from .memory import MemoryService, MemoryStale
from .memory.assessment import (MEMORY_INSTRUCTIONS, memory_input, memory_schema,
                                validate_memory_assessment)
from .policy import load_policy, policy_rule_ids
from .senso import SensoClient, retrieve_policy_async
from .trust_store import StorageFaultError, TrustError


def _policy_query(path) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    rules = document["rules"]
    prefix = "Operator policy " + document["policy_id"] + " rules " + " ".join(rule["id"] for rule in rules)
    if len(prefix) > 2000:
        raise ValueError("policy identifiers exceed the retrieval query bound")
    requirements = " ".join(rule["requirement"] for rule in rules)
    return (prefix + " requirements " + requirements)[:2000]


@dataclass(frozen=True)
class ReviewAttempt:
    server_id: str
    outcome: str
    stage: str
    assessment_event_id: str | None = None
    recommendation: str | None = None
    policy_ids: tuple[str, ...] = ()
    precedent_ids: tuple[str, ...] = ()
    memory_status: str = "disabled"
    response: dict[str, Any] = field(default_factory=dict)
    error_type: str | None = None


class OpenAIReviewer:
    """Explicit SDK reviewer; memory is off unless deliberately enabled.

    Each assessment owns its model client/metadata. The same immutable snapshot is
    checked before network work, after retrieval, after the model, and in SQLite's
    final decision transaction. No model recommendation can approve a tool.
    """
    def __init__(self, *, api_key: str, model: str, senso_client: SensoClient,
                 policy_content_ids: Sequence[str], memory_enabled: bool = False,
                 memory_backend=None, memory_scope: str = "default", top_k: int = 3,
                 max_retries: int = 0, timeout_seconds: float = 90,
                 max_output_tokens: int = 8000, assessor_factory=AsyncOpenAIAssessor) -> None:
        if not api_key or not model or not policy_content_ids:
            raise ValueError("explicit OpenAI model, credentials and policy sources are required")
        if memory_enabled and memory_backend is None:
            raise ValueError("enabled memory requires a verified backend")
        self._api_key = api_key
        self.model, self.senso_client = model, senso_client
        self.policy_content_ids = tuple(policy_content_ids)
        self.memory_enabled, self.memory_backend = memory_enabled, memory_backend
        self.memory_scope, self.top_k = memory_scope, top_k
        self.max_retries, self.timeout_seconds = max_retries, timeout_seconds
        self.max_output_tokens, self.assessor_factory = max_output_tokens, assessor_factory

    async def __call__(self, monitor, server_id: str) -> ReviewAttempt:
        record = monitor.status(server_id)
        if record is None or record.observed_revision is None:
            raise ValueError("observation required before review")
        policy = monitor.policy
        path = monitor.policy_path
        known = tuple(sorted(policy_rule_ids(path)))
        memory = MemoryService(monitor.store, lambda: monitor.policy,
                               rule_ids=known, scope=self.memory_scope)
        initial = memory.snapshot(enabled=self.memory_enabled)
        ids = self.policy_content_ids
        configuration = (self.model, ids, self.memory_enabled, self.memory_scope,
                         id(self.memory_backend), self.max_retries, self.top_k,
                         self.timeout_seconds, self.max_output_tokens,
                         id(self.senso_client), id(self.assessor_factory))
        detector = monitor.detector_binding
        rules = detector.rules_digest if detector else "disabled"
        context_binding = policy.binding + "|rules=" + rules + "|senso=" + ",".join(sorted(ids))
        assessor = None
        retrieved_policy = retrieved_memory = None
        memory_retrieval_attempted = False
        observed_context = None
        stage = "context"

        def guard():
            current_configuration = (self.model, self.policy_content_ids, self.memory_enabled,
                self.memory_scope, id(self.memory_backend), self.max_retries, self.top_k,
                self.timeout_seconds, self.max_output_tokens,
                id(self.senso_client), id(self.assessor_factory))
            if current_configuration != configuration:
                return "review configuration changed"
            if monitor.policy.binding != policy.binding or load_policy(path).binding != policy.binding:
                return "policy changed"
            if monitor.detector_binding != detector:
                return "detector configuration changed"
            if detector is not None:
                from .detector import rules_digest_of
                if rules_digest_of(detector.rules_path.read_bytes()) != rules:
                    return "detector rules changed"
            if monitor.config.servers[server_id].launch_identity != record.launch_identity:
                return "launch identity changed"
            observed_error = monitor.assessment_stale_reason(observed_context)
            if observed_error:
                return observed_error
            return memory.guard(initial)

        def assert_current():
            error = guard()
            current = monitor.status(server_id)
            if error or current is None or current.observed_revision != record.observed_revision or current.generation != record.generation:
                raise MemoryStale(error or "server revision/generation changed")

        try:
            try:
                observed_context = monitor.assessment_context(server_id)
            except StorageFaultError:
                raise
            except TrustError:
                raise MemoryStale("assessment requires a current session observation") from None
            assert_current()
            stage = "retrieval"
            retrieved_policy = await retrieve_policy_async(self.senso_client, ids, path, query=_policy_query(path))
            assert_current()
            # Generic, bounded query contains only configured metadata, never tool arguments.
            query = "Operator-reviewed precedents for tool metadata change: " + " ".join(
                tool.get("description", "") for tool in record.observed_tools)
            memory_retrieval_attempted = True
            retrieved_memory = await memory.retrieve(query, self.memory_backend,
                enabled=self.memory_enabled, top_k=self.top_k)
            assert_current()
            if retrieved_memory.snapshot != initial:
                raise MemoryStale("memory snapshot changed during retrieval")
            context = ReviewContext(server_id, record.observed_revision, record.generation,
                                    record.observed_tools, known, retrieved_policy.content_ids)
            previous = (monitor.store.reviewed_tools_for_revision(server_id, record.approved_revision)
                        if record.approved_revision else ()) or ()
            assessor = self.assessor_factory(self._api_key, self.model,
                max_retries=self.max_retries, timeout_seconds=self.timeout_seconds,
                max_output_tokens=self.max_output_tokens, instructions=MEMORY_INSTRUCTIONS,
                input_builder=lambda ctx, prev, pol: memory_input(ctx, prev, pol, retrieved_memory),
                schema_builder=lambda rules: memory_schema(rules, retrieved_memory.lesson_ids))
            stage = "model"
            if inspect.iscoroutinefunction(assessor.assess):
                raw = await assessor.assess(context, previous, retrieved_policy)
            else:
                # Explicit legacy/test injection only. Production uses AsyncOpenAIAssessor.
                raw = await asyncio.to_thread(assessor.assess, context, previous, retrieved_policy)
            assert_current()
            stage = "validation"
            validated = validate_memory_assessment(raw, context, retrieved_memory)
            detail = {"assessed_revision": record.observed_revision,
                      "assessed_generation": record.generation, "policy_context": context_binding,
                      "assessment_context": asdict(observed_context),
                      "policy": retrieved_policy.as_dict(), "memory": retrieved_memory.as_dict(),
                      "policy_requested_content_ids": list(ids),
                      "policy_returned_content_ids": list(retrieved_policy.content_ids),
                      "response": assessor.response_metadata(), **validated.as_dict(),
                      "origin": record.origin}
            stage = "apply"
            accepted = await monitor.client.record_assessment_if_current(server_id,
                revision=record.observed_revision, generation=record.generation,
                policy_context=context_binding, active_policy_context=lambda: context_binding,
                detail=detail, context_guard=guard)
            if accepted.status == "stale":
                raise MemoryStale(accepted.reason or "assessment is stale")
            outcome = monitor.status(server_id).state.value
            if validated.recommendation == "quarantine":
                applied = await monitor.client.apply_hard_deny(server_id,
                    revision=record.observed_revision, generation=record.generation,
                    policy_context=context_binding, active_policy_context=lambda: context_binding,
                    detection={**detail, "assessment_event_id": accepted.event_id},
                    actor="model-reviewer", context_guard=guard)
                if applied.status == "stale":
                    raise MemoryStale(applied.reason or "decision is stale")
                outcome = "quarantined"
            return ReviewAttempt(server_id, outcome, "completed", accepted.event_id,
                validated.recommendation, validated.assessment.policy_ids, validated.precedent_ids,
                retrieved_memory.status, assessor.response_metadata())
        except StorageFaultError:
            raise  # Authoritative failure cannot become an optional-adapter error/retry.
        except Exception as exc:
            # Persist classifications, never arbitrary remote error bodies or credentials.
            response = assessor.response_metadata() if assessor else {}
            stale = isinstance(exc, MemoryStale)
            memory_status = (retrieved_memory.status if retrieved_memory else "disabled" if not initial.enabled
                             else "retrieval_failed" if memory_retrieval_attempted else "not_attempted")
            memory_detail = (retrieved_memory.as_dict() if retrieved_memory else
                {"status": memory_status, "enabled": initial.enabled,
                 "requested_content_ids": [lesson.content_id for lesson in initial.lessons]
                    if memory_retrieval_attempted else [],
                 "returned_content_ids": None})
            monitor.store.record_event(server_id, "assessment_stale" if stale else "model_assessment_failed",
                actor="model-reviewer", detail={"stage": stage, "error_type": type(exc).__name__,
                    "assessed_revision": record.observed_revision, "assessed_generation": record.generation,
                    "policy_context": context_binding, "response": response,
                    "policy_requested_content_ids": list(ids),
                    "policy_returned_content_ids": list(retrieved_policy.content_ids) if retrieved_policy else None,
                    "memory": memory_detail})
            return ReviewAttempt(server_id, "stale" if stale else "failed", stage,
                                 memory_status=memory_status, response=response, error_type=type(exc).__name__)
        finally:
            if assessor is not None:
                close = getattr(assessor, "aclose", None) or getattr(getattr(assessor, "_client", None), "close", None)
                if close:
                    try:
                        if inspect.iscoroutinefunction(close):
                            await asyncio.wait_for(close(), timeout=min(1.0, monitor.config.shutdown_timeout / 2))
                        else:
                            await asyncio.to_thread(close)  # explicit injected synchronous fake/legacy adapter
                    except Exception as exc:
                        # A cleanup error must not replace a completed decision's outcome.
                        if not monitor.store.faulted:
                            monitor.store.record_event(server_id, "model_client_cleanup_failed",
                                actor="model-reviewer", detail={"error_type": type(exc).__name__})
