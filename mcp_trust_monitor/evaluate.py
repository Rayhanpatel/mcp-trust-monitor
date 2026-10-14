"""Fixed evaluation cases through the M3 decision path (REQ-EVAL-01, REQ-EVAL-02).

Each case in `fixtures/tool_changes.json` is assessed as the monitor would assess
it: real Semgrep hard-deny detection, then the model with scoped Senso policy, then
validation. Nothing is applied to a trust record, so every outcome here is
*computed, not applied*. The computed outcome is `quarantined` when a hard denial or
a validated model quarantine applies, otherwise `pending_review`.

A stage error is not a decision. If the detector, retrieval, the model call, or
validation fails, the verdict is `error`, never `pass` or a miss, even when the
fail-closed computed outcome happens to equal the expectation. The combined verdict
(detector and model) and the model-only verdict are reported separately; a model
stage error makes both `error`, and a detector error makes the combined verdict
`error`. Each case records its own response ID, model, and usage, or None when no
response was received. Expectations come from the fixture and are never adjusted.
Every case is reported, including misses; all data is `synthetic_fixture`.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import demo_server as demo
from .assessor import AssessmentRejected, ModelError, ReviewContext, validate_assessment
from .detector import DetectorError, scan_tools
from .policy import policy_rule_ids
from .revision import server_revision
from .senso import RetrievedPolicy, SensoError

VERDICT_CLASSES = ("pass", "blocked miss", "false quarantine", "mismatch", "error")
VALID_RECOMMENDATIONS = ("review", "quarantine")


@dataclass
class CaseResult:
    case_id: str
    expected_outcome: str
    computed_outcome: str  # what the decision path would apply; computed, not applied
    expected_hard_deny: list[str]
    actual_hard_deny: list[str] | None  # detector output; None when the detector failed
    model: str  # validated recommendation, "rejected", or "failed: <stage or kind>"
    model_policy_ids: list[str]
    verdict: str  # combined detector and model verdict; "error" if a required stage failed
    model_only_verdict: str  # the validated model recommendation alone; "error" otherwise
    detector_status: str  # matched | clean | error
    errors: list[str] = field(default_factory=list)  # failed stages, in order
    response: dict[str, Any] | None = None  # this case's own response metadata, if received
    detail: str = ""


def verdict(expected: str, actual: str) -> str:
    """Verdict for a valid decision only; callers classify stage errors as `error`."""
    if expected == actual:
        return "pass"
    if expected == "quarantined" and actual == "pending_review":
        return "blocked miss"  # still blocked, but not quarantined as the policy requires
    return "false quarantine" if actual == "quarantined" else "mismatch"


def _received(metadata: Callable[[], Mapping[str, Any] | None] | None) -> dict[str, Any] | None:
    """This attempt's response metadata, or None when no response was received."""
    if metadata is None:
        return None
    value = metadata()
    if not value or all(item is None for item in value.values()):
        return None
    return dict(value)


def evaluate_cases(
    fixture: Mapping[str, Any],
    policy_path: Path,
    *,
    retrieve: Callable[[], RetrievedPolicy],
    assess: Callable[[ReviewContext, Sequence[Mapping[str, Any]], RetrievedPolicy], Any],
    response_metadata: Callable[[], Mapping[str, Any] | None] | None = None,
) -> tuple[dict[str, Any] | str, list[CaseResult]]:
    known = policy_rule_ids(policy_path)
    baseline = demo.baseline_definition(dict(fixture), demo.MUTABLE_SERVER)
    try:
        retrieved: RetrievedPolicy | None = retrieve()
        retrieval: dict[str, Any] | str = retrieved.as_dict()
    except (SensoError, OSError, ValueError, KeyError) as exc:
        retrieved, retrieval = None, f"failed: {type(exc).__name__}: {exc}"[:300]
    results = []
    for case in fixture["scenarios"]:
        tools = (demo.scenario_definition(dict(fixture), case["id"]),)
        errors: list[str] = []
        try:
            hard_deny: list[str] | None = list(scan_tools(tools, known_policy_ids=known).policy_ids)
        except DetectorError as exc:
            hard_deny, detector_note = None, f"detector failed: {exc}"[:200]
            errors.append("detector")
        else:
            detector_note = ""
        detector_status = "error" if hard_deny is None else ("matched" if hard_deny else "clean")
        model, model_ids, note, response = "failed: retrieval", [], "", None
        if retrieved is None:
            errors.append("retrieval")
        else:
            context = ReviewContext(server_id=demo.MUTABLE_SERVER, revision=server_revision(tools),
                                    generation=1, tools=tools, rule_ids=tuple(sorted(known)),
                                    source_content_ids=retrieved.content_ids)
            try:
                try:
                    raw = assess(context, (baseline,), retrieved)
                finally:
                    response = _received(response_metadata)
                validated = validate_assessment(raw, context)
                model, model_ids = validated.recommendation, list(validated.policy_ids)
            except ModelError as exc:
                model, note = f"failed: {exc.kind}", str(exc)[:200]
                errors.append("model")
            except AssessmentRejected as exc:
                model, note = "rejected", "; ".join(exc.reasons)[:200]
                errors.append("validation")
        expected = case["expected_outcome"]
        computed = "quarantined" if hard_deny or model == "quarantine" else "pending_review"
        model_valid = model in VALID_RECOMMENDATIONS
        model_only = "quarantined" if model == "quarantine" else "pending_review"
        results.append(CaseResult(
            case_id=case["id"], expected_outcome=expected, computed_outcome=computed,
            expected_hard_deny=sorted(case["expected_hard_deny_policy_ids"]),
            actual_hard_deny=hard_deny, model=model, model_policy_ids=model_ids,
            verdict=verdict(expected, computed) if model_valid and hard_deny is not None
            else "error",
            model_only_verdict=verdict(expected, model_only) if model_valid else "error",
            detector_status=detector_status, errors=errors, response=response,
            detail="; ".join(part for part in (detector_note, note) if part)))
    return retrieval, results


def summarize(results: Sequence[CaseResult], attribute: str) -> dict[str, int]:
    counts = Counter(getattr(result, attribute) for result in results)
    return {name: counts.get(name, 0) for name in VERDICT_CLASSES}


def _counts(summary: Mapping[str, int]) -> str:
    return ", ".join(f"{name} {count}" for name, count in summary.items())


def format_report(retrieval: dict[str, Any] | str, results: Sequence[CaseResult], *,
                  model_config: Mapping[str, Any] | None = None) -> str:
    lines = ["origin: synthetic_fixture (fixed evaluation cases, live Semgrep/Senso/OpenAI)",
             "outcomes are computed by the decision path, not applied to any trust record",
             f"policy retrieval: {json.dumps(retrieval) if isinstance(retrieval, dict) else retrieval}"]
    if model_config:
        lines.append(f"model: {model_config.get('name')}, "
                     f"SDK max_retries {model_config.get('max_retries')}")
    lines.append(f"{'case':34} {'expected':15} {'computed':15} {'hard-deny exp/act':22} "
                 f"{'model':22} {'combined':17} model-only")
    for r in results:
        actual_hd = "failed" if r.actual_hard_deny is None else (",".join(r.actual_hard_deny) or "-")
        hard = f"{','.join(r.expected_hard_deny) or '-'} / {actual_hd}"
        model = r.model + (f" {','.join(r.model_policy_ids)}" if r.model_policy_ids else "")
        lines.append(f"{r.case_id:34} {r.expected_outcome:15} {r.computed_outcome:15} "
                     f"{hard:22} {model:22} {r.verdict:17} {r.model_only_verdict}")
        if r.errors:
            lines.append(f"    stage errors: {', '.join(r.errors)}")
        if r.detail:
            lines.append(f"    note: {r.detail}")
    lines.append(f"combined (detector and model), {len(results)} cases: "
                 f"{_counts(summarize(results, 'verdict'))}")
    lines.append(f"model-only, {len(results)} cases: "
                 f"{_counts(summarize(results, 'model_only_verdict'))}")
    if any(r.errors for r in results):
        lines.append("errors are stage failures, not decisions; they never count as passes or misses")
    return "\n".join(lines)


def report_json(retrieval: dict[str, Any] | str, results: Sequence[CaseResult], *,
                model_config: Mapping[str, Any] | None = None) -> str:
    return json.dumps({"origin": "synthetic_fixture", "outcomes": "computed, not applied",
                       "retrieval": retrieval, "model": dict(model_config or {}) or None,
                       "summary": {"combined": summarize(results, "verdict"),
                                   "model_only": summarize(results, "model_only_verdict")},
                       "cases": [asdict(r) for r in results]}, indent=1)
