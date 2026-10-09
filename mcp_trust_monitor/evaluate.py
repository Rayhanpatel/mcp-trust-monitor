"""Fixed evaluation cases through the M3 decision path (REQ-EVAL-01, REQ-EVAL-02).

Each case in `fixtures/tool_changes.json` is assessed exactly as the monitor would:
real Semgrep hard-deny detection, then the model with scoped Senso policy, then
validation. The applied outcome is `quarantined` when a hard denial or a validated
model quarantine applies, otherwise `pending_review`. Expectations come from the
fixture and are never adjusted. Every case is reported, including misses; all data
is `synthetic_fixture`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import demo_server as demo
from .assessor import AssessmentRejected, ModelError, ReviewContext, validate_assessment
from .detector import DetectorError, scan_tools
from .policy import policy_rule_ids
from .revision import server_revision
from .senso import RetrievedPolicy, SensoError


@dataclass
class CaseResult:
    case_id: str
    expected_outcome: str
    actual_outcome: str
    expected_hard_deny: list[str]
    actual_hard_deny: list[str] | None  # None when the detector failed
    model: str  # validated recommendation, or rejected/failed with the stage
    model_policy_ids: list[str]
    verdict: str
    detail: str = ""


def verdict(expected: str, actual: str) -> str:
    if expected == actual:
        return "pass"
    if expected == "quarantined" and actual == "pending_review":
        return "blocked miss"  # still blocked, but not quarantined as the policy requires
    return "false quarantine" if actual == "quarantined" else "mismatch"


def evaluate_cases(
    fixture: Mapping[str, Any],
    policy_path: Path,
    *,
    retrieve: Callable[[], RetrievedPolicy],
    assess: Callable[[ReviewContext, Sequence[Mapping[str, Any]], RetrievedPolicy], Any],
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
        try:
            hard_deny: list[str] | None = list(scan_tools(tools, known_policy_ids=known).policy_ids)
        except DetectorError as exc:
            hard_deny, detector_note = None, f"detector failed: {exc}"[:200]
        else:
            detector_note = ""
        model, model_ids, note = "failed: retrieval", [], ""
        if retrieved is not None:
            context = ReviewContext(server_id=demo.MUTABLE_SERVER, revision=server_revision(tools),
                                    generation=1, tools=tools, rule_ids=tuple(sorted(known)),
                                    source_content_ids=retrieved.content_ids)
            try:
                validated = validate_assessment(assess(context, (baseline,), retrieved), context)
                model, model_ids = validated.recommendation, list(validated.policy_ids)
            except ModelError as exc:
                model, note = f"failed: {exc.kind}", str(exc)[:200]
            except AssessmentRejected as exc:
                model, note = "rejected", "; ".join(exc.reasons)[:200]
        actual = "quarantined" if hard_deny or model == "quarantine" else "pending_review"
        results.append(CaseResult(
            case_id=case["id"], expected_outcome=case["expected_outcome"], actual_outcome=actual,
            expected_hard_deny=sorted(case["expected_hard_deny_policy_ids"]),
            actual_hard_deny=hard_deny, model=model, model_policy_ids=model_ids,
            verdict=verdict(case["expected_outcome"], actual),
            detail="; ".join(part for part in (detector_note, note) if part)))
    return retrieval, results


def format_report(retrieval: dict[str, Any] | str, results: Sequence[CaseResult]) -> str:
    lines = ["origin: synthetic_fixture (fixed evaluation cases, live Semgrep/Senso/OpenAI)",
             f"policy retrieval: {json.dumps(retrieval) if isinstance(retrieval, dict) else retrieval}",
             f"{'case':34} {'expected':15} {'actual':15} {'hard-deny exp/act':22} "
             f"{'model':22} verdict"]
    for r in results:
        actual_hd = "failed" if r.actual_hard_deny is None else (",".join(r.actual_hard_deny) or "-")
        hard = f"{','.join(r.expected_hard_deny) or '-'} / {actual_hd}"
        model = r.model + (f" {','.join(r.model_policy_ids)}" if r.model_policy_ids else "")
        lines.append(f"{r.case_id:34} {r.expected_outcome:15} {r.actual_outcome:15} "
                     f"{hard:22} {model:22} {r.verdict}")
        if r.detail:
            lines.append(f"    note: {r.detail}")
    passed = sum(r.verdict == "pass" for r in results)
    lines.append(f"{passed}/{len(results)} cases match their policy-defined expected outcome")
    return "\n".join(lines)


def report_json(retrieval: dict[str, Any] | str, results: Sequence[CaseResult]) -> str:
    return json.dumps({"origin": "synthetic_fixture", "retrieval": retrieval,
                       "cases": [asdict(r) for r in results]}, indent=1)
