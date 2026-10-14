"""Frozen, interleaved paired evaluation; failures stay in the scheduled denominator."""
from __future__ import annotations

import hashlib
import json
import time
import asyncio
from collections import Counter
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(encoded.encode()).hexdigest()


def freeze_plan(manifest: Mapping[str, Any], *, model: str, policy_binding: str,
                rules_digest: str, memory_digest: str, max_retries: int = 0,
                pairs: int = 3, review_config: Mapping[str, Any] | None = None) -> dict[str, Any]:
    cases = manifest["held_out"]
    if type(pairs) is not int or pairs < 3 or len(cases) < 8:
        raise ValueError("release evaluation needs at least eight cases and three pairs")
    ids = [case["id"] for case in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("held-out IDs must be unique")
    counts = Counter(case["expected_outcome"] for case in cases)
    if counts["quarantined"] < 4 or counts["pending_review"] < 4:
        raise ValueError("need four benign and four policy-violation held-out cases")
    if set(ids) & {case["id"] for case in manifest["lesson_source"]}:
        raise ValueError("lesson sources cannot be evaluated as held-out cases")
    if set(counts) != {"quarantined", "pending_review"} or type(max_retries) is not int or max_retries < 0:
        raise ValueError("outcomes and retry policy must be explicit and valid")
    review_config = dict(review_config or {})
    if set(review_config) - {"top_k", "timeout_seconds", "max_output_tokens"}:
        raise ValueError("review_config may contain only nonsecret review limits")
    trials = []
    for pair in range(pairs):
        for case in cases:
            for mode in (("off", "on") if pair % 2 == 0 else ("on", "off")):
                trials.append({"trial_id": f"{case['id']}/{pair + 1}/{mode}",
                               "case_id": case["id"], "pair": pair + 1, "memory": mode,
                               "expected_outcome": case["expected_outcome"],
                               "expected_detector": case["expected_hard_deny_policy_ids"]})
    plan = {"schema_version": 1, "origin": "synthetic_fixture", "manifest_digest": digest(manifest),
            "manifest_version": manifest["manifest_version"], "model": model,
            "max_retries": max_retries, "policy_binding": policy_binding,
            "rules_digest": rules_digest, "memory_digest": memory_digest,
            "review_config": review_config,
            "independent_cases": len(cases),
            "families": sorted({case["family"] for case in cases}), "pairs_per_case": pairs,
            "trials": trials, "replacement_policy": "no outcome-based replacement",
            "cost": "unavailable unless separately calculated from usage and dated rates"}
    plan["plan_digest"] = digest(plan)
    return plan


def _verdict(expected: str, actual: str | None) -> str:
    if actual not in {"pending_review", "quarantined"}:
        return "error"
    if actual == expected:
        return "pass"
    return "false quarantine" if actual == "quarantined" else "blocked miss"


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    # Within-case counts first; repeated trials are not independent cases.
    cases: dict[str, Any] = {}
    for result in results:
        case = cases.setdefault(result["case_id"], {})
        counts = case.setdefault(result["memory"], Counter())
        counts[result["verdict"]] += 1
    return {"scheduled_trials": len(results),
            "attempted_trials": sum(r.get("status") != "not_started" for r in results),
            "by_case": cases,
            "by_mode": {mode: dict(Counter(r["verdict"] for r in results if r["memory"] == mode))
                        for mode in ("off", "on")},
            "model_only_by_mode": {mode: dict(Counter(r["model_only_verdict"] for r in results
                                                       if r["memory"] == mode)) for mode in ("off", "on")},
            "limitations": "Exploratory fixed cases; repeated trials are not independent. "
                           "No significance, generalization, or improvement claim is implied."}


def _gate(report: Mapping[str, Any]) -> dict[str, Any]:
    rows = report["results"]
    errors = [r["trial_id"] for r in rows if r["verdict"] == "error" or r["model_only_verdict"] == "error"]
    unexpected = [r["trial_id"] for r in rows if r.get("detector_matches_expectation") is False]
    regressions = []
    for case_id, modes in summarize(rows)["by_case"].items():
        for outcome in ("false quarantine", "blocked miss"):
            if modes.get("on", {}).get(outcome, 0) > modes.get("off", {}).get(outcome, 0):
                regressions.append({"case_id": case_id, "outcome": outcome,
                    "off": modes.get("off", {}).get(outcome, 0), "on": modes.get("on", {}).get(outcome, 0)})
    complete = report["complete"] and all(r.get("status") != "not_started" for r in rows)
    return {"release_blocked": not complete or bool(errors) or bool(unexpected),
            "complete": complete, "error_trials": errors, "unexpected_detector_trials": unexpected,
            "semantic_regressions_requiring_review": regressions,
            "scope": "Evaluation integrity only; independent enforcement and memory-integrity proofs are required. "
                     "No automatic recommendation to enable memory follows from this report."}


async def run_plan(plan: Mapping[str, Any], manifest: Mapping[str, Any], *,
                   attempt: Callable[[Mapping[str, Any], bool], Awaitable[Mapping[str, Any]]],
                   report_path: Path) -> dict[str, Any]:
    """Run each scheduled attempt once. Adapter transport retries must equal the frozen plan.

    attempt returns actual applied_outcome, model_outcome, detector IDs/status, model
    metadata/usage and evidence. It must not use the expectation as an input to a model.
    Checkpoints prevent losing failures. Existing reports are never overwritten/re-run.
    """
    if digest(manifest) != plan["manifest_digest"]:
        raise ValueError("manifest changed after plan freeze")
    if digest({k: v for k, v in plan.items() if k != "plan_digest"}) != plan["plan_digest"]:
        raise ValueError("evaluation plan digest mismatch")
    expected_plan = freeze_plan(manifest, model=plan["model"], policy_binding=plan["policy_binding"],
        rules_digest=plan["rules_digest"], memory_digest=plan["memory_digest"],
        max_retries=plan["max_retries"], pairs=plan["pairs_per_case"], review_config=plan.get("review_config"))
    if dict(plan) != expected_plan:
        raise ValueError("plan schedule or expectations differ from the frozen manifest")
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report = {"plan": dict(plan), "results": [dict(trial, status="not_started", verdict="not_run",
              model_only_verdict="not_run") for trial in plan["trials"]], "complete": False}
    report["summary"] = summarize(report["results"])
    report["gate"] = _gate(report)
    # Claim the output before the first remote request; never silently replace an old run.
    with report_path.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
    cases = {case["id"]: case for case in manifest["held_out"]}
    for position, trial in enumerate(plan["trials"]):
        start = time.monotonic()
        result = dict(trial)
        case = cases[trial["case_id"]]
        # Do not pass labels/rationales to the assessment adapter.
        assessment_input = {key: case[key] for key in ("id", "family", "before", "after")}
        report["results"][position].update(status="running")
        report["summary"] = summarize(report["results"])
        report["gate"] = _gate(report)
        _checkpoint(report_path, report)
        try:
            received = dict(await attempt(assessment_input, trial["memory"] == "on"))
            forbidden = set(received) & (set(trial) | {"verdict", "model_only_verdict", "elapsed_ms"})
            if forbidden:
                raise ValueError("attempt tried to replace frozen fields")
            result.update(received)
            valid = (result.get("status") == "completed"
                     and result.get("detector_status") in {"clean", "matched"})
            result["verdict"] = _verdict(trial["expected_outcome"], result.get("applied_outcome")) if valid else "error"
            if result.get("model_status") == "completed":
                result["model_only_verdict"] = _verdict(trial["expected_outcome"], result.get("model_outcome"))
            elif result.get("model_status") == "skipped_hard_deny" and result.get("detector_status") == "matched":
                result["model_only_verdict"] = "not_run"
            else:
                result["model_only_verdict"] = "error"
            result["detector_matches_expectation"] = (result.get("detector_status") in {"clean", "matched"}
                and sorted(result.get("detector_ids", [])) == sorted(trial["expected_detector"]))
        except asyncio.CancelledError:
            result.update(status="interrupted", error_type="CancelledError", verdict="error",
                          model_only_verdict="error")
            result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 2)
            report["results"][position] = result
            report["summary"] = summarize(report["results"])
            report["gate"] = _gate(report)
            _checkpoint(report_path, report)
            raise
        except Exception as exc:
            result.update(status="failed", error_type=type(exc).__name__, verdict="error",
                          model_only_verdict="error")
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 2)
        report["results"][position] = result
        report["summary"] = summarize(report["results"])
        report["gate"] = _gate(report)
        _checkpoint(report_path, report)
    report["complete"] = True
    report["gate"] = _gate(report)
    _checkpoint(report_path, report)
    return report


def _checkpoint(path: Path, report: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)
