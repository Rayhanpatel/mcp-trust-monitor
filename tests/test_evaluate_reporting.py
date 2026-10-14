"""REQ-EVAL-02: evaluation reporting never counts a stage error as a decision.

The model and retrieval are MOCKED, and most tests replace the detector with a stub
that returns each fixed case's expected hard-deny IDs, because these tests check
reporting, not detection (real Semgrep is covered in test_detector.py and in
test_model_review.py's evaluation test). No live service is called.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor import evaluate as evaluation
from mcp_trust_monitor.assessor import ModelError, OpenAIAssessor
from mcp_trust_monitor.detector import DetectorError
from mcp_trust_monitor.evaluate import evaluate_cases, format_report, report_json
from mcp_trust_monitor.policy import load_policy
from mcp_trust_monitor.senso import RetrievedPolicy, SensoError

from conftest import POLICY_PATH

POLICY_TEXT = POLICY_PATH.read_text()
POLICY = json.loads(POLICY_TEXT)
CONTENT_ID = "cid-policy-1"
FIXTURE = demo.load_fixture()
CASES = [case["id"] for case in FIXTURE["scenarios"]]
EXPECTED = {case["id"]: case["expected_outcome"] for case in FIXTURE["scenarios"]}


def retrieved_policy() -> RetrievedPolicy:
    return RetrievedPolicy(policy_id=POLICY["policy_id"], revision=POLICY["revision"],
                           policy_digest=load_policy(POLICY_PATH).digest,
                           content_ids=(CONTENT_ID,), passages=(POLICY_TEXT,))


def failing_retrieve():
    raise SensoError("HTTP 503 on POST /org/search/context")


def raw(ctx, recommendation="review", **overrides):
    value = {"recommendation": recommendation, "server_id": ctx.server_id,
             "revision": ctx.revision, "generation": ctx.generation,
             "policy_ids": ["POL-001"] if recommendation == "quarantine" else [],
             "source_content_ids": list(ctx.source_content_ids),
             "evidence": [{"tool": ctx.tools[0]["name"], "text": ctx.tools[0]["description"]}]
             if recommendation == "quarantine" else [],
             "explanation": "Assessed against the operator policy."}
    value.update(overrides)
    return value


@pytest.fixture
def stub_detector(monkeypatch):
    """Return each fixed case's expected hard-deny IDs, keyed by its description."""
    by_description = {}
    for case in FIXTURE["scenarios"]:
        tool = demo.scenario_definition(FIXTURE, case["id"])
        by_description[tool["description"]] = tuple(case["expected_hard_deny_policy_ids"])

    def scan(tools, known_policy_ids):
        return SimpleNamespace(policy_ids=by_description[tools[0]["description"]])

    monkeypatch.setattr(evaluation, "scan_tools", scan)


def run(**kwargs):
    kwargs.setdefault("retrieve", retrieved_policy)
    return evaluate_cases(FIXTURE, POLICY_PATH, **kwargs)


def by_case(results):
    return {r.case_id: r for r in results}


def test_retrieval_failure_makes_every_case_an_error_and_counts_no_pass(stub_detector):
    retrieval, results = run(retrieve=failing_retrieve, assess=lambda *a: pytest.fail("called"))
    assert isinstance(retrieval, str) and retrieval.startswith("failed")
    assert {r.verdict for r in results} == {"error"}
    assert {r.model_only_verdict for r in results} == {"error"}
    assert all(r.errors == ["retrieval"] and r.response is None for r in results)
    # The fail-closed computed outcome still equals the expectation for benign cases...
    assert by_case(results)["harmless-wording-change"].computed_outcome == "pending_review"
    # ...but that is not a decision, so nothing counts as a pass.
    assert evaluation.summarize(results, "verdict")["pass"] == 0
    assert evaluation.summarize(results, "verdict")["error"] == len(CASES)


def test_model_errors_are_errors_even_when_the_fail_closed_outcome_matches(stub_detector):
    def refuse(ctx, prev, ret):
        raise ModelError("refusal", "no")

    _, results = run(assess=refuse)
    cases = by_case(results)
    assert cases["benign-policy-mention"].computed_outcome == "pending_review"
    assert cases["private-content-demand"].computed_outcome == "quarantined"  # hard deny
    assert {r.verdict for r in results} == {"error"}  # neither counts as a pass
    assert {r.model_only_verdict for r in results} == {"error"}
    assert all(r.errors == ["model"] and r.model == "failed: refusal" for r in results)


def test_validation_rejection_is_an_error_not_a_blocked_miss(stub_detector):
    _, results = run(assess=lambda ctx, prev, ret: raw(ctx, revision="sha256:other"))
    cases = by_case(results)
    assert all(r.model == "rejected" and r.errors == ["validation"] for r in results)
    assert cases["private-content-without-address"].verdict == "error"  # not "blocked miss"
    assert cases["harmless-wording-change"].verdict == "error"  # not "pass"


def test_detector_error_makes_combined_verdict_error_but_keeps_model_only(monkeypatch):
    def broken(tools, known_policy_ids):
        raise DetectorError("semgrep exited 2")

    monkeypatch.setattr(evaluation, "scan_tools", broken)
    _, results = run(assess=lambda ctx, prev, ret: raw(ctx, "review"))
    cases = by_case(results)
    assert all(r.detector_status == "error" and r.actual_hard_deny is None for r in results)
    assert {r.verdict for r in results} == {"error"}
    assert cases["harmless-wording-change"].model_only_verdict == "pass"
    assert cases["private-content-without-address"].model_only_verdict == "blocked miss"


def test_valid_decisions_report_combined_and_model_only_separately(stub_detector):
    _, results = run(assess=lambda ctx, prev, ret: raw(ctx, "review"))
    cases = by_case(results)
    assert not any(r.errors for r in results)
    assert cases["private-content-demand"].verdict == "pass"  # the hard denial applies
    assert cases["private-content-demand"].model_only_verdict == "blocked miss"
    assert cases["private-content-demand"].detector_status == "matched"
    assert cases["harmless-wording-change"].detector_status == "clean"
    assert cases["private-content-without-address"].verdict == "blocked miss"
    assert {r.case_id: r.expected_outcome for r in results} == EXPECTED  # never adjusted


def test_report_labels_outcomes_computed_and_counts_each_class(stub_detector):
    retrieval, results = run(retrieve=failing_retrieve, assess=lambda *a: None)
    text = format_report(retrieval, results, model_config={"name": "m", "max_retries": 2})
    assert "computed by the decision path, not applied" in text
    assert "SDK max_retries 2" in text
    assert f"combined (detector and model), {len(CASES)} cases: pass 0," in text
    assert f"error {len(CASES)}" in text
    assert "never count as passes" in text
    assert "cases match their policy-defined expected outcome" not in text
    report = json.loads(report_json(retrieval, results, model_config={"name": "m"}))
    assert report["outcomes"] == "computed, not applied"
    assert report["summary"]["combined"]["pass"] == 0
    assert report["summary"]["model_only"]["error"] == len(CASES)
    assert "computed_outcome" in report["cases"][0] and "actual_outcome" not in report["cases"][0]


# Per-case response metadata, through the real assessor with a scripted fake client.

class Scripted:
    """Return the next scripted item per request: an exception, or a response factory."""

    def __init__(self, *items):
        self.items, self.calls = list(items), []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.items.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item(kwargs)


def response(response_id, *, text=None, status="completed", refusal=False, incomplete=None):
    def build(kwargs):
        header = json.loads(kwargs["input"].split("\n<untrusted_tool_metadata>")[0])
        ctx = SimpleNamespace(server_id=header["server_id"], revision=header["revision"],
                              generation=header["generation"],
                              source_content_ids=header["policy"]["content_ids"], tools=[])
        body = text(ctx) if callable(text) else text
        parts = ([SimpleNamespace(type="refusal", refusal="no")] if refusal else
                 [SimpleNamespace(type="output_text", text=body)] if body is not None else [])
        return SimpleNamespace(
            id=response_id, model=f"model-for-{response_id}", status=status,
            incomplete_details=incomplete,
            usage=SimpleNamespace(input_tokens=11, output_tokens=7, total_tokens=18),
            output=[SimpleNamespace(type="message", content=parts)])
    return build


def review_json(ctx):
    return json.dumps({"recommendation": "review", "server_id": ctx.server_id,
                       "revision": ctx.revision, "generation": ctx.generation,
                       "policy_ids": [], "source_content_ids": ctx.source_content_ids,
                       "evidence": [], "explanation": "No rule is violated."})


def test_each_case_records_its_own_response_metadata_or_none(stub_detector):
    # One scripted item per fixed case, in fixture order.
    script = Scripted(
        response("resp_ok", text=review_json),                    # received, valid
        TimeoutError("timed out"),                                 # no response received
        response("resp_incomplete", status="incomplete",
                 incomplete=SimpleNamespace(reason="max_output_tokens")),
        response("resp_refusal", refusal=True),
        response("resp_malformed", text="{not json"),
        response("resp_rejected", text=lambda ctx: review_json(
            SimpleNamespace(**{**ctx.__dict__, "revision": "sha256:other"}))),
    )
    assessor = OpenAIAssessor("unused", client=SimpleNamespace(responses=script))
    _, results = run(assess=assessor.assess, response_metadata=assessor.response_metadata)
    got = [(r.case_id, r.response["response_id"] if r.response else None, r.model)
           for r in results]
    assert got == [
        (CASES[0], "resp_ok", "review"),
        (CASES[1], None, "failed: api_error"),
        (CASES[2], "resp_incomplete", "failed: incomplete"),
        (CASES[3], "resp_refusal", "failed: refusal"),
        (CASES[4], "resp_malformed", "failed: malformed"),
        (CASES[5], "resp_rejected", "rejected"),
    ]
    assert results[1].response is None  # not the previous case's metadata
    for r in (results[0], *results[2:]):
        assert r.response["model"] == f"model-for-{r.response['response_id']}"
        assert r.response["usage"] == {"input_tokens": 11, "output_tokens": 7,
                                       "total_tokens": 18}
    assert [r.verdict for r in results[1:]] == ["error"] * 5
