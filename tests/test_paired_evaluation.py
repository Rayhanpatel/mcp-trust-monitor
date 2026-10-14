import asyncio
import json
from collections import Counter
from pathlib import Path

import pytest

from mcp_trust_monitor.paired_evaluation import freeze_plan, run_plan

MANIFEST = Path(__file__).resolve().parents[1] / "fixtures" / "memory_cases.json"


def plan():
    manifest = json.loads(MANIFEST.read_text())
    return manifest, freeze_plan(manifest, model="test", policy_binding="policy-v1",
                                rules_digest="rules-v1", memory_digest="memory-v1")


def test_schedule_is_paired_balanced_and_frozen():
    manifest, frozen = plan()
    assert len(frozen["trials"]) == 48
    assert Counter(t["memory"] for t in frozen["trials"]) == {"on": 24, "off": 24}
    for i in range(0, 48, 2):
        a, b = frozen["trials"][i:i+2]
        assert a["case_id"] == b["case_id"] and a["pair"] == b["pair"]
        assert a["memory"] != b["memory"]
    assert frozen == freeze_plan(manifest, model="test", policy_binding="policy-v1",
                                rules_digest="rules-v1", memory_digest="memory-v1")


def test_unexpected_hard_deny_preserves_combined_outcome_and_skipped_model(tmp_path):
    manifest, frozen = plan()
    async def attempt(case, enabled):
        return {"status": "completed", "applied_outcome": "quarantined",
                "detector_status": "matched", "detector_ids": ["POL-001"],
                "model_status": "skipped_hard_deny", "model_outcome": None}
    report = asyncio.run(run_plan(frozen, manifest, attempt=attempt,
                                  report_path=tmp_path / "unexpected.json"))
    assert len(report["results"]) == 48
    assert {row["model_only_verdict"] for row in report["results"]} == {"not_run"}
    assert {row["verdict"] for row in report["results"]} == {"pass", "false quarantine"}
    assert report["gate"]["release_blocked"]
    assert len(report["gate"]["unexpected_detector_trials"]) == 48


def test_failed_trials_retained_not_replaced_and_labels_not_passed(tmp_path):
    manifest, frozen = plan()
    calls = []
    async def attempt(case, enabled):
        assert set(case) == {"id", "family", "before", "after"}
        calls.append((case["id"], enabled))
        raise RuntimeError("sensitive raw response must not be copied")
    path = tmp_path / "report.json"
    report = asyncio.run(run_plan(frozen, manifest, attempt=attempt, report_path=path))
    assert len(calls) == 48 and len(report["results"]) == 48 and report["complete"]
    assert all(row["verdict"] == "error" for row in report["results"])
    assert "sensitive" not in path.read_text()
    with pytest.raises(FileExistsError):
        asyncio.run(run_plan(frozen, manifest, attempt=attempt, report_path=path))
    assert len(calls) == 48


def test_changed_manifest_or_plan_refused_before_request(tmp_path):
    manifest, frozen = plan()
    async def attempt(*args):
        pytest.fail("must not run")
    manifest["description"] += " changed"
    with pytest.raises(ValueError, match="manifest"):
        asyncio.run(run_plan(frozen, manifest, attempt=attempt, report_path=tmp_path / "a"))
    manifest, frozen = plan()
    frozen["max_retries"] = 20
    with pytest.raises(ValueError, match="plan digest"):
        asyncio.run(run_plan(frozen, manifest, attempt=attempt, report_path=tmp_path / "b"))
