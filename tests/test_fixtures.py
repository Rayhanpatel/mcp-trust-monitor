"""REQ-EVAL-01: the fixed evaluation cases are internally consistent with the policy.

These checks cover structure only. They do not evaluate any detector or model.
"""

import json

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.revision import server_revision

from conftest import FIXTURE_PATH, POLICY_PATH


def test_cases_cite_only_policy_rules_and_defined_outcomes():
    fixture = json.loads(FIXTURE_PATH.read_text())
    policy = json.loads(POLICY_PATH.read_text())
    rule_ids = {rule["id"] for rule in policy["rules"]}

    assert fixture["policy_revision"] == policy["revision"]
    ids = [case["id"] for case in fixture["scenarios"]]
    assert len(ids) == len(set(ids))
    for case in fixture["scenarios"]:
        assert case["expected_outcome"] in fixture["outcome_definitions"]
        assert set(case["expected_policy_ids"]) <= rule_ids
        assert set(case["expected_hard_deny_policy_ids"]) <= set(case["expected_policy_ids"])
        # A quarantine expectation must be grounded in at least one cited rule.
        assert (case["expected_outcome"] == "quarantined") == bool(case["expected_policy_ids"])


def test_every_case_changes_the_mutable_server_revision():
    fixture = json.loads(FIXTURE_PATH.read_text())
    baseline = server_revision([fixture["baseline"]])
    revisions = {server_revision([demo.scenario_definition(fixture, case["id"])])
                 for case in fixture["scenarios"]}
    assert baseline not in revisions
    assert len(revisions) == len(fixture["scenarios"])
