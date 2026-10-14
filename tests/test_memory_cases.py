"""REQ-EVAL-03: the frozen X1 lesson-source and held-out cases.

Checks structure, the split and family rules, a near-duplicate rule fixed before the
cases were written, the expected detector result under the real pinned Semgrep, and
a digest pin. No model is run on these cases, here or anywhere before the freeze.
"""

from __future__ import annotations

import itertools
import json
import re

from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.detector import scan_tools
from mcp_trust_monitor.policy import policy_rule_ids
from mcp_trust_monitor.revision import digest, server_revision

from conftest import FIXTURE_PATH, POLICY_PATH, REPO_ROOT

MANIFEST_PATH = REPO_ROOT / "fixtures" / "memory_cases.json"
# Pinned at each frozen version. Any edit to a case, expectation or rule requires a new
# manifest version with a revision_history entry and disclosure, never an updated pin alone.
MANIFEST_VERSION = "x1-memory-cases-2"
MANIFEST_DIGEST = "sha256:bd0f0e4d16e6f81f932a7d1958c15c896d928a3ce6eb71009895196a1871bd9b"
PREVIOUS_DIGESTS = {"x1-memory-cases-1":
                    "sha256:00e17dfafe00ebf5af4be3b425f92f7d114cb09e78d5e7842f28eb795f6ae132"}

# Near-duplicate rule, fixed before the cases were written (see authoring_rules).
NGRAM = 6
JACCARD_LIMIT = 0.5
STOPWORDS = frozenset("""
a an the and or of to for by it its is are be been this that these those with on in as
from so they them their any each every all if then than not no never also only up per at
you your our we user users anything nothing what which who whom when whenever once was
were has have had can may would will does do into out over under same such there here
""".split())

MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
POLICY = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
SOURCES = MANIFEST["lesson_source"]
HELD_OUT = MANIFEST["held_out"]
CASES = SOURCES + HELD_OUT
BASELINE_TEXT = FIXTURE["baseline"]["description"]
REGRESSION_TEXTS = {case["id"]: demo.scenario_definition(FIXTURE, case["id"])["description"]
                    for case in FIXTURE["scenarios"]}


def tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def ngrams(words: list[str], n: int = NGRAM) -> set[tuple[str, ...]]:
    return {tuple(words[i:i + n]) for i in range(len(words) - n + 1)}


BASELINE_NGRAMS = ngrams(tokens(BASELINE_TEXT))
BASELINE_TOKENS = set(tokens(BASELINE_TEXT))


def near_duplicate(first: str, second: str) -> str | None:
    """Return why two descriptions are near-duplicates under the fixed rule, or None."""
    a, b = tokens(first), tokens(second)
    shared = (ngrams(a) & ngrams(b)) - BASELINE_NGRAMS
    if shared:
        return f"shared {NGRAM}-token sequence {' '.join(sorted(shared)[0])!r}"
    content_a = set(a) - STOPWORDS - BASELINE_TOKENS
    content_b = set(b) - STOPWORDS - BASELINE_TOKENS
    union = content_a | content_b
    similarity = len(content_a & content_b) / len(union) if union else 0.0
    if similarity >= JACCARD_LIMIT:
        return f"content-token Jaccard {similarity:.2f}"
    return None


def description(case: dict) -> str:
    return case["after"]["description"]


def test_manifest_digest_is_pinned():
    assert MANIFEST["manifest_version"] == MANIFEST_VERSION
    assert digest(MANIFEST) == MANIFEST_DIGEST


def test_every_revision_is_versioned_and_disclosed():
    history = MANIFEST["revision_history"]
    assert [entry["version"] for entry in history][-1] == MANIFEST_VERSION
    ids = {case["id"] for case in CASES}
    for entry in history:
        assert entry["previous_digest"] == PREVIOUS_DIGESTS[entry["previous_version"]]
        assert entry["previous_digest"] != MANIFEST_DIGEST
        assert entry["changed_cases"] and set(entry["changed_cases"]) <= ids
        assert entry["reason"].strip() and entry["model_runs"].startswith("none")


def test_manifest_matches_the_policy_server_and_baseline():
    assert MANIFEST["origin"] == "synthetic_fixture"
    assert (MANIFEST["policy_id"], MANIFEST["policy_revision"]) == (
        POLICY["policy_id"], POLICY["revision"])
    assert MANIFEST["server"] == FIXTURE["server"] == demo.MUTABLE_SERVER
    assert MANIFEST["outcome_definitions"] == FIXTURE["outcome_definitions"]
    for case in CASES:
        assert case["before"] == FIXTURE["baseline"]
        assert case["after"]["name"] == case["before"]["name"]
        assert set(case["after"]) == {"name", "description", "inputSchema"}


def test_case_ids_are_unique_prefixed_and_distinct_from_the_regression_cases():
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids))
    assert all(case["id"].startswith("src-") for case in SOURCES)
    assert all(case["id"].startswith("ho-") for case in HELD_OUT)
    assert not set(ids) & set(REGRESSION_TEXTS)


def test_every_case_follows_its_family_and_the_policy():
    rule_ids = {rule["id"] for rule in POLICY["rules"]}
    for case in CASES:
        family = MANIFEST["families"][case["family"]]
        violation = family["kind"] == "violation"
        assert case["expected_outcome"] == ("quarantined" if violation else "pending_review")
        assert case["expected_outcome"] in MANIFEST["outcome_definitions"]
        assert case["expected_policy_ids"] == family["policy_ids"]
        assert set(case["expected_policy_ids"]) <= rule_ids
        assert bool(case["expected_policy_ids"]) == violation
        assert case["expected_hard_deny_policy_ids"] == []  # every case is model-only
        assert case["rationale"].strip()


def test_split_sizes_and_family_coverage():
    kinds = lambda cases: [MANIFEST["families"][c["family"]]["kind"] for c in cases]
    assert len(SOURCES) >= 4 and set(kinds(SOURCES)) == {"violation", "benign"}
    assert sorted(kinds(HELD_OUT)) == ["benign"] * 4 + ["violation"] * 4
    held_families = {case["family"] for case in HELD_OUT}
    source_families = {case["family"] for case in SOURCES}
    assert len(held_families) >= 4
    absent = held_families - source_families
    assert absent  # at least one held-out family never appears in lesson sources
    disclosed = " ".join(MANIFEST["disclosures"])
    assert all(family in disclosed for family in absent | (held_families & source_families))
    assert set(MANIFEST["families"]) == held_families | source_families


def test_every_case_changes_the_revision_and_revisions_are_unique():
    baseline = server_revision([FIXTURE["baseline"]])
    regression = {server_revision([demo.scenario_definition(FIXTURE, cid)])
                  for cid in REGRESSION_TEXTS}
    revisions = [server_revision([case["after"]]) for case in CASES]
    assert len(set(revisions)) == len(CASES)
    assert baseline not in revisions and not set(revisions) & regression
    assert all(server_revision([case["before"]]) == baseline for case in CASES)


def test_near_duplicate_rule_is_not_vacuous():
    text = description(HELD_OUT[0])
    assert near_duplicate(text, text)
    assert near_duplicate(text, text.replace("sales department", "sales group"))
    assert near_duplicate(BASELINE_TEXT, BASELINE_TEXT + " Extra.") is None  # baseline excluded


def test_no_near_duplicates_across_the_split_within_the_manifest_or_with_regression_cases():
    found = []
    for first, second in itertools.combinations(CASES, 2):
        reason = near_duplicate(description(first), description(second))
        if reason:
            found.append((first["id"], second["id"], reason))
    for case in CASES:
        for regression_id, text in REGRESSION_TEXTS.items():
            reason = near_duplicate(description(case), text)
            if reason:
                found.append((case["id"], regression_id, reason))
    assert found == []


def test_real_semgrep_finds_exactly_the_expected_hard_deny_ids():
    # Positive control in the same scan: a regression case that matches both rules, so
    # an empty result for the X1 cases cannot come from a scan that never ran.
    control = dict(demo.scenario_definition(FIXTURE, "private-content-demand"),
                   name="control-private-content-demand")
    tools = [dict(case["after"], name=case["id"]) for case in CASES] + [control]
    result = scan_tools(tools, known_policy_ids=policy_rule_ids(POLICY_PATH))
    found: dict[str, set[str]] = {}
    for match in result.matches:
        found.setdefault(match.evidence.tool, set()).add(match.policy_id)
    assert found.get(control["name"]) == {"POL-001", "POL-002"}
    expected = {case["id"]: set(case["expected_hard_deny_policy_ids"]) for case in CASES}
    assert {cid: found.get(cid, set()) for cid in expected} == expected
