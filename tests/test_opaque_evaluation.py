"""Independent evaluation-harness checks; no external service requests."""
import copy
from dataclasses import replace
import json
import re
import sqlite3
from types import SimpleNamespace

import pytest

from mcp_trust_monitor import TrustMonitor
from mcp_trust_monitor.async_assessor import AsyncOpenAIAssessor
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from mcp_trust_monitor.memory import MemorySnapshot
from mcp_trust_monitor.paired_evaluation import digest, freeze_plan
from mcp_trust_monitor.policy import load_policy
from scripts import release_memory as release
from test_openai_reviewer_adapter import PolicySource

pytestmark = pytest.mark.anyio


def manifest():
    return json.loads((release.ROOT / "fixtures/memory_cases.json").read_text())


def frozen_plan(snapshot=None):
    return freeze_plan(manifest(), model="test", policy_binding="policy",
        rules_digest="rules", memory_digest=digest(snapshot or {}),
        review_config=release.REVIEW_CONFIG)


def test_real_memory_snapshot_survives_json_roundtrip_but_rejects_changed_epoch(tmp_path):
    # MemorySnapshot.as_dict retains tuples; JSON arrays decode as lists. Compare
    # the canonical persisted representation, while still rejecting real changes.
    snapshot = MemorySnapshot("client", "scope", "policy", 3, (), True)
    plan = frozen_plan(snapshot.as_dict())
    protocol = release.evaluation_protocol("opaque-v3", plan, snapshot,
        {"files": {}, "plan_digest": None, "memory_digest": None})
    for name, value in (("protocol.json", protocol), ("paired-plan.json", plan),
                        ("active-memory.json", snapshot.as_dict())):
        (tmp_path / name).write_text(json.dumps(value))
    release.validate_evaluation_artifacts(tmp_path, tmp_path, protocol, plan, snapshot)
    altered = json.loads((tmp_path / "active-memory.json").read_text())
    altered["registry_revision"] += 1
    (tmp_path / "active-memory.json").write_text(json.dumps(altered))
    with pytest.raises(ValueError, match="frozen evaluation artifacts changed"):
        release.validate_evaluation_artifacts(tmp_path, tmp_path, protocol, plan, snapshot)


@pytest.mark.parametrize("value", ["", ".", "..", "../old", "nested/run", "/tmp/run", "a\\b", "bad id"])
def test_namespace_validation_refuses_unsafe_or_ambiguous_paths(value):
    with pytest.raises(ValueError):
        release.validate_evaluation_id(value)


def test_all_trial_identifiers_are_opaque_unique_stable_and_run_scoped():
    plan = frozen_plan()
    current = [release.opaque_server_id("opaque-v2", trial["trial_id"]) for trial in plan["trials"]]
    repeat = [release.opaque_server_id("opaque-v2", trial["trial_id"]) for trial in plan["trials"]]
    other = [release.opaque_server_id("opaque-v3", trial["trial_id"]) for trial in plan["trials"]]
    assert current == repeat
    assert len(set(current)) == 48
    assert not set(current) & set(other)
    assert all(re.fullmatch(r"eval-[0-9a-f]{64}", sid) for sid in current)
    for sid in current:
        assert not any(case["id"] in sid or case["family"] in sid for case in manifest()["held_out"])
        assert "opaque-v2" not in sid


def test_versioned_configuration_preserves_source_profiles_and_legacy_artifacts(tmp_path):
    cases = manifest()
    legacy = release.configuration(tmp_path, cases)
    original = {path: path.read_bytes() for path in tmp_path.rglob("definition.json")}
    frozen_report = tmp_path / "paired-results.json"
    frozen_report.write_bytes(b"original failed or successful evidence must survive\n")
    new = release.configuration(tmp_path, cases, evaluation_id="opaque-v2")
    source_ids = {"source/" + case["id"] for case in cases["lesson_source"]}
    assert len(new.servers) == 52
    assert {sid for sid in new.servers if sid.startswith("source/")} == source_ids
    assert not any(sid.startswith("heldout/") for sid in new.servers)
    assert new.state_dir == legacy.state_dir
    assert new.client_id == legacy.client_id
    assert new.policy_path == legacy.policy_path
    for sid in source_ids:
        assert new.servers[sid] == legacy.servers[sid]
        assert new.servers[sid].launch_identity == legacy.servers[sid].launch_identity
    assert all(path.read_bytes() == body for path, body in original.items())
    assert frozen_report.read_bytes() == b"original failed or successful evidence must survive\n"
    for sid, profile in new.servers.items():
        if sid not in source_ids:
            assert str(tmp_path / "evaluations/opaque-v2/servers" / sid / "definition.json") in profile.args


@pytest.mark.parametrize("field", ["trial_servers", "plan_digest", "memory_digest", "active_lesson_ids"])
def test_rehashed_protocol_tampering_cannot_retarget_trials_or_change_snapshot(field):
    snapshot = {"lessons": [{"lesson_id": "reviewed-source-a"}, {"lesson_id": "reviewed-source-b"}]}
    plan = frozen_plan(snapshot)
    prior = {"files": {"paired-results.json": "sha256:prior-file"},
             "plan_digest": "sha256:prior-plan", "memory_digest": "sha256:prior-memory"}
    protocol = release.evaluation_protocol("opaque-v2", plan, snapshot, prior)
    release.validate_evaluation_protocol(protocol, plan, snapshot)
    assert protocol["active_lesson_count"] == 2
    assert "same eight" in protocol["case_reuse"].lower()
    assert "reactivate" in protocol["memory_change"].lower()
    altered = copy.deepcopy(protocol)
    if field == "trial_servers":
        first = plan["trials"][0]["trial_id"]
        altered[field][first] = "heldout/" + first
    elif field == "active_lesson_ids":
        altered[field] = ["unreviewed-or-revoked-lesson"]
    else:
        altered[field] = "sha256:different-binding"
    altered["protocol_digest"] = digest({k:v for k,v in altered.items() if k != "protocol_digest"})
    with pytest.raises(ValueError):
        release.validate_evaluation_protocol(altered, plan, snapshot)


def test_existing_namespace_and_original_evidence_are_never_overwritten(tmp_path):
    cases = manifest()
    release.configuration(tmp_path, cases)
    state = tmp_path / "state"
    state.mkdir()
    sqlite3.connect(state / "trust.sqlite3").close()
    plan = frozen_plan()
    release.write(tmp_path / "paired-plan.json", plan)
    release.write(tmp_path / "paired-results.json", {"plan": plan, "complete": True, "results": [{}] * 48})
    originals = {name:(tmp_path/name).read_bytes() for name in ("paired-plan.json", "paired-results.json")}
    output, prior = release.versioned_evaluation_setup(tmp_path, cases, "opaque-v2")
    sentinel = output / "paired-results.json"
    sentinel.write_bytes(b"interrupted attempt retained")
    assert set(prior["files"]) == set(originals)
    with pytest.raises(FileExistsError):
        release.versioned_evaluation_setup(tmp_path, cases, "opaque-v2")
    assert sentinel.read_bytes() == b"interrupted attempt retained"
    assert all((tmp_path/name).read_bytes() == value for name,value in originals.items())


def test_first_opaque_run_needs_no_legacy_evaluation(tmp_path):
    cases = manifest()
    release.configuration(tmp_path, cases)
    state = tmp_path / "state"
    state.mkdir()
    sqlite3.connect(state / "trust.sqlite3").close()
    output, prior = release.versioned_evaluation_setup(tmp_path, cases, "first-run")
    assert output == tmp_path / "evaluations/first-run"
    assert prior["files"] == {}
    assert not (tmp_path / "paired-plan.json").exists()
    assert not (tmp_path / "paired-results.json").exists()


@pytest.mark.parametrize("only_file", ["paired-plan.json", "paired-results.json"])
def test_partial_legacy_artifacts_refuse_new_run_without_creating_namespace(tmp_path, only_file):
    cases = manifest()
    release.configuration(tmp_path, cases)
    state = tmp_path / "state"
    state.mkdir()
    sqlite3.connect(state / "trust.sqlite3").close()
    (tmp_path / only_file).write_text("{}")
    with pytest.raises(ValueError):
        release.versioned_evaluation_setup(tmp_path, cases, "opaque-v2")
    assert not (tmp_path / "evaluations/opaque-v2").exists()


@pytest.mark.parametrize("change", ["evaluation_id", "prior_artifacts", "plan", "snapshot"])
def test_frozen_artifact_guard_rejects_self_consistent_replacements(tmp_path, change):
    snapshot = {"lessons": [{"lesson_id": "reviewed-source-a"}]}
    plan = frozen_plan(snapshot)
    prior = {"files": {}, "plan_digest": None, "memory_digest": None}
    protocol = release.evaluation_protocol("opaque-v2", plan, snapshot, prior)
    output = tmp_path / "evaluations/opaque-v2"
    output.mkdir(parents=True)
    for name, value in (("protocol.json", protocol), ("paired-plan.json", plan),
                        ("active-memory.json", snapshot)):
        release.write(output / name, value)
    release.validate_evaluation_artifacts(output, tmp_path, protocol, plan, snapshot)
    if change == "evaluation_id":
        changed = release.evaluation_protocol("opaque-v3", plan, snapshot, prior)
        release.write(output / "protocol.json", changed)
    elif change == "prior_artifacts":
        altered_prior = {**prior, "plan_digest": "sha256:rewritten-history"}
        changed = release.evaluation_protocol("opaque-v2", plan, snapshot, altered_prior)
        release.write(output / "protocol.json", changed)
    elif change == "plan":
        changed = {**plan, "model": "different-model"}
        changed["plan_digest"] = digest({k:v for k,v in changed.items() if k != "plan_digest"})
        release.write(output / "paired-plan.json", changed)
    else:
        release.write(output / "active-memory.json", {"lessons": []})
    with pytest.raises(ValueError, match="frozen evaluation artifacts changed"):
        release.validate_evaluation_artifacts(output, tmp_path, protocol, plan, snapshot)


async def test_source_identity_preflight_is_read_only_and_refuses_changed_launch(tmp_path):
    cases = manifest()
    old = release.configuration(tmp_path, cases)
    source_ids = ["source/" + case["id"] for case in cases["lesson_source"]]
    async with TrustMonitor(old) as monitor:
        for sid in source_ids:
            await monitor.observe(sid)
    current = release.configuration(tmp_path, cases, evaluation_id="opaque-v2")
    prior_plan = {"policy_binding": load_policy(current.policy_path).binding}
    database = current.state_dir / "trust.sqlite3"
    before = database.read_bytes()
    release.validate_existing_source_profiles(current, cases, prior_plan)
    sid = source_ids[0]
    changed = dict(current.servers)
    changed[sid] = replace(changed[sid], args=(*changed[sid].args, "--changed-launch"))
    with pytest.raises(ValueError, match="source launch identity"):
        release.validate_existing_source_profiles(replace(current, servers=changed), cases, prior_plan)
    with pytest.raises(ValueError, match="operator policy"):
        release.validate_existing_source_profiles(current, cases, {"policy_binding": "changed-policy"})
    assert database.read_bytes() == before
    assert not (current.state_dir / "owner.unclean").exists()


@pytest.mark.parametrize("case_index", [0, 4])
async def test_actual_provider_input_has_metadata_but_no_case_family_arm_or_trial_labels(tmp_path, case_index):
    cases = manifest()
    case = cases["held_out"][case_index]
    evaluation_id = "opaque-v2"
    trial_id = case["id"] + "/1/on"
    sid = release.opaque_server_id(evaluation_id, trial_id)
    config = release.configuration(tmp_path, cases, evaluation_id=evaluation_id)
    captured = []

    class LocalProvider:
        responses = None

        def __init__(self):
            self.responses = self

        async def create(self, **request):
            captured.append(request)
            payload, _ = json.JSONDecoder().raw_decode(request["input"])
            answer = {"server_id": payload["server_id"], "revision": payload["revision"],
                "generation": payload["generation"], "recommendation": "review", "policy_ids": [],
                "source_content_ids": payload["policy"]["content_ids"], "evidence": [],
                "explanation": "Offline transport test only; no classification evidence.", "precedent_ids": []}
            return SimpleNamespace(id="offline-provider-response", model="test", status="completed",
                usage={"total_tokens": 1}, output=[SimpleNamespace(type="message",
                    content=[SimpleNamespace(type="output_text", text=json.dumps(answer))])])

        async def close(self):
            pass

    class RecordingAssessor(AsyncOpenAIAssessor):
        def __init__(self, key, model, **kwargs):
            super().__init__(key, model, client=LocalProvider(), **kwargs)

    reviewer = OpenAIReviewer(api_key="offline-test-only", model="test",
        senso_client=PolicySource(), policy_content_ids=("policy-source",),
        assessor_factory=RecordingAssessor)
    async with TrustMonitor(config) as monitor:
        await release.changed_case(monitor, tmp_path / "evaluations/opaque-v2/servers", sid, case)
        result = await reviewer(monitor, sid)
        assert result.stage == "completed", result
    assert len(captured) == 1
    request = captured[0]
    text = request["input"]
    assert case["after"]["description"] in text
    assert sid in text
    for item in cases["held_out"]:
        assert item["id"] not in text
        assert item["family"] not in text
    assert trial_id not in text and evaluation_id not in text
    assert "heldout/" not in text
    assert '"expected_outcome"' not in text and '"expected_detector"' not in text
    assert '"memory": "on"' not in text and '"pair": 1' not in text
    assert "tools" not in request

