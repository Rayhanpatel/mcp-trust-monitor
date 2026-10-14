"""Nested evaluation selection stays separate from legacy rehearsal evidence."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_trust_monitor.paired_evaluation import digest, freeze_plan
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.trust_store import TrustStore
from scripts import rehearse_memory as rehearsal
from scripts import release_memory as release
from test_memory_rehearsal import completed_evaluation

pytestmark = pytest.mark.anyio


async def nested_evaluation(directory, evaluation_id="opaque-v2"):
    output = directory / "evaluations" / evaluation_id
    output.mkdir(parents=True)
    manifest, old_plan, report = await completed_evaluation(output)
    snapshot = {"lessons": [{"lesson_id": "reviewed-source-a"}, {"lesson_id": "reviewed-source-b"}]}
    plan = freeze_plan(manifest, model=old_plan["model"], policy_binding=old_plan["policy_binding"],
        rules_digest=old_plan["rules_digest"], memory_digest=digest(snapshot),
        review_config=old_plan["review_config"])
    protocol = release.evaluation_protocol(evaluation_id, plan, snapshot, {"files": {}})
    report["plan"] = plan
    for row in report["results"]:
        row.update(server_id=protocol["trial_servers"][row["trial_id"]], evaluation_id=evaluation_id,
                   protocol_digest=protocol["protocol_digest"])
    for name, value in (("paired-plan.json", plan), ("paired-results.json", report),
                        ("protocol.json", protocol), ("active-memory.json", snapshot)):
        release.write(output / name, value)
    return manifest, output, plan, protocol


async def test_first_nested_evaluation_selects_opaque_profiles_without_legacy_reports(tmp_path):
    manifest, output, plan, protocol = await nested_evaluation(tmp_path)
    before = {p:p.read_bytes() for p in output.iterdir()}
    assert rehearsal.selected_evaluation(tmp_path, manifest, "opaque-v2") == (output, plan, protocol)
    assert not (tmp_path / "paired-plan.json").exists()
    assert not (tmp_path / "paired-results.json").exists()
    assert all(p.read_bytes() == value for p,value in before.items())


async def test_legacy_selection_stays_at_root(tmp_path):
    manifest, plan, _ = await completed_evaluation(tmp_path)
    assert rehearsal.selected_evaluation(tmp_path, manifest) == (tmp_path, plan, None)


@pytest.mark.parametrize("change", ["protocol_identity", "trial_server", "trial_protocol", "snapshot"])
async def test_changed_nested_binding_refuses_before_credentials_or_owner(tmp_path, monkeypatch, change):
    manifest, output, plan, protocol = await nested_evaluation(tmp_path)
    if change == "protocol_identity":
        snapshot = json.loads((output / "active-memory.json").read_text())
        release.write(output / "protocol.json", release.evaluation_protocol("opaque-v3", plan, snapshot, {"files": {}}))
    elif change == "snapshot":
        release.write(output / "active-memory.json", {"lessons": []})
    else:
        report = json.loads((output / "paired-results.json").read_text())
        report["results"][0]["server_id" if change == "trial_server" else "protocol_digest"] = "wrong-binding"
        release.write(output / "paired-results.json", report)
    def forbidden(*args, **kwargs):
        pytest.fail("invalid evidence reached configuration or credentials")
    monkeypatch.setattr(rehearsal, "existing_configuration", forbidden)
    monkeypatch.setattr(rehearsal, "read_settings", forbidden)
    with pytest.raises(ValueError):
        await rehearsal.run(SimpleNamespace(directory=tmp_path, evaluation_id="opaque-v2"))
    assert not (output / rehearsal.REPORT).exists()


async def test_nested_failed_rehearsal_is_retained_before_credentials(tmp_path, monkeypatch):
    _, output, _, _ = await nested_evaluation(tmp_path)
    path = output / rehearsal.REPORT
    path.write_text("failed prior attempt retained")
    monkeypatch.setattr(rehearsal, "read_settings", lambda *_:pytest.fail("must refuse before credentials"))
    with pytest.raises(FileExistsError):
        await rehearsal.run(SimpleNamespace(directory=tmp_path, evaluation_id="opaque-v2"))
    assert path.read_text() == "failed prior attempt retained"


def test_rehearsal_identity_subset_preserves_unselected_evaluations(tmp_path):
    manifest = json.loads((release.ROOT / "fixtures/memory_cases.json").read_text())
    legacy = release.configuration(tmp_path, manifest)
    selected = release.configuration(tmp_path, manifest, evaluation_id="opaque-v2")
    database = selected.state_dir / "trust.sqlite3"
    store = TrustStore(database, client_id=selected.client_id)
    try:
        for sid, profile in {**legacy.servers, **selected.servers}.items():
            path = profile.args[profile.args.index("--definition") + 1]
            tools = [json.loads(Path(path).read_text())]
            store.record_observation(sid, server_revision(tools), tools,
                provenance={"launch_identity": profile.launch_identity, "origin": "synthetic_fixture"})
    finally:
        store.close()
    before = database.read_bytes()
    definitions = {p:p.read_bytes() for p in tmp_path.rglob("definition.json")}
    assert rehearsal.existing_configuration(tmp_path, manifest, evaluation_id="opaque-v2") == selected
    assert rehearsal.existing_configuration(tmp_path, manifest) == legacy
    assert database.read_bytes() == before
    assert all(p.read_bytes() == value for p,value in definitions.items())
    # Missing metadata is a refusal, never an invitation to synthesize a baseline.
    sid = next(s for s in selected.servers if s.startswith("eval-"))
    missing = tmp_path / "evaluations/opaque-v2/servers" / sid / "definition.json"
    missing.unlink()
    with pytest.raises(ValueError, match="complete and clean"):
        rehearsal.existing_configuration(tmp_path, manifest, evaluation_id="opaque-v2")
    assert not missing.exists()
