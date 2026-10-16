"""The JSON CLI can declare the same policy/detector pair as an SDK owner (REQ-DEC-06).

Corrective review S1: approvals bind the policy plus detector binding, and the CLI could
not declare a detector, so CLI and detector-enabled SDK owners of one state directory
reset each other's approvals. An optional `detector_binding` (the operator's binding
JSON) now lets every owner declare the same pair. Owners that declare different pairs
still fail closed. Separate CLI processes and a real stdio server with its own call log.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT
from mcp_trust_monitor import TrustMonitor
from mcp_trust_monitor.config import ConfigurationError
from mcp_trust_monitor.detector import rules_digest_of
from mcp_trust_monitor.library_cli import load_config
from mcp_trust_monitor.policy import DetectorBinding, load_policy
from mcp_trust_monitor.trust_store import TrustState

pytestmark = pytest.mark.anyio
SERVER = REPO_ROOT / "examples" / "external_stdio_server.py"
RULE = "hard-deny.ext-1.exact-directive"


def project(tmp_path: Path, *, detector: bool = True) -> Path:
    root = tmp_path / "project"
    (root / "rules").mkdir(parents=True, exist_ok=True)
    (root / "definition.json").write_text(json.dumps(
        {"name": "echo", "description": "Echo public text.", "inputSchema": {"type": "object"}}))
    (root / "policy.json").write_text(json.dumps({"policy_id": "cli-detector", "revision": "1", "rules": [
        {"id": "EXT-1", "requirement": "Use public text only.",
         "hard_deny_condition": "The description contains the exact export directive."}]}))
    rules = root / "rules" / "rules.json"
    rules.write_text(json.dumps({"rules": [{"id": RULE, "languages": ["generic"], "severity": "ERROR",
        "message": "Prohibited directive.", "metadata": {"policy_id": "EXT-1"},
        "pattern-regex": "EXPORT_EVERYTHING"}]}))
    (root / "rules" / "binding.json").write_text(json.dumps({
        "rules_path": "rules.json", "policy_digest": load_policy(root / "policy.json").digest,
        "rules_digest": rules_digest_of(rules.read_bytes()), "rule_mapping": {RULE: "EXT-1"}}))
    document = {"state_dir": "state", "policy_path": "policy.json", "timeout_seconds": 30,
                "servers": [{"server_id": "local", "command": sys.executable, "origin": "synthetic_fixture",
                             "args": [str(SERVER), "--definition", "definition.json",
                                      "--calls", "calls.jsonl"]}]}
    if detector:
        document["detector_binding"] = "rules/binding.json"
    config = root / ("config.json" if detector else "config-without-detector.json")
    config.write_text(json.dumps(document))
    return config


def cli(config: Path, *args: str) -> subprocess.CompletedProcess:
    environment = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run([sys.executable, "-m", "mcp_trust_monitor", "--config", str(config), *args],
                          capture_output=True, text=True, timeout=120, cwd=str(config.parent.parent),
                          env=environment)


def calls(config: Path) -> int:
    path = config.parent / "calls.jsonl"
    return len(path.read_text().splitlines()) if path.exists() else 0


def test_config_binding_resolves_beside_the_binding_file(tmp_path):
    config = project(tmp_path)
    loaded = load_config(config).detector
    root = config.parent
    assert loaded == DetectorBinding(root / "rules" / "rules.json", load_policy(root / "policy.json").digest,
                                     rules_digest_of((root / "rules" / "rules.json").read_bytes()),
                                     {RULE: "EXT-1"})
    assert load_config(project(tmp_path / "other", detector=False)).detector is None


@pytest.mark.parametrize("change", [
    {"unexpected": True}, {"rule_mapping": ["not", "a", "mapping"]}, {"rules_digest": ""},
    {"scanned_fields": "description"}, {"rule_mapping": {RULE: 1}}])
def test_malformed_binding_files_are_refused(tmp_path, change):
    config = project(tmp_path)
    path = config.parent / "rules" / "binding.json"
    valid = json.loads(path.read_text())
    path.write_text(json.dumps({**valid, **change}))
    with pytest.raises(ConfigurationError):
        load_config(config)


@pytest.mark.parametrize("field", ["rules_path", "policy_digest", "rules_digest", "rule_mapping"])
def test_binding_files_missing_a_field_or_unreadable_are_refused(tmp_path, field):
    config = project(tmp_path)
    path = config.parent / "rules" / "binding.json"
    missing = json.loads(path.read_text())
    missing.pop(field)
    path.write_text(json.dumps(missing))
    with pytest.raises(ConfigurationError):
        load_config(config)
    path.write_text("{not json")
    with pytest.raises(ConfigurationError):
        load_config(config)
    path.unlink()
    with pytest.raises(ConfigurationError):
        load_config(config)


def test_a_binding_that_does_not_match_the_policy_is_refused_before_any_state(tmp_path):
    config = project(tmp_path)
    path = config.parent / "rules" / "binding.json"
    path.write_text(json.dumps({**json.loads(path.read_text()), "policy_digest": "sha256:" + "0" * 64}))
    refused = cli(config, "observe", "local")
    assert refused.returncode != 0
    assert not (config.parent / "state" / "trust.sqlite3").exists()
    assert calls(config) == 0


async def test_cli_and_sdk_owners_declaring_the_same_pair_keep_each_others_approvals(tmp_path):
    config = project(tmp_path)
    observed = cli(config, "observe", "local")
    assert observed.returncode == 0, observed.stderr
    record = json.loads(observed.stdout)
    approved = cli(config, "approve", "local", "--revision", record["observed_revision"],
                   "--generation", str(record["generation"]))
    assert approved.returncode == 0, approved.stderr
    generation = json.loads(approved.stdout)["generation"]
    async with TrustMonitor(load_config(config)) as monitor:  # e.g. examples/reviewed_monitor.py
        assert monitor.detector_binding is not None
        current = monitor.status("local")
        assert (current.state, current.generation) == (TrustState.APPROVED, generation)
        assert current.approved_policy_revision == monitor.decision_binding
        assert not (await monitor.observe_and_call("local", "echo", {})).isError
    assert calls(config) == 1
    called = cli(config, "call", "local", "echo", "--refresh", "--arguments", "{}")
    assert called.returncode == 0, called.stderr
    assert calls(config) == 2
    status = json.loads(cli(config, "status").stdout)[0]
    assert (status["state"], status["generation"]) == ("approved", generation)


async def test_owners_declaring_different_pairs_still_fail_closed(tmp_path):
    config = project(tmp_path)
    without = project(tmp_path, detector=False)
    async with TrustMonitor(load_config(config)) as monitor:
        record = await monitor.observe("local")
        await monitor.approve("local", revision=record.observed_revision,
                              expected_generation=record.generation, actor="operator")
        generation = monitor.status("local").generation
    observed = cli(without, "observe", "local")  # an owner without the detector
    assert observed.returncode == 0, observed.stderr
    after = json.loads(observed.stdout)
    assert after["state"] == "pending_review" and after["generation"] > generation
    refused = cli(without, "call", "local", "echo", "--refresh", "--arguments", "{}")
    assert refused.returncode == 3
    assert json.loads(refused.stderr)["reason"] == "pending_review"
    assert calls(config) == 0


async def test_read_only_commands_do_not_need_the_binding_file(tmp_path):
    config = project(tmp_path)
    async with TrustMonitor(load_config(config)) as monitor:
        await monitor.observe("local")
    (config.parent / "rules" / "binding.json").rename(config.parent / "moved-binding.json")
    for command in ("status", "events", "catalog", "export"):
        result = cli(config, command)
        assert result.returncode == 0, (command, result.stderr)
    assert json.loads(cli(config, "status").stdout)[0]["server_id"] == "local"
    refused = cli(config, "observe", "local")  # an owner must activate the declared pair
    assert refused.returncode != 0
    assert json.loads(refused.stderr)["error"] == "ConfigurationError"


def test_cli_review_exits_nonzero_when_the_detector_scan_fails(tmp_path, monkeypatch):
    config = project(tmp_path)
    record = json.loads(cli(config, "observe", "local").stdout)
    cli(config, "approve", "local", "--revision", record["observed_revision"],
        "--generation", str(record["generation"]))
    monkeypatch.setenv("MCP_TRUST_SEMGREP", str(tmp_path / "missing-semgrep"))
    reviewed = cli(config, "review", "local")
    assert reviewed.returncode == 1, reviewed.stderr
    result = json.loads(reviewed.stdout)
    assert (result["detector"], result["outcome"]) == ("failed", "failed")
    status = json.loads(cli(config, "status").stdout)[0]
    assert status["state"] == "approved"  # a failed scan neither approves nor revokes
    events = [event["event_type"] for event in json.loads(cli(config, "events").stdout)]
    assert "detector_failed" in events
