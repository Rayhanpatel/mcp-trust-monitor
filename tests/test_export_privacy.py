"""Decision-record export privacy contract (REQ-AUD-03; review finding R7).

Every identifier is a keyed HMAC-SHA256 pseudonym. By default the key is fresh and
random for each export and never stored, so exports cannot be linked and guessed
identifiers cannot be confirmed. An operator key gives stable pseudonyms across
exports. No identifier shape is exempt, links resolve within one export, no key
material or key-derived verifier is exported, and exporting writes nothing.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from conftest import REPO_ROOT
from mcp_trust_monitor.evidence import export_decision_records
from mcp_trust_monitor.trust_store import TrustStore

REV = "sha256:" + "1" * 64
POLICY = "customer@one#sha256:" + "2" * 64
RULES = "sha256:" + "3" * 64
LAUNCH = "sha256:" + "4" * 64
TOOLS = [{"name": "read_salary", "description": "synthetic only", "inputSchema": {}}]
OPERATOR_KEY = b"synthetic-operator-export-key/0123456789abcdef"
OTHER_KEY = b"another-synthetic-export-key/0123456789abcdef!"
SERVER = REPO_ROOT / "examples" / "external_stdio_server.py"


def adapter(store):
    return SimpleNamespace(store=store, events=store.events)


def strings(value):
    """Every string in an exported JSON tree, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from strings(item)


def identifiers(exported):
    return {value for value in strings(exported) if value.startswith("pid:")}


def reviewer_store(path):
    """The reviewer's synthetic reproduction: a guessable server ID in one call_blocked."""
    store = TrustStore(path, client_id="finance-team")
    store.record_observation("payroll-production", REV, TOOLS)
    store.record_event("payroll-production", "call_blocked", actor="operator-local",
                       detail={"tool": "read_salary", "reason": "unreviewed"})
    return store


def test_reviewers_three_guess_dictionary_attack_recovers_nothing(tmp_path):
    store = reviewer_store(tmp_path / "export.sqlite3")
    try:
        exported = export_decision_records(adapter(store))
    finally:
        store.close()
    row = next(item for item in exported["records"] if item["event_type"] == "call_blocked")
    serialized = json.dumps(exported)
    guesses = ["calendar-production", "payroll-production", "documents-production"]
    recovered = [guess for guess in guesses
                 if "id:sha256:" + hashlib.sha256(guess.encode()).hexdigest() == row["server_id"]]
    assert recovered == []
    assert row["server_id"].startswith("pid:")
    for plain in (*guesses, "finance-team", "operator-local", "read_salary"):
        assert plain not in serialized
        # No unkeyed digest of any identifier, in any encoding the old schema used.
        assert hashlib.sha256(plain.encode()).hexdigest() not in serialized


def test_uuid_shaped_identifiers_are_never_emitted_verbatim(tmp_path):
    server, actor, client = "123e4567-e89b-12d3-a456-426614174000", str(uuid4()), str(uuid4())
    tool, call = str(uuid4()), str(uuid4())
    store = TrustStore(tmp_path / "export.sqlite3", client_id=client)
    try:
        store.record_observation(server, REV, TOOLS)
        store.record_event(server, "call_dispatch_started", actor=actor,
                           detail={"tool": tool, "call_id": call})
        exported = export_decision_records(adapter(store))
        generated = [item["event_id"] for item in store.events()]
        generated += [item["observation_id"] for item in store.observations()]
        generated.append(store.run_id)
    finally:
        store.close()
    serialized = json.dumps(exported).lower()
    for value in (server, actor, client, tool, call, *generated):
        assert value.lower() not in serialized
        assert value.replace("-", "").lower() not in serialized
    row = exported["records"][-1]
    assert row["server_id"].startswith("pid:") and row["actor_id"].startswith("pid:")
    assert row["links"]["call_id"].startswith("pid:")


def test_repeated_default_exports_share_no_identifier(tmp_path):
    store = reviewer_store(tmp_path / "export.sqlite3")
    try:
        first = export_decision_records(adapter(store))
        second = export_decision_records(adapter(store))
    finally:
        store.close()
    fields = ("event_id", "run_id", "client_id", "server_id", "actor_id", "tool_id")
    linked = [(name, one[name]) for one, two in zip(first["records"], second["records"])
              for name in fields if one[name] is not None and one[name] == two[name]]
    assert linked == []
    assert first["schema_version"] == second["schema_version"] == 2
    assert first["pseudonymization"]["scope"] == "export"
    assert identifiers(first) and identifiers(second)
    assert identifiers(first).isdisjoint(identifiers(second))
    assert first["pseudonymization"]["export_id"] != second["pseudonymization"]["export_id"]
    # The non-identifier evidence itself is unchanged.
    assert ([(row["event_type"], row["metadata_revision"], row["timestamp"]) for row in first["records"]]
            == [(row["event_type"], row["metadata_revision"], row["timestamp"]) for row in second["records"]])


def linked_store(path):
    """A real store with assessment, quarantine, verification, call and verdict links."""
    store = TrustStore(path, client_id="customer-owner")
    record = store.record_observation("customer-server", REV, TOOLS,
        provenance={"endpoint": "stdio:customer-server#" + LAUNCH, "transport": "stdio",
                    "origin": "synthetic_fixture"})
    observation_id = store.observations()[0]["observation_id"]
    detail = {"assessed_revision": REV, "assessed_generation": record.generation,
              "recommendation": "quarantine", "policy_ids": ["EXT-1"],
              "source_content_ids": ["customer-policy-source"],
              "policy": {"policy_id": "customer", "revision": "one",
                         "policy_digest": "sha256:" + "2" * 64,
                         "content_ids": ["customer-policy-source"]},
              "policy_context": POLICY + "|rules=" + RULES + "|senso=customer-policy-source"}
    assessed = store.record_assessment_if_current("customer-server", revision=REV,
        generation=record.generation, policy_revision=POLICY, active_policy_revision=POLICY,
        detail=detail)
    applied = store.apply_hard_deny("customer-server", revision=REV, generation=record.generation,
        policy_revision=POLICY, active_policy_revision=POLICY,
        detection={**detail, "assessment_event_id": assessed.event_id}, actor="model-reviewer")
    quarantined = store.get("customer-server")
    store.record_event("customer-server", "call_blocked", actor="managed-client",
                       detail={"tool": "read_salary", "reason": "quarantined"})
    store.record_event("customer-server", "verified_blocked", actor="verifier", detail={
        "verified": True, "quarantine_applied_event_id": applied.applied_event_id,
        "blocked_reason": "quarantined", "state_after": "quarantined",
        "applied_generation": quarantined.generation, "generation_after": quarantined.generation,
        "received_before": 0, "received_after": 0,
        "client_dispatches_before": 1, "client_dispatches_after": 1})
    call = str(uuid4())
    store.record_event("customer-server", "call_dispatch_started", actor="managed-client",
                       detail={"tool": "read_salary", "call_id": call})
    store.record_event("customer-server", "call_completed", actor="managed-client",
                       detail={"tool": "read_salary", "call_id": call, "outcome": "outcome_unknown"})
    verdict = str(uuid4())
    store.record_event("customer-server", "verdict_recorded", actor="operator", detail={
        "verdict_id": verdict, "value": "violation", "observation_id": observation_id,
        "assessment_event_id": assessed.event_id, "revision": REV})
    store.record_event("customer-server", "lesson_drafted", actor="operator",
                       detail={"lesson_id": "lesson-one", "verdict_id": verdict})
    return store


def test_every_link_resolves_within_one_export(tmp_path):
    store = linked_store(tmp_path / "trust.sqlite3")
    try:
        exported = export_decision_records(adapter(store))
    finally:
        store.close()
    records = exported["records"]
    by_id = {row["event_id"]: row for row in records}
    assert len(by_id) == len(records)
    expected_type = {"assessment_event_id": "model_assessment_recorded",
                     "quarantine_requested_event_id": "quarantine_requested",
                     "quarantine_applied_event_id": "quarantine_applied"}
    resolved = 0
    for row in records:
        for name, target in row["links"].items():
            if name in expected_type:
                assert by_id[target]["event_type"] == expected_type[name]
                resolved += 1
    assert resolved >= 4  # requested→assessment, applied→requested, verified→applied, verdict→assessment
    verified = next(row for row in records if row["event_type"] == "verified_blocked")
    assert verified["evidence"]["verification_level"] == "independent_counter_verified_blocked"
    started, completed = (next(row for row in records if row["event_type"] == kind)
                          for kind in ("call_dispatch_started", "call_completed"))
    assert started["links"]["call_id"] == completed["links"]["call_id"]
    assert started["evidence"]["dispatch_status"] == "dispatch_started"
    assert completed["evidence"]["dispatch_status"] == "outcome_unknown"
    verdict = next(row for row in records if row["event_type"] == "verdict_recorded")
    lesson = next(row for row in records if row["event_type"] == "lesson_drafted")
    assert verdict["links"]["verdict_id"] == lesson["links"]["verdict_id"]
    observation_ids = {item["observation_id"] for item in exported["observations"]}
    assert verdict["observation_association"] == "explicit"
    assert verdict["observation_id"] in observation_ids
    assert all(row["observation_id"] in observation_ids for row in records if row["observation_id"])
    servers = {row["server_id"] for row in records} | {item["server_id"] for item in exported["observations"]}
    assert len(servers) == 1
    model = next(row for row in records if row["event_type"] == "model_assessment_recorded")
    assert model["retrieval"]["policy"]["cited_content_ids"] == model["retrieval"]["policy"]["returned_content_ids"]
    assert model["launch_identity"] == LAUNCH
    assert model["context"]["rules_digest"] == RULES


def test_operator_key_is_stable_across_exports_and_specific_to_that_key(tmp_path):
    store = linked_store(tmp_path / "trust.sqlite3")
    try:
        first = export_decision_records(adapter(store), pseudonym_key=OPERATOR_KEY)
        second = export_decision_records(adapter(store), pseudonym_key=OPERATOR_KEY)
        other = export_decision_records(adapter(store), pseudonym_key=OTHER_KEY)
    finally:
        store.close()
    reopened = TrustStore.open_readonly(tmp_path / "trust.sqlite3", client_id="customer-owner")
    try:
        later = export_decision_records(adapter(reopened), pseudonym_key=OPERATOR_KEY)
    finally:
        reopened.close()
    assert first["pseudonymization"]["scope"] == "operator_key"
    for repeat in (second, later):
        assert repeat["records"] == first["records"]
        assert repeat["observations"] == first["observations"]
        assert repeat["pseudonymization"]["export_id"] != first["pseudonymization"]["export_id"]
    assert identifiers(first) and identifiers(first).isdisjoint(identifiers(other))


def key_encodings(key):
    return [key.decode("latin-1"), key.hex(), key.hex().upper(), base64.b64encode(key).decode(),
            base64.urlsafe_b64encode(key).decode(), base64.b32encode(key).decode(),
            hashlib.sha256(key).hexdigest(), hashlib.sha512(key).hexdigest(),
            hmac.new(key, b"", hashlib.sha256).hexdigest()]


def test_key_material_and_key_verifiers_never_appear_in_the_export(tmp_path):
    store = linked_store(tmp_path / "trust.sqlite3")
    try:
        exported = export_decision_records(adapter(store), pseudonym_key=OPERATOR_KEY)
    finally:
        store.close()
    serialized = json.dumps(exported)
    for encoding in key_encodings(OPERATOR_KEY):
        assert encoding not in serialized
    assert set(exported["pseudonymization"]) == {"method", "scope", "export_id"}
    assert exported["pseudonymization"]["method"] == "hmac-sha256"


@pytest.mark.parametrize("key,error,message", [
    ("text-key-is-not-bytes-0123456789abcdef", TypeError, "must be bytes"),
    (bytearray(OPERATOR_KEY), TypeError, "must be bytes"),
    (b"short-operator-key", ValueError, "at least 32 bytes"), (b"", ValueError, "at least 32 bytes")])
def test_unusable_operator_keys_are_refused_without_echoing_them(tmp_path, key, error, message):
    store = reviewer_store(tmp_path / "export.sqlite3")
    try:
        with pytest.raises(error, match=message) as raised:
            export_decision_records(adapter(store), pseudonym_key=key)
    finally:
        store.close()
    text = key if isinstance(key, str) else bytes(key).decode()
    if text:
        assert text not in str(raised.value)


# Separate-process CLI: read-only store access, the key file option, and no writes.

def cli(config, *args):
    environment = dict(os.environ, PYTHONPATH=str(REPO_ROOT))
    return subprocess.run([sys.executable, "-m", "mcp_trust_monitor", "--config", str(config), *args],
                          capture_output=True, text=True, timeout=120, cwd=str(config.parent),
                          env=environment)


def cli_state(tmp_path):
    (tmp_path / "definition.json").write_text(json.dumps(
        {"name": "echo", "description": "synthetic", "inputSchema": {"type": "object"}}))
    (tmp_path / "policy.json").write_text(json.dumps(
        {"policy_id": "export-privacy", "revision": "1", "rules": []}))
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"state_dir": "state", "policy_path": "policy.json",
        "timeout_seconds": 30, "servers": [{"server_id": "payroll-production",
            "command": sys.executable, "cwd": str(tmp_path), "origin": "synthetic_fixture",
            "args": [str(SERVER), "--definition", "definition.json", "--calls", "calls.jsonl"]}]}))
    observed = cli(config, "observe", "payroll-production")
    assert observed.returncode == 0, observed.stderr[-500:]
    return config


def snapshot(directory):
    return {path.name: (path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in sorted(directory.iterdir()) if path.is_file()}


def test_cli_export_opens_the_store_read_only_and_writes_nothing(tmp_path):
    config = cli_state(tmp_path)
    state = tmp_path / "state"
    key_file = tmp_path / "export.key"
    key_file.write_bytes(OPERATOR_KEY)
    key_file.chmod(0o400)
    before, key_before = snapshot(state), snapshot(tmp_path)["export.key"]
    outputs = []
    for args in ((), ("--pseudonym-key-file", str(key_file)), ("--pseudonym-key-file", str(key_file))):
        exported = cli(config, "export", *args)
        assert exported.returncode == 0, exported.stderr[-500:]
        outputs.append(json.loads(exported.stdout))
    after = snapshot(state)
    assert after["trust.sqlite3"] == before["trust.sqlite3"]  # database bytes unchanged
    assert {name: value for name, value in after.items() if name in before} == before
    # A read-only SQLite reader of a WAL database may leave only its empty sidecars.
    assert set(after) - set(before) <= {"trust.sqlite3-wal", "trust.sqlite3-shm"}
    assert after.get("trust.sqlite3-wal", (0,))[0] == 0
    assert snapshot(tmp_path)["export.key"] == key_before
    default, keyed, keyed_again = outputs
    assert default["pseudonymization"]["scope"] == "export"
    assert keyed["pseudonymization"]["scope"] == "operator_key"
    assert keyed["records"] == keyed_again["records"] and keyed["records"]
    assert identifiers(default).isdisjoint(identifiers(keyed))
    for output in outputs:
        serialized = json.dumps(output)
        assert "payroll-production" not in serialized
        for encoding in key_encodings(OPERATOR_KEY):
            assert encoding not in serialized


def test_cli_refuses_a_short_key_file_without_printing_it(tmp_path):
    config = cli_state(tmp_path)
    key_file = tmp_path / "short.key"
    key_file.write_bytes(b"short-synthetic-key")
    refused = cli(config, "export", "--pseudonym-key-file", str(key_file))
    assert refused.returncode == 1
    assert refused.stdout == ""
    assert json.loads(refused.stderr.strip().splitlines()[-1]) == {"error": "ValueError"}
    assert "short-synthetic-key" not in refused.stderr
    missing = cli(config, "export", "--pseudonym-key-file", str(tmp_path / "absent.key"))
    assert missing.returncode == 1 and missing.stdout == ""


def test_policy_change_invalidation_events_are_recognized_not_unrecognized(tmp_path):
    """Integration of R2 with R7: the new decision_context_invalidated audit event is
    exported as a recognized event type with its generation and states."""
    store = TrustStore(tmp_path / "trust.sqlite3", client_id="client")
    store.invalidate_policy("policy@1#sha256:" + "5" * 64)  # activation at owner open
    store.record_observation("srv", REV, TOOLS)
    store.invalidate_policy("policy@2#sha256:" + "6" * 64)  # a genuine change
    events = [event for event in store.events("srv")
              if event["event_type"] == "decision_context_invalidated"]
    assert len(events) == 1
    records = export_decision_records(adapter(store))["records"]
    exported = [record for record in records if record["event_type"] == "decision_context_invalidated"]
    assert len(exported) == 1 and exported[0]["generation"] == events[0]["generation"]
    assert not any(record["event_type"] == "unrecognized" for record in records)
    store.close()
