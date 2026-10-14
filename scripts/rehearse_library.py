#!/usr/bin/env python3
"""Rehearse the original six frozen fixtures through the public TrustMonitor SDK.

Local: uv run python scripts/rehearse_library.py
Live:  uv run python scripts/rehearse_library.py --live --env-file /explicit/.env

Each invocation gets a new evidence directory. Baseline approvals are explicit
synthetic-fixture actions, not human verdicts or lesson approvals. No memory cases,
held-out cases, lessons, publication, or ClickHouse delivery are performed.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp_trust_monitor import MonitorConfig, TrustMonitor
from mcp_trust_monitor import demo_server as demo
from mcp_trust_monitor.assessor import DEFAULT_MODEL
from mcp_trust_monitor.detector import rules_digest_of, verify_semgrep
from mcp_trust_monitor.evaluate import verdict
from mcp_trust_monitor.evidence import export_decision_records
from mcp_trust_monitor.history import sanitize
from mcp_trust_monitor.managed_client import CallBlocked
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer
from mcp_trust_monitor.policy import DetectorBinding, load_policy
from mcp_trust_monitor.senso import SensoClient

FROZEN = {
    "fixtures/tool_changes.json": "60233171f953a690c08a3e16c4ed9130e06754f9016b64282fed33011ee0a2fc",
    "policies/demo-policy.json": "bb08d75e7bcc762e887630d1c2470c18f4b36119f1f9682df42ed9a1cd27cae9",
    "rules/hard_deny.yaml": "e0a2685c906de76f165586c7b71a73f89dd8a414982745581c9fea594e56d2c4",
}
RULE_MAPPING = {
    "hard-deny.pol-001.private-content-to-address": "POL-001",
    "hard-deny.pol-002.override-operator-policy": "POL-002",
}
LOOKUP, CONTROL = demo.MUTABLE_SERVER, demo.CONTROL_SERVER
LOOKUP_ARGS = {"title": "Synthetic public annual report"}


def read_settings(path: Path) -> dict[str, str]:
    """Read only the explicitly selected file; never print or inherit credentials."""
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        if key.strip() in {"OPENAI_API_KEY", "SENSO_API_KEY", "SENSO_POLICY_CONTENT_IDS", "MODEL_NAME"}:
            values[key.strip()] = value.strip().strip("\"'")
    for key in ("OPENAI_API_KEY", "SENSO_API_KEY", "SENSO_POLICY_CONTENT_IDS"):
        if not values.get(key):
            raise ValueError("required live setting is missing")
    return values


def write(path: Path, value, secrets=()):
    text = sanitize(json.dumps(value, indent=2, ensure_ascii=False), list(secrets))
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text + "\n", encoding="utf-8")
    temporary.replace(path)


def freeze(directory: Path):
    for relative, expected in FROZEN.items():
        source = ROOT / relative
        if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
            raise ValueError("the original six-case fixture/policy/rules changed")
        target = directory / "frozen" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return (directory / "frozen/fixtures/tool_changes.json",
            directory / "frozen/policies/demo-policy.json",
            directory / "frozen/rules/hard_deny.yaml")


async def measured_call(monitor, state_dir, server_id, tool, arguments):
    before = demo.received_call_count(state_dir, server_id)
    dispatched = monitor.client.dispatch_count(server_id)
    reason, error = None, None
    try:
        response = await monitor.call_tool(server_id, tool, arguments)
        if response.isError:
            error = "tool_error"
    except CallBlocked as blocked:
        reason = blocked.reason
    except Exception as exc:
        error = type(exc).__name__
    after = demo.received_call_count(state_dir, server_id)
    return {"blocked_reason": reason, "error_type": error,
            "received_before": before, "received_after": after,
            "client_dispatches_before": dispatched,
            "client_dispatches_after": monitor.client.dispatch_count(server_id)}


def call_succeeded(evidence):
    return (evidence["blocked_reason"] is None and evidence["error_type"] is None
            and evidence["received_after"] == evidence["received_before"] + 1
            and evidence["client_dispatches_after"] == evidence["client_dispatches_before"] + 1)


async def run_case(case, directory, fixture_path, policy_path, detector, reviewer, secrets):
    state_dir = directory / "cases" / case["id"]
    profiles = {sid: demo.server_config(sid, state_dir, fixture_path) for sid in demo.DEMO_SERVERS}
    config = MonitorConfig(state_dir, policy_path, profiles, client_id="six-fixture-rehearsal",
        detector=detector, reviewer=reviewer, poll_interval=180, timeout_seconds=90)
    result = {"case_id": case["id"], "origin": "synthetic_fixture",
              "expected_outcome": case["expected_outcome"],
              "expected_hard_deny_policy_ids": case["expected_hard_deny_policy_ids"],
              "status": "started", "errors": []}
    async with TrustMonitor(config) as monitor:
        # This script's only approvals: named, observed synthetic baseline revisions.
        for sid in demo.DEMO_SERVERS:
            baseline = await monitor.observe(sid)
            await monitor.approve(sid, revision=baseline.observed_revision,
                expected_generation=baseline.generation, actor="synthetic-rehearsal-operator")
        result["baseline_lookup"] = await measured_call(monitor, state_dir, LOOKUP, "lookup_document", LOOKUP_ARGS)
        result["baseline_control"] = await measured_call(monitor, state_dir, CONTROL, "health_check", {})
        demo.write_definition(state_dir, demo.scenario_definition(demo.load_fixture(fixture_path), case["id"]))
        changed = await monitor.observe(LOOKUP)
        result["changed_revision"] = changed.observed_revision
        result["changed_generation"] = changed.generation
        result["state_after_change"] = changed.state.value
        result["pre_review_call"] = await measured_call(monitor, state_dir, LOOKUP, "lookup_document", LOOKUP_ARGS)
        started = time.perf_counter()
        review = await monitor.review_once(LOOKUP, observe=False)
        result["review_seconds"] = time.perf_counter() - started
        result["review"] = asdict(review)
        events = monitor.events(LOOKUP)
        scan = next((row for row in reversed(events) if row["actor"] == "hard-deny-detector"
            and row["event_type"] in ("hard_deny_scan_clean", "quarantine_requested")), None)
        result["actual_hard_deny_policy_ids"] = sorted(scan["detail"].get("policy_ids", [])) if scan else None
        result["detector_contract"] = "pass" if (scan is not None and
            result["actual_hard_deny_policy_ids"] == sorted(case["expected_hard_deny_policy_ids"])) else "error"
        current = monitor.status(LOOKUP)
        result["applied_outcome"] = current.state.value
        applied = next((row for row in reversed(events) if row["event_type"] == "quarantine_applied"), None)
        proof = await measured_call(monitor, state_dir, LOOKUP, "lookup_document", LOOKUP_ARGS)
        after = monitor.status(LOOKUP)
        proof.update({"state_after": after.state.value, "generation_after": after.generation,
                      "quarantine_applied_event_id": applied["event_id"] if applied else None,
                      "applied_generation": applied["generation"] if applied else None})
        unchanged = (proof["received_before"] == proof["received_after"] and
                     proof["client_dispatches_before"] == proof["client_dispatches_after"])
        proof["local_nondispatch"] = bool(unchanged and proof["blocked_reason"] and not proof["error_type"])
        proof["verified_blocked"] = bool(applied and unchanged and not proof["error_type"]
            and proof["blocked_reason"] == "quarantined" and after.state.value == "quarantined"
            and after.generation == applied["generation"])
        # Canonical audit schema used by the decision-record exporter. Retain the
        # descriptive report field too; both reflect the exact measured checks.
        proof["verified"] = proof["verified_blocked"]
        if applied:
            monitor.store.record_event(LOOKUP,
                "verified_blocked" if proof["verified_blocked"] else "verification_failed",
                actor="synthetic-rehearsal-verifier", detail=proof)
        result["post_review_call"] = proof
        # Refresh only the unchanged control; quarantine stays closed.
        await monitor.observe(CONTROL)
        result["control_after_review"] = await measured_call(monitor, state_dir, CONTROL, "health_check", {})
        model = review.detail if hasattr(review.detail, "recommendation") else None
        if review.detector in ("failed", "stale") or review.assessment in ("failed", "stale"):
            result["combined_verdict"] = "error"
        else:
            result["combined_verdict"] = verdict(case["expected_outcome"], current.state.value)
        result["model_only_verdict"] = (verdict(case["expected_outcome"],
            "quarantined" if model.recommendation == "quarantine" else "pending_review")
            if model and model.stage == "completed" else
            "error" if review.assessment in ("failed", "stale") else "not_run")
        result["errors"] += [name for name in ("baseline_lookup", "baseline_control", "control_after_review")
                              if not call_succeeded(result[name])]
        pre = result["pre_review_call"]
        if (pre["blocked_reason"] != "pending_review" or pre["error_type"] or
            pre["received_before"] != pre["received_after"] or
            pre["client_dispatches_before"] != pre["client_dispatches_after"]):
            result["errors"].append("change_invalidated_before_review")
        if not proof["local_nondispatch"] or (applied and not proof["verified_blocked"]):
            result["errors"].append("post_review_enforcement")
        raw_events = monitor.events()
        exported = export_decision_records(monitor)
        if applied:
            # Export identifiers are keyed pseudonyms (schema 2). Records follow the
            # store's event order, so the applied event's pseudonym is found by position.
            applied_pid = next((row["event_id"] for raw, row in zip(raw_events, exported["records"])
                if raw["event_id"] == applied["event_id"]), None
                ) if len(raw_events) == len(exported["records"]) else None
            exported_proof = next((row for row in reversed(exported["records"])
                if applied_pid is not None
                and row["event_type"] in ("verified_blocked", "verification_failed")
                and row["links"].get("quarantine_applied_event_id") == applied_pid), None)
            result["exported_verification_level"] = (exported_proof["evidence"]["verification_level"]
                if exported_proof else "missing")
            if proof["verified"] and result["exported_verification_level"] != "independent_counter_verified_blocked":
                result["errors"].append("verification_export")
        write(state_dir / "decision-records.json", exported, secrets)
        result["status"] = "completed"
        result["outbox"] = monitor.store.outbox_status()
        write(state_dir / "events.json", monitor.events(), secrets)
        write(state_dir / "result.json", result, secrets)
    return result


async def run(args):
    directory = args.output_root.resolve() / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + ("-live-" if args.live else "-local-") + uuid.uuid4().hex[:8])
    directory.mkdir(parents=True, exist_ok=False)
    report = {"origin": "synthetic_fixture", "mode": "live" if args.live else "local",
              "gate_scope": "six applied combined outcomes and enforcement" if args.live else
                  "six detector expectations and enforcement; model coverage unavailable",
              "cloud": "requested" if args.live else "disabled", "memory": "disabled",
              "history_delivery": "disabled; outbox retained locally", "cases": [],
              "fixture_file_sha256": FROZEN, "directory": str(directory),
              "package_version": importlib.metadata.version("mcp-trust-monitor"),
              "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "python": sys.version.split()[0], "setup_error": None}
    secrets = []
    try:
        report["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        fixture_path, policy_path, rules_path = freeze(directory)
        fixture = demo.load_fixture(fixture_path)
        report["planned_cases"] = [{"case_id": c["id"], "expected_outcome": c["expected_outcome"],
            "expected_hard_deny_policy_ids": c["expected_hard_deny_policy_ids"]} for c in fixture["scenarios"]]
        detector = DetectorBinding(rules_path, load_policy(policy_path).digest,
                                   rules_digest_of(rules_path.read_bytes()), RULE_MAPPING)
        detector.validate(policy_path)
        report["semgrep_version"] = await asyncio.to_thread(verify_semgrep)
        reviewer = None
        if args.live:
            if args.env_file is None:
                raise ValueError("--live requires an explicit --env-file")
            settings = read_settings(args.env_file)
            secrets = [settings["OPENAI_API_KEY"], settings["SENSO_API_KEY"]]
            model = args.model or settings.get("MODEL_NAME") or DEFAULT_MODEL
            reviewer = OpenAIReviewer(api_key=settings["OPENAI_API_KEY"], model=model,
                senso_client=SensoClient(settings["SENSO_API_KEY"], attempts=1),
                policy_content_ids=tuple(value.strip() for value in settings["SENSO_POLICY_CONTENT_IDS"].split(",") if value.strip()),
                memory_enabled=False, max_retries=0, timeout_seconds=90, max_output_tokens=8000)
            report["model_configuration"] = {"model": model, "max_retries": 0,
                "timeout_seconds": 90, "max_output_tokens": 8000, "senso_attempts": 1}
        write(directory / "report.json", report, secrets)
        print(json.dumps({"directory": str(directory), "mode": report["mode"]}), flush=True)
        for case in fixture["scenarios"]:
            try:
                result = await run_case(case, directory, fixture_path, policy_path, detector, reviewer, secrets)
            except Exception as exc:
                result = {"case_id": case["id"], "expected_outcome": case["expected_outcome"],
                          "status": "error", "error_type": type(exc).__name__,
                          "combined_verdict": "error", "model_only_verdict": "error",
                          "detector_contract": "error", "errors": ["case_execution"]}
            report["cases"].append(result)
            write(directory / "report.json", report, secrets)
            print(json.dumps({"case": case["id"], "detector": result["detector_contract"],
                "applied": result.get("applied_outcome"), "combined": result["combined_verdict"],
                "model_only": result["model_only_verdict"], "errors": result["errors"]}), flush=True)
        report["summary"] = {field: dict(Counter(case[field] for case in report["cases"]))
            for field in ("detector_contract", "combined_verdict", "model_only_verdict")}
        report["enforcement_ok"] = all(not case["errors"] for case in report["cases"])
        report["complete"] = len(report["cases"]) == len(fixture["scenarios"])
        report["demonstrations"] = {"M2": "private-content-demand", "M3": "private-content-without-address"}
        report["interpretation"] = ("Applied SDK outcomes. Model-only covers detector-clean cases only; hard denials skip the model. "
            "A pending malicious case is a blocked miss, never a pass. Local mode has no model semantic coverage. "
            "Single-trial fixture regression, not held-out accuracy or memory improvement evidence.")
        ok = report["enforcement_ok"] and report["summary"]["detector_contract"] == {"pass": 6}
        if args.live:
            ok = ok and report["summary"]["combined_verdict"] == {"pass": 6}
        report["gate_passed"] = ok
    except Exception as exc:
        report["setup_error"] = type(exc).__name__
        report["gate_passed"] = False
    write(directory / "report.json", report, secrets)
    print(json.dumps({"gate_passed": report["gate_passed"], "setup_error": report["setup_error"],
                      "summary": report.get("summary"), "report": str(directory / "report.json")}), flush=True)
    return 0 if report["gate_passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--output-root", type=Path, default=ROOT / "runtime/release/library-regression")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
