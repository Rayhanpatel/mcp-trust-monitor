#!/usr/bin/env python3
"""Synthetic release evidence through the public SDK; no implicit human approval.

sources runs four source assessments. draft requires a reviewed verdict file.
publish requires a separate exact-digest approval file. evaluate freezes and runs
48 held-out trials under an explicit --evaluation-id with opaque server IDs.
None of these commands derive human decisions from labels.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mcp_trust_monitor import MonitorConfig, ServerConfig, TrustMonitor
from mcp_trust_monitor.assessor import DEFAULT_MODEL
from mcp_trust_monitor.detector import DEFAULT_RULES, rules_digest_of
from mcp_trust_monitor.memory import MemoryService
from mcp_trust_monitor.memory_senso import SensoMemoryBackend
from mcp_trust_monitor.openai_reviewer import OpenAIReviewer, ReviewAttempt
from mcp_trust_monitor.paired_evaluation import digest, freeze_plan, run_plan
from mcp_trust_monitor.policy import DetectorBinding, load_policy, policy_rule_ids
from mcp_trust_monitor.revision import server_revision
from mcp_trust_monitor.senso import SensoClient

MANIFEST_VERSION = "x1-memory-cases-2"
MANIFEST_DIGEST = "sha256:bd0f0e4d16e6f81f932a7d1958c15c896d928a3ce6eb71009895196a1871bd9b"
REVIEW_CONFIG = {"top_k": 3, "timeout_seconds": 90, "max_output_tokens": 8000}
OPAQUE_SCHEME = "sha256-trial-identity-v1"
STOPWORDS = frozenset("""a an the and or of to for by it its is are be been this that these those with on in as
from so they them their any each every all if then than not no never also only up per at
you your our we user users anything nothing what which who whom when whenever once was
were has have had can may would will does do into out over under same such there here""".split())


def validate_manifest(manifest):
    if manifest.get("manifest_version") != MANIFEST_VERSION or digest(manifest) != MANIFEST_DIGEST:
        raise ValueError("release fixture differs from the independently frozen manifest")


def reject_heldout_summary(summary, manifest):
    """The frozen six-token/Jaccard rule; no held-out outcomes influence this check."""
    words = lambda text: re.findall(r"[a-z0-9]+", text.lower())
    grams = lambda tokens: {tuple(tokens[i:i + 6]) for i in range(len(tokens) - 5)}
    baseline = words(manifest["lesson_source"][0]["before"]["description"])
    candidate = words(summary)
    for case in manifest["held_out"]:
        held = words(case["after"]["description"])
        a, b = set(candidate) - STOPWORDS - set(baseline), set(held) - STOPWORDS - set(baseline)
        union = a | b
        if ((grams(candidate) & grams(held)) - grams(baseline)
                or (union and len(a & b) / len(union) >= 0.5)):
            raise ValueError("lesson summary duplicates held-out wording under the frozen split rule")


def validate_source_review(memory, manifest, case_id, review, proposal, source):
    sources = {case["id"]: case for case in manifest["lesson_source"]}
    if case_id not in sources or proposal["case_id"] != case_id or review["case_id"] != case_id:
        raise ValueError("only a frozen lesson-source case can supply a lesson")
    case = sources[case_id]
    expected_revision = server_revision([case["after"]])
    observation = next((row for row in memory.store.observations()
                        if row["observation_id"] == source["observation_id"]), None)
    if (not observation or observation["server_id"] != "source/" + case_id
            or observation["revision"] != expected_revision
            or review["revision"] != expected_revision or proposal["revision"] != expected_revision
            or proposal["family"] != case["family"] or not review.get("actor")):
        raise ValueError("human review/proposal does not bind the exact recorded source observation")
    reject_heldout_summary(proposal["summary"], manifest)


def validate_active_sources(memory, manifest, snapshot):
    allowed = {("source/" + case["id"], server_revision([case["after"]]))
               for case in manifest["lesson_source"]}
    for lesson in snapshot.lessons:
        verdict = memory.get_verdict(lesson.verdict_id)
        if (verdict.server_id, verdict.revision) not in allowed:
            raise ValueError("evaluation snapshot contains a lesson outside the frozen source split")
        reject_heldout_summary(json.loads(lesson.body)["summary"], manifest)


def read_settings(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        if key.strip() in {"OPENAI_API_KEY", "SENSO_API_KEY", "SENSO_POLICY_CONTENT_IDS"}:
            values[key.strip()] = value.strip().strip("'\"")
    return values


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def validate_evaluation_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", value):
        raise ValueError("evaluation ID must be 1-48 lowercase letters, numbers, underscores or hyphens")
    return value


def opaque_server_id(evaluation_id, trial_id):
    validate_evaluation_id(evaluation_id)
    if not isinstance(trial_id, str) or not trial_id:
        raise ValueError("trial identity is required")
    return "eval-" + digest([OPAQUE_SCHEME, evaluation_id, trial_id]).removeprefix("sha256:")


def _file_digest(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def versioned_evaluation_setup(directory, manifest, evaluation_id):
    """Claim a new run namespace; never replace even an incomplete previous run."""
    validate_evaluation_id(evaluation_id)
    directory = Path(directory).resolve()
    validate_manifest(manifest)
    if (not (directory / "state/trust.sqlite3").is_file()
            or (directory / "state/owner.unclean").exists()
            or any(not (directory / "source" / case["id"] / "definition.json").is_file()
                   for case in manifest["lesson_source"])):
        raise ValueError("versioned evaluation requires the existing clean source owner")
    original_paths = [directory/name for name in ("paired-plan.json", "paired-results.json")]
    if any(path.exists() for path in original_paths) and not all(path.is_file() for path in original_paths):
        raise ValueError("incomplete original evaluation artifacts must be retained and reviewed")
    prior = {"files": {}}
    if all(path.is_file() for path in original_paths):
        previous = json.loads(original_paths[0].read_text())
        results = json.loads(original_paths[1].read_text())
        if (results.get("complete") is not True or results.get("plan") != previous
                or len(results.get("results", ())) != 48
                or previous["manifest_digest"] != digest(manifest)
                or digest({k:v for k,v in previous.items() if k != "plan_digest"}) != previous["plan_digest"]):
            raise ValueError("retain a complete internally consistent original evaluation before a protocol correction")
        prior = {"files": {path.name:_file_digest(path) for path in original_paths},
                 "plan_digest": previous["plan_digest"], "memory_digest": previous["memory_digest"],
                 "comparison_configuration": {key:previous[key] for key in
                     ("model", "policy_binding", "rules_digest", "review_config")}}
    parent = directory / "evaluations"
    if parent.is_symlink():
        raise ValueError("evaluation namespace cannot be a symlink")
    parent.mkdir(exist_ok=True)
    output = parent / evaluation_id
    output.mkdir(exist_ok=False)
    return output, prior


def validate_existing_source_profiles(config, manifest, prior_plan=None):
    """Read-only preflight before owner initialization can invalidate any record."""
    if prior_plan is not None and load_policy(config.policy_path).binding != prior_plan["policy_binding"]:
        raise ValueError("protocol correction must preserve the original operator policy")
    database = Path(config.state_dir) / "trust.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        rows = dict(db.execute("SELECT server_id, launch_identity FROM trust_records WHERE client_id=?",
                               (config.client_id,)))
        for case in manifest["lesson_source"]:
            sid = "source/" + case["id"]
            if rows.get(sid) != config.servers[sid].launch_identity:
                raise ValueError("source launch identity differs from the original owner")
        if any(sid in rows for sid in config.servers if sid.startswith("eval-")):
            raise ValueError("opaque trial identity already exists; never reuse an attempted trial")


def evaluation_protocol(evaluation_id, plan, snapshot, prior_artifacts):
    validate_evaluation_id(evaluation_id)
    snapshot_value = snapshot.as_dict() if hasattr(snapshot, "as_dict") else snapshot
    mapping = {trial["trial_id"]:opaque_server_id(evaluation_id, trial["trial_id"]) for trial in plan["trials"]}
    if len(mapping) != 48 or len(set(mapping.values())) != 48:
        raise ValueError("protocol correction requires 48 unique scheduled trial identities")
    if digest(snapshot_value) != plan["memory_digest"]:
        raise ValueError("snapshot differs from the frozen evaluation plan")
    if any(plan[key] != value for key,value in prior_artifacts.get("comparison_configuration", {}).items()):
        raise ValueError("protocol correction must preserve the original model, policy, rules and review limits")
    has_prior = bool(prior_artifacts["files"])
    protocol = {"schema": "mcp-trust-monitor.evaluation-protocol", "schema_version": 1,
        "evaluation_id": evaluation_id, "identifier_scheme": OPAQUE_SCHEME,
        "plan_digest": plan["plan_digest"], "manifest_digest": plan["manifest_digest"],
        "memory_digest": plan["memory_digest"], "active_lesson_count": len(snapshot_value["lessons"]),
        "active_lesson_ids": [lesson["lesson_id"] for lesson in snapshot_value["lessons"]],
        "trial_servers": mapping, "prior_artifacts": prior_artifacts,
        "prior_evaluation_present": has_prior, "same_manifest_reused": has_prior,
        "correction_reason": ("Original model-visible server IDs exposed benign/policy case-name hints."
                              if has_prior else "No legacy evaluation is present; use opaque model-visible IDs from the first run."),
        "case_reuse": ("The same eight frozen synthetic cases are reused; these are not new independent cases."
                       if has_prior else "No prior root-level evaluation is present; this run uses the eight frozen synthetic cases."),
        "memory_change": "Freeze the currently eligible approved lessons; preserve prior revocation and never reactivate lessons.",
        "interpretation": ("Separate complete protocol-correction run, not outcome-based replacement. Retain the original functional results. Different memory snapshots must not be pooled or described as the same treatment."
                           if has_prior else "Complete opaque-ID evaluation with a frozen approved memory snapshot. All outcomes, including failures, remain in the denominator.")}
    protocol["protocol_digest"] = digest(protocol)
    return protocol


def validate_evaluation_protocol(protocol, plan, snapshot):
    expected = evaluation_protocol(protocol["evaluation_id"], plan, snapshot, protocol["prior_artifacts"])
    if protocol != expected:
        raise ValueError("opaque protocol, schedule mapping or snapshot binding changed")


def validate_evaluation_artifacts(output, directory, protocol, plan, snapshot):
    """Bind the files to captured values, not a self-consistent replacement."""
    loaded_protocol = json.loads((output / "protocol.json").read_text())
    snapshot_value = snapshot.as_dict() if hasattr(snapshot, "as_dict") else snapshot
    if (loaded_protocol != protocol
            or json.loads((output / "paired-plan.json").read_text()) != plan
            or digest(json.loads((output / "active-memory.json").read_text())) != digest(snapshot_value)):
        raise ValueError("frozen evaluation artifacts changed")
    validate_evaluation_protocol(loaded_protocol, plan, snapshot)
    if any(_file_digest(directory/name) != expected
           for name,expected in protocol["prior_artifacts"]["files"].items()):
        raise ValueError("original evaluation artifacts changed during the separate run")


def configuration(directory, manifest, *, evaluation_id=None):
    if evaluation_id is not None:
        validate_evaluation_id(evaluation_id)
    directory.mkdir(parents=True, exist_ok=True)
    policy = ROOT / "policies/demo-policy.json"
    profiles = {}
    all_cases = [("source/" + case["id"], case, directory / "source" / case["id"])
                 for case in manifest["lesson_source"]]
    for pair in range(1, 4):
        for case in manifest["held_out"]:
            for mode in ("off", "on"):
                trial = f"{case['id']}/{pair}/{mode}"
                sid = "heldout/" + trial if evaluation_id is None else opaque_server_id(evaluation_id, trial)
                local = (directory / sid if evaluation_id is None else
                         directory / "evaluations" / evaluation_id / "servers" / sid)
                all_cases.append((sid, case, local))
    for sid, case, local in all_cases:
        local.mkdir(parents=True, exist_ok=True)
        definition = local / "definition.json"
        if not definition.exists():
            write(definition, case["before"])
        profiles[sid] = ServerConfig(sid, sys.executable,
            args=(str(ROOT / "examples/external_stdio_server.py"),
                  "--definition", str(definition), "--calls", str(local / "calls.jsonl")),
            origin="synthetic_fixture")
    import yaml
    inventory = yaml.safe_load(DEFAULT_RULES.read_text())["rules"]
    detector = DetectorBinding(DEFAULT_RULES, load_policy(policy).digest,
        rules_digest_of(DEFAULT_RULES.read_bytes()),
        {rule["id"]: rule["metadata"]["policy_id"] for rule in inventory})
    return MonitorConfig(directory / "state", policy, profiles, client_id="release-evaluation",
                         detector=detector, timeout_seconds=20.0, poll_interval=120.0)


async def changed_case(monitor, directory, sid, case):
    path = directory / sid / "definition.json"
    if monitor.status(sid) is not None:
        raise ValueError("case already used; retain its outcome, do not repeat it in this evidence run")
    write(path, case["before"])
    before = await monitor.observe(sid)
    # Scripted setup authorizes a synthetic baseline only. It never records human ground truth.
    await monitor.approve(sid, revision=before.observed_revision,
                          expected_generation=before.generation, actor="synthetic-baseline-setup")
    write(path, case["after"])
    return await monitor.observe(sid)


async def assessed_case(monitor, sid, reviewer):
    """Keep deterministic precedence even if a frozen semantic case surprises us."""
    detector = await monitor.review_once(sid, observe=False)
    if detector.detector == "clean":
        model = await reviewer(monitor, sid)
    else:
        model = ReviewAttempt(sid, monitor.status(sid).state.value,
            "skipped_hard_deny" if detector.detector == "matched" else "skipped_detector_failure",
            memory_status="not_attempted")
    return detector, model


async def run(args):
    directory = args.directory.resolve()
    manifest = json.loads((ROOT / "fixtures/memory_cases.json").read_text())
    validate_manifest(manifest)
    evaluation_id = getattr(args, "evaluation_id", None)
    output, prior_artifacts = directory, None
    if args.command == "evaluate":
        if evaluation_id is None:
            raise ValueError("evaluate requires a new explicit --evaluation-id; legacy reports remain immutable")
        output, prior_artifacts = versioned_evaluation_setup(directory, manifest, evaluation_id)
    elif evaluation_id is not None:
        raise ValueError("--evaluation-id is only valid for evaluate")
    config = configuration(directory, manifest, evaluation_id=evaluation_id)
    if args.command == "evaluate":
        previous_plan = (json.loads((directory / "paired-plan.json").read_text())
                         if prior_artifacts["files"] else None)
        validate_existing_source_profiles(config, manifest, previous_plan)
    async with TrustMonitor(config) as monitor:
        memory = MemoryService(monitor.store, lambda: monitor.policy,
            rule_ids=policy_rule_ids(config.policy_path), scope="release-evaluation",
            excluded_revisions=tuple(server_revision([case["after"]]) for case in manifest["held_out"]),
            summary_validator=lambda summary:reject_heldout_summary(summary, manifest))
        if args.command == "draft":
            reviews = json.loads(args.reviewed_verdicts.read_text())
            proposals = json.loads(args.proposals.read_text())
            sources = json.loads((directory / "sources.json").read_text())
            by_id = {r["case_id"]: r for r in reviews}
            if len(by_id) != len(reviews) or len({p["case_id"] for p in proposals}) != len(proposals):
                raise ValueError("duplicate source reviews or proposals")
            # Validate the complete requested batch before recording any human verdict.
            for proposal in proposals:
                case_id = proposal["case_id"]
                validate_source_review(memory, manifest, case_id, by_id[case_id], proposal, sources[case_id])
            drafts = []
            for proposal in proposals:
                review = by_id[proposal["case_id"]]
                source = sources[proposal["case_id"]]
                verdict = memory.record_verdict(observation_id=source["observation_id"],
                    assessment_event_id=source["assessment_event_id"], value=review["value"],
                    actor=review["actor"], rationale=review["rationale"])
                lesson = memory.draft_lesson(verdict.verdict_id, proposal["summary"],
                    actor="draft-assistant", rule_ids=proposal["rule_ids"], family=proposal["family"])
                drafts.append(lesson.as_dict())
            write(directory / "lesson-previews.json", drafts)
            print("Exact lesson previews written; publication still requires digest-bound operator approval.")
            return
        settings = read_settings(args.env_file)
        senso = SensoClient(settings["SENSO_API_KEY"], attempts=1)
        backend = SensoMemoryBackend(senso, capability_evidence=args.capability_evidence)
        def reviewer(enabled):
            return OpenAIReviewer(api_key=settings["OPENAI_API_KEY"], model=args.model,
                senso_client=senso, policy_content_ids=settings["SENSO_POLICY_CONTENT_IDS"].split(","),
                memory_enabled=enabled, memory_backend=backend, memory_scope="release-evaluation",
                max_retries=0, **REVIEW_CONFIG)
        if args.command == "publish":
            approvals = json.loads(args.approvals.read_text())
            all_active = bool(approvals)
            for approval in approvals:
                lesson = memory.approve_lesson(approval["lesson_id"], digest=approval["digest"],
                                               actor=approval["actor"])
                active = await memory.publish(lesson.lesson_id, backend, actor=approval["actor"])
                all_active = all_active and active.state == "active"
                print(json.dumps({"lesson_id": active.lesson_id, "state": active.state}))
            write(directory / "active-memory.json", memory.snapshot(enabled=True).as_dict())
            return 0 if all_active else 1
        if args.command == "sources":
            path = directory / "sources.json"
            if path.exists():
                raise ValueError("source evidence already exists; do not overwrite the run")
            report = {}
            write(path, report)
            for case in manifest["lesson_source"]:
                sid = "source/" + case["id"]
                record = await changed_case(monitor, directory, sid, case)
                detection, result = await assessed_case(monitor, sid, reviewer(False))
                observation = next(o for o in reversed(monitor.store.observations(sid))
                                   if o["revision"] == record.observed_revision and o["generation"] == record.generation)
                report[case["id"]] = {"observation_id": observation["observation_id"],
                    "assessment_event_id": result.assessment_event_id,
                    "review": dataclasses.asdict(result), "detector": dataclasses.asdict(detection)}
                write(path, report)
                print(json.dumps({"case": case["id"], "outcome": result.outcome,
                                  "stage": result.stage, "error_type": result.error_type}), flush=True)
            return 0 if all(row["review"]["stage"] == "completed" for row in report.values()) else 1
        if args.command == "evaluate":
            snapshot = memory.snapshot(enabled=True)
            if len(snapshot.lessons) < 1:
                raise ValueError("no active operator-approved lessons; memory comparison is not ready")
            validate_active_sources(memory, manifest, snapshot)
            plan = freeze_plan(manifest, model=args.model, policy_binding=monitor.policy.binding,
                rules_digest=config.detector.rules_digest, memory_digest=digest(snapshot.as_dict()),
                review_config=REVIEW_CONFIG)
            protocol = evaluation_protocol(evaluation_id, plan, snapshot, prior_artifacts)
            plan_path = output / "paired-plan.json"
            if plan_path.exists():
                raise ValueError("a paired plan already exists; do not silently replace it")
            # All bindings are durable local artifacts before the first observation
            # or model request. The root-level legacy evaluation is never rewritten.
            for name, value in (("protocol.json", protocol), ("active-memory.json", snapshot.as_dict()),
                                ("paired-plan.json", plan)):
                with (output/name).open("x", encoding="utf-8") as file:
                    json.dump(value, file, indent=2, ensure_ascii=False)
            def assert_frozen():
                memory.assert_current(snapshot)
                validate_evaluation_artifacts(output, directory, protocol, plan, snapshot)
                if (args.model != plan["model"] or REVIEW_CONFIG != plan["review_config"]
                        or monitor.policy.binding != plan["policy_binding"]
                        or rules_digest_of(config.detector.rules_path.read_bytes()) != plan["rules_digest"]):
                    raise ValueError("evaluation runtime differs from the frozen configuration")
            position = 0
            async def attempt(case, enabled):
                nonlocal position
                trial = plan["trials"][position]
                position += 1
                assert_frozen()
                sid = protocol["trial_servers"][trial["trial_id"]]
                await changed_case(monitor, output / "servers", sid, case)
                assert_frozen()
                detector, model = await assessed_case(monitor, sid, reviewer(enabled))
                assert_frozen()
                actual = monitor.status(sid).state.value
                detail = detector.detail or {}
                print(json.dumps({"trial": position, "of": len(plan["trials"]),
                    "case": case["id"], "memory": enabled, "applied": actual,
                    "model_stage": model.stage}), flush=True)
                return {"status": "completed" if model.stage in {"completed", "skipped_hard_deny"} else "failed",
                    "applied_outcome": actual, "model_status": model.stage,
                    "model_outcome": "quarantined" if model.recommendation == "quarantine" else
                        "pending_review" if model.recommendation == "review" else None,
                    "detector_status": detector.detector, "detector_ids": detail.get("policy_ids", []),
                    "response": model.response, "precedent_ids": list(model.precedent_ids),
                    "memory_status": model.memory_status, "assessment_event_id": model.assessment_event_id,
                    "model_name": args.model, "max_retries": 0,
                    "server_id": sid, "evaluation_id": evaluation_id,
                    "protocol_digest": protocol["protocol_digest"],
                    "error_type": model.error_type}
            report = await run_plan(plan, manifest, attempt=attempt, report_path=output / "paired-results.json")
            print(json.dumps({"summary": report["summary"], "gate": report["gate"]}), flush=True)
            return 1 if report["gate"]["release_blocked"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["sources", "draft", "publish", "evaluate"])
    parser.add_argument("--directory", type=Path, default=ROOT / "runtime/release/library-live")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--capability-evidence", type=Path, default=ROOT / "runtime/release/senso-capability.json")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--evaluation-id", help="new versioned opaque-ID evaluation; never overwrites a previous run")
    parser.add_argument("--reviewed-verdicts", type=Path)
    parser.add_argument("--proposals", type=Path, default=ROOT / "runtime/release/source-proposals.json")
    parser.add_argument("--approvals", type=Path)
    args = parser.parse_args(argv)
    if args.command != "draft" and args.env_file is None:
        parser.error("this command requires an explicit --env-file")
    if args.command == "draft" and args.reviewed_verdicts is None:
        parser.error("draft requires explicit --reviewed-verdicts")
    if args.command == "publish" and args.approvals is None:
        parser.error("publish requires explicit digest-bound --approvals")
    if args.command == "evaluate" and args.evaluation_id is None:
        parser.error("evaluate requires a new --evaluation-id")
    try:
        return asyncio.run(run(args)) or 0
    except Exception as exc:
        # Provider text can include credentials or untrusted content.
        print(json.dumps({"error_type": type(exc).__name__, "status": "failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
