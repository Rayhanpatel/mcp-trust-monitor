"""Historical hackathon demonstrations (M1-M3). This is NOT the library CLI.

These commands replay the original fixture walkthroughs against the two synthetic
demo servers. They operate only on dedicated demo state: a state directory marked
by a regular `historical-demo-state` file, which a command creates on first use of a
directory that holds no trust store. They refuse library state directories (use
`mcp-trust-monitor --config CONFIG` or `python -m mcp_trust_monitor --config CONFIG`
for those) and refuse to write while another process owns the directory
(REQ-LIB-04). `status` and `received` only read.

Path defaults (runtime/state, policies/demo-policy.json, fixtures/tool_changes.json,
.env) exist only when running from a source checkout. An installed package has no
default demo paths; pass them explicitly.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
import tempfile
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Iterator

from . import demo_server as demo
from . import history
from .detector import DetectorError, verify_semgrep
from .managed_client import CallBlocked, ManagedClient, trust_db_path
from .ownership import OwnershipError, StateOwner
from .policy import load_policy
from .assessor import DEFAULT_MODEL, OpenAIAssessor
from .evaluate import evaluate_cases, format_report, report_json
from .model_review import ModelReviewReport, model_review
from .review import review_server, verify_blocked
from .senso import SensoClient, SensoError, load_env, retrieve_policy, upload_policy
from .trust_store import StaleDecisionError, TrustError, TrustStore

PROG = "python -m mcp_trust_monitor.historical_demo"
MODEL_SETTINGS = ("SENSO_API_KEY", "SENSO_POLICY_CONTENT_IDS", "OPENAI_API_KEY")

# The directory above this package. Only a source checkout supplies default demo paths.
PACKAGE_ROOT = demo.REPO_ROOT
_INSTALL_DIRECTORIES = frozenset({"site-packages", "dist-packages"})

# Dedicated demo state is marked explicitly; library state never carries this file.
MARKER_NAME = "historical-demo-state"
MARKER_CONTENT = {"purpose": "historical-demo"}
# Files a library owner (or an earlier unmarked run) leaves in a state directory.
_STORE_TRACES = ("trust.sqlite3", "trust.sqlite3-wal", "trust.sqlite3-shm",
                 "trust.sqlite3-journal", "owner.lock", "owner.unclean")


class DemoStateRefused(TrustError):
    """The directory is not dedicated demo state, or another process owns it."""


def checkout_root(root: Path | None = None) -> Path | None:
    """The source checkout this package runs from, or None for an installed package."""
    root = Path(PACKAGE_ROOT if root is None else root).resolve()
    if _INSTALL_DIRECTORIES & set(root.parts):
        return None
    if (root / "pyproject.toml").is_file() and (root / "fixtures" / "tool_changes.json").is_file():
        return root
    return None


def is_demo_state(state_dir: Path) -> bool:
    """True only for a directory whose marker is a regular file (symlinks do not count)."""
    try:
        return stat.S_ISREG(os.lstat(Path(state_dir) / MARKER_NAME).st_mode)
    except OSError:
        return False


def _library_refusal(state_dir: Path, traces: list[str]) -> DemoStateRefused:
    return DemoStateRefused(
        f"{state_dir} holds trust state ({', '.join(traces)}) but no {MARKER_NAME} marker, so it "
        "is library state, not historical demo state. Nothing was changed. Operate on it with "
        "`mcp-trust-monitor --config CONFIG`, or pass a fresh --state-dir for the historical demo.")


def _traces(state_dir: Path) -> list[str]:
    return [name for name in _STORE_TRACES if os.path.lexists(Path(state_dir) / name)]


def check_demo_state_readable(state_dir: Path) -> None:
    """Refuse to read unmarked library state. Writes nothing."""
    if not is_demo_state(state_dir) and (traces := _traces(state_dir)):
        raise _library_refusal(state_dir, traces)


def claim_demo_state(state_dir: Path) -> None:
    """Mark a directory without a trust store as demo state; refuse anything else.

    Runs before ownership is acquired: `StateOwner.acquire` itself writes owner files,
    so an unmarked library directory must be refused first and never written.
    """
    state_dir = Path(state_dir)
    marker = state_dir / MARKER_NAME
    if is_demo_state(state_dir):
        return
    if os.path.lexists(marker):
        raise DemoStateRefused(f"{marker} exists but is not a regular file; nothing was changed")
    if traces := _traces(state_dir):
        raise _library_refusal(state_dir, traces)
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        with marker.open("x", encoding="utf-8") as stream:
            json.dump(MARKER_CONTENT, stream)
            stream.write("\n")
    except FileExistsError:
        pass  # a concurrent historical command marked it first
    except OSError as exc:
        raise DemoStateRefused(f"cannot mark {state_dir} as historical demo state: {exc}") from None
    if not is_demo_state(state_dir):
        raise DemoStateRefused(f"{marker} is not a regular file; nothing was changed")


@contextmanager
def owned_store(state_dir: Path, client_id: str, run_id: str | None = None) -> Iterator[TrustStore]:
    """The only writable store in this module: marked demo state, exclusively owned.

    Mirrors the library owner: acquire, open, recover after an unclean exit, and
    release cleanly only when the store has not faulted.
    """
    claim_demo_state(state_dir)
    owner = StateOwner(state_dir)
    try:
        owner.acquire()
    except OwnershipError:
        raise DemoStateRefused(
            f"{state_dir} is owned by another process (a running TrustMonitor or historical "
            "command); historical demo commands never write state they do not own. "
            "Nothing was changed.") from None
    store: TrustStore | None = None
    opened = False
    try:
        store = TrustStore(trust_db_path(state_dir), client_id=client_id, run_id=run_id)
        if owner.recovery_required:
            store.recover_owner()
        opened = True
        yield store
    finally:
        clean = opened and store is not None and not store.faulted
        try:
            if store is not None:
                store.close()
        finally:
            owner.release(clean=clean)


def _servers(state_dir: Path, fixture: Path) -> dict:
    return {sid: demo.server_config(sid, state_dir, fixture) for sid in demo.DEMO_SERVERS}


@asynccontextmanager
async def _client(args: argparse.Namespace, state_dir: Path | None = None,
                  run_id: str | None = None) -> AsyncIterator[ManagedClient]:
    state_dir = state_dir or args.state_dir
    binding = load_policy(args.policy).binding
    with owned_store(state_dir, args.client_id, run_id) as store:
        async with ManagedClient(store, _servers(state_dir, args.fixture),
                                 policy_revision=binding) as client:
            yield client


def _print_record(record: Any) -> None:
    print(f"{record.server_id}: {record.state.value}  generation={record.generation}")
    print(f"  observed revision: {record.observed_revision}")
    print(f"  approved revision: {record.approved_revision}")
    print(f"  approved under policy: {record.approved_policy_revision}")
    if record.observation_failed_at is not None:
        print(f"  observation failed at {record.observation_failed_at}; "
              "observe successfully before approving or restoring")


def _result_text(result: Any) -> str:
    if result.structuredContent is not None:
        return json.dumps(result.structuredContent)
    return " ".join(getattr(block, "text", "") for block in result.content)


async def cmd_status(args: argparse.Namespace) -> int:
    """Read-only snapshot: never migrates, never needs ownership, coexists with an owner."""
    check_demo_state_readable(args.state_dir)
    print(f"active policy: {load_policy(args.policy).binding}")
    path = trust_db_path(args.state_dir)
    if not path.exists():
        print("no trust records")
        return 0
    store = TrustStore.open_readonly(path, client_id=args.client_id)
    try:
        records = store.records()
    finally:
        store.close()
    if not records:
        print("no trust records")
    for record in records:
        _print_record(record)
        for tool in record.observed_tools:
            print(f"  tool {tool['name']}: {tool['description']!r}")
    return 0


async def cmd_observe(args: argparse.Namespace) -> int:
    async with _client(args) as client:
        _print_record(await client.observe(args.server))
    return 0


async def cmd_approve(args: argparse.Namespace) -> int:
    binding = load_policy(args.policy).binding
    with owned_store(args.state_dir, args.client_id) as store:
        record = store.approve(
            args.server, revision=args.revision, policy_revision=binding,
            expected_generation=args.generation, actor="operator-cli", restore=args.restore,
        )
    _print_record(record)
    return 0


async def cmd_quarantine(args: argparse.Namespace) -> int:
    with owned_store(args.state_dir, args.client_id) as store:
        record = store.quarantine(args.server, actor="operator-cli", reason=args.reason)
    _print_record(record)
    return 0


async def cmd_call(args: argparse.Namespace) -> int:
    async with _client(args) as client:
        try:
            result = await client.call_tool(args.server, args.tool, json.loads(args.arguments))
        except CallBlocked as blocked:
            print(f"BLOCKED before dispatch: {blocked.reason}")
            return 3
    print(_result_text(result))
    return 1 if result.isError else 0


async def cmd_received(args: argparse.Namespace) -> int:
    check_demo_state_readable(args.state_dir)
    calls = demo.received_requests(args.state_dir, args.server)
    print(f"{args.server} received {len(calls)} tools/call request(s)")
    return 0


async def cmd_mutate(args: argparse.Namespace) -> int:
    if args.baseline:
        with owned_store(args.state_dir, args.client_id):
            demo.clear_definition(args.state_dir)
        print(f"{demo.MUTABLE_SERVER} now serves the fixture baseline")
    else:
        tool = demo.scenario_definition(demo.load_fixture(args.fixture), args.scenario)
        with owned_store(args.state_dir, args.client_id):
            demo.write_definition(args.state_dir, tool)
        print(f"{demo.MUTABLE_SERVER} now serves scenario {args.scenario}")
    return 0


async def cmd_demo(args: argparse.Namespace) -> int:
    """Scripted M1 walkthrough over real stdio MCP transport in a fresh state directory."""
    state_dir = Path(tempfile.mkdtemp(prefix="mcp-trust-demo-"))
    lookup, control = demo.MUTABLE_SERVER, demo.CONTROL_SERVER
    fixture = demo.load_fixture(args.fixture)

    def received(server_id: str) -> int:
        return len(demo.received_requests(state_dir, server_id))

    async def try_call(client: ManagedClient, server_id: str, tool: str, arguments: dict) -> None:
        try:
            result = await client.call_tool(server_id, tool, arguments)
            outcome = f"ok {_result_text(result)}"
        except CallBlocked as blocked:
            outcome = f"BLOCKED before dispatch ({blocked.reason})"
        print(f"    call {server_id}/{tool}: {outcome}")
        print(f"    server-side received tools/call count for {server_id}: {received(server_id)}")

    print(f"state directory: {state_dir}  (all data synthetic_fixture)")
    async with _client(args, state_dir) as client:
        print("[1] observe both servers; first observation is unreviewed")
        records = {sid: await client.observe(sid) for sid in (lookup, control)}
        for record in records.values():
            print(f"    {record.server_id}: {record.state.value} {record.observed_revision[:19]}")
        await try_call(client, lookup, "lookup_document", {"title": "Annual report"})

        print("[2] operator explicitly approves both baselines")
        for record in records.values():
            await client.approve(record.server_id, revision=record.observed_revision,
                                 expected_generation=record.generation, actor="operator-demo")
        await try_call(client, lookup, "lookup_document", {"title": "Annual report"})
        await try_call(client, control, "health_check", {})

        print("[3] harmless wording change: approval invalidated, pending operator review")
        baseline = client.store.get(lookup)
        demo.write_definition(state_dir, demo.scenario_definition(fixture, "harmless-wording-change"))
        changed = await client.observe(lookup)
        print(f"    {lookup}: {changed.state.value} {changed.observed_revision[:19]}")
        await try_call(client, lookup, "lookup_document", {"title": "Annual report"})
        try:
            await client.approve(lookup, revision=baseline.observed_revision,
                                 expected_generation=baseline.generation, actor="stale-replay")
        except StaleDecisionError as stale:
            print(f"    stale approval of the old revision rejected: {stale}")
        await client.approve(lookup, revision=changed.observed_revision,
                             expected_generation=changed.generation, actor="operator-demo")
        print("    operator approved the new revision explicitly")
        await try_call(client, lookup, "lookup_document", {"title": "Annual report"})

        print("[4] quarantine the mutable server")
        await client.quarantine(lookup, actor="operator-demo", reason="manual M1 demo")
        await try_call(client, lookup, "lookup_document", {"title": "Annual report"})
        await try_call(client, control, "health_check", {})

    print("[5] restart the managed client with the same state")
    async with _client(args, state_dir) as client:
        print(f"    {lookup}: {client.store.get(lookup).state.value}")
        await try_call(client, lookup, "lookup_document", {"title": "Annual report"})
        await try_call(client, control, "health_check", {})
    return 0


def _print_detection(detection: dict | None) -> None:
    for match in (detection or {}).get("matches", []):
        print(f"    {match['policy_id']} {match['rule_id']}  {match['tool']}.{match['field']}"
              f"[{match['start']}:{match['end']}]")
        print(f"      evidence: {match['text']!r}")


class SettingsMissing(Exception):
    pass


def _content_ids(env_file: Path) -> list[str]:
    value = load_env(["SENSO_POLICY_CONTENT_IDS"], env_file).get("SENSO_POLICY_CONTENT_IDS", "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _model_stage(args: argparse.Namespace) -> dict:
    """Scoped Senso retrieval and the OpenAI assessor, from .env (values never printed)."""
    return _model_parts(args)[0]


def _model_parts(args: argparse.Namespace) -> tuple[dict, OpenAIAssessor]:
    """The model-stage keyword arguments for `model_review`, and the assessor itself."""
    env = load_env([*MODEL_SETTINGS, "MODEL_NAME"], args.env_file)
    missing = [key for key in MODEL_SETTINGS if not env.get(key)]
    if missing:
        raise SettingsMissing(f"missing {', '.join(missing)}")
    senso = SensoClient(env["SENSO_API_KEY"])
    ids = _content_ids(args.env_file)
    assessor = OpenAIAssessor(env["OPENAI_API_KEY"], env.get("MODEL_NAME") or DEFAULT_MODEL)
    return ({"retrieve": lambda: retrieve_policy(senso, ids, args.policy),
             "assess": assessor.assess,
             "configured_content_ids": lambda: _content_ids(args.env_file),
             "model": assessor.model, "response_id": lambda: assessor.last_response_id},
            assessor)


def _print_model(report: ModelReviewReport) -> None:
    if report.retrieved:
        print(f"    Senso policy: {report.retrieved['policy_id']} revision "
              f"{report.retrieved['revision']}, {report.retrieved['passages']} scoped passage(s) "
              f"from {report.retrieved['content_ids']} verified; digest "
              f"{report.retrieved['policy_digest'][:19]}")
    if report.validated:
        v = report.validated
        print(f"    model {report.model}: recommends {v.recommendation} "
              f"{list(v.policy_ids)}; validation passed (exact spans, retrieved sources)")
        for item in v.evidence:
            print(f"      evidence [{item['tool']}]: {item['text']!r}")
    if report.rejected:
        print(f"    model output REJECTED by validation: {'; '.join(report.rejected)}")
    if report.error:
        print(f"    model stage FAILED at {report.stage}: {report.error}")
    print(f"    applied outcome: {report.outcome}")


async def cmd_review(args: argparse.Namespace) -> int:
    """Hard-deny review, then optionally the model stage. Never approves."""
    stage = None
    if args.model:
        try:
            stage = _model_stage(args)
        except SettingsMissing as missing:
            print(f"model stage unavailable: {missing}")
            return 2
    async with _client(args) as client:
        report = await review_server(client, args.server, policy_path=args.policy)
        print(f"{args.server}: {report.outcome} after {report.attempts} attempt(s)"
              f"  revision {report.revision}")
        _print_detection(report.detection)
        if report.error:
            print(f"    detector error: {report.error}")
        ok = report.outcome in ("quarantined", "pending_review", "skipped")
        if stage is not None:
            model = await model_review(client, args.server, policy_path=args.policy, **stage)
            _print_model(model)
            ok = ok and model.outcome not in ("failed", "stale")
    return 0 if ok else 1


async def cmd_senso_upload(args: argparse.Namespace) -> int:
    """Upload only the operator policy to Senso and save its content ID in the env file."""
    env = load_env(["SENSO_API_KEY"], args.env_file)
    if not env.get("SENSO_API_KEY"):
        print("not uploaded: missing SENSO_API_KEY")
        return 2
    try:
        result = upload_policy(SensoClient(env["SENSO_API_KEY"]), args.policy, args.env_file,
                               force=args.force)
    except SensoError as exc:
        print(f"upload FAILED: {exc}")
        return 1
    verb = "uploaded and saved" if result["uploaded"] else "already configured (use --force)"
    print(f"policy {verb}: SENSO_POLICY_CONTENT_IDS={','.join(result['content_ids'])}")
    return 0


async def cmd_evaluate(args: argparse.Namespace) -> int:
    """Live evaluation of the fixed cases; outcomes are computed, not applied.

    Exit 1 if any required stage failed for any case. Those cases are errors, not decisions.
    """
    try:
        stage, assessor = _model_parts(args)
    except SettingsMissing as missing:
        print(f"evaluation unavailable: {missing}")
        return 2
    retrieval, results = await asyncio.to_thread(
        evaluate_cases, demo.load_fixture(args.fixture), args.policy,
        retrieve=stage["retrieve"], assess=stage["assess"],
        response_metadata=assessor.response_metadata)
    model_config = {"name": assessor.model, "max_retries": assessor.max_retries}
    print(format_report(retrieval, results, model_config=model_config))
    if args.json:
        Path(args.json).write_text(report_json(retrieval, results, model_config=model_config),
                                   encoding="utf-8")
        print(f"report written to {args.json}")
    failed = isinstance(retrieval, str) or any(r.errors for r in results)
    if failed:
        print("FAILED: at least one required stage failed; those cases are errors, not decisions")
    return 1 if failed else 0


def _deliver(store: TrustStore, settings: dict[str, str]) -> history.DeliveryResult:
    secrets = history.secrets_of(settings)
    try:
        client = history.ClickHouseHTTP(settings)
    except ValueError as exc:
        return history.DeliveryResult(0, store.outbox_status()["pending"],
                                      history.sanitize(str(exc), secrets))
    return history.deliver_pending(store, client, settings["CLICKHOUSE_DATABASE"],
                                   secrets=secrets)


async def cmd_deliver(args: argparse.Namespace) -> int:
    """Deliver pending outbox events to ClickHouse. Exit 0 only if none remain pending."""
    with owned_store(args.state_dir, args.client_id) as store:
        try:
            settings = history.load_settings(args.env_file)
        except history.SettingsMissing as missing:
            print(f"not delivered: {missing}; {store.outbox_status()['pending']} event(s) "
                  "stay pending")
            return 2
        result = _deliver(store, settings)
    print(f"delivered {result.delivered}; pending {result.pending}")
    if result.error:
        print(f"delivery error (sanitized): {result.error}")
    return 0 if result.ok else 1


async def cmd_demo_m2(args: argparse.Namespace) -> int:
    """M2 run: real Semgrep hard-deny -> automatic quarantine -> verified block -> ClickHouse."""
    state_dir = Path(tempfile.mkdtemp(prefix="mcp-trust-demo-m2-"))
    run_id = f"demo-m2-{uuid.uuid4()}"
    lookup, control = demo.MUTABLE_SERVER, demo.CONTROL_SERVER
    fixture = demo.load_fixture(args.fixture)
    lookup_args = {"title": "Annual report"}
    failures: list[str] = []

    def received(server_id: str) -> int:
        # Strict evidence: a missing, unreadable, or malformed log raises, never reads as 0.
        return demo.received_call_counter(state_dir, server_id)()

    def shown(server_id: str) -> str:
        try:
            return str(received(server_id))
        except demo.EvidenceUnavailable as exc:
            return f"unavailable ({exc})"

    async def call(client: ManagedClient, server_id: str, tool: str, arguments: dict) -> bool:
        try:
            result = await client.call_tool(server_id, tool, arguments)
            print(f"    call {server_id}/{tool}: ok {_result_text(result)}")
            ok = not result.isError
        except CallBlocked as blocked:
            print(f"    call {server_id}/{tool}: BLOCKED before dispatch ({blocked.reason})")
            ok = False
        print(f"    server-side received tools/call count for {server_id}: {shown(server_id)}")
        return ok

    print(f"run id: {run_id}")
    print(f"state directory: {state_dir}  (all data synthetic_fixture)")
    try:
        print(f"[0] pinned Semgrep executable verified: {verify_semgrep()}")
    except DetectorError as exc:
        print(f"[0] Semgrep verification FAILED: {exc}")
        return 1

    binding = load_policy(args.policy).binding
    # The owned store outlives the client session: step 5 delivers its outbox.
    with owned_store(state_dir, args.client_id, run_id) as store:
        async with ManagedClient(store, _servers(state_dir, args.fixture),
                                 policy_revision=binding) as client:
            print("[1] operator explicitly approves both baselines; normal calls succeed")
            for server_id in (lookup, control):
                record = await client.observe(server_id)
                await client.approve(server_id, revision=record.observed_revision,
                                     expected_generation=record.generation, actor="operator-demo")
            if not await call(client, lookup, "lookup_document", lookup_args):
                failures.append("baseline lookup")
            if not await call(client, control, "health_check", {}):
                failures.append("baseline control")

            print("[2] the mutable server changes its description (scenario private-content-demand)")
            tool = demo.scenario_definition(fixture, "private-content-demand")
            demo.write_definition(state_dir, tool)
            print(f"    new description: {tool['description']!r}")
            changed = await client.observe(lookup)
            started = time.perf_counter()
            print(f"    {lookup}: {changed.state.value} (approval invalidated) "
                  f"{changed.observed_revision[:19]} generation {changed.generation}")
            await call(client, lookup, "lookup_document", lookup_args)

            print("[3] hard-deny review with real Semgrep; no human decision")
            report = await review_server(client, lookup, policy_path=args.policy)
            _print_detection(report.detection)
            state = client.store.get(lookup).state.value
            print(f"    outcome: {report.outcome}; trust state: {state}; attempts {report.attempts}")
            if report.outcome != "quarantined":
                failures.append(f"review outcome {report.outcome}")

            print("[4] verify through the normal call path; the control is unaffected")
            if report.quarantine is None:
                print("    no applied quarantine to verify")
                print(f"FAILED: {', '.join(failures)}")
                return 1
            verification = await verify_blocked(client, lookup, "lookup_document", lookup_args,
                                                demo.received_call_counter(state_dir, lookup),
                                                quarantine=report.quarantine)
            elapsed_ms = (time.perf_counter() - started) * 1000
            print(f"    call {lookup}/lookup_document: BLOCKED before dispatch "
                  f"({verification['blocked_reason']})" if verification["blocked_reason"]
                  else f"    call {lookup}/lookup_document was NOT blocked")
            print(f"    server-side received count before {verification['received_before']}, "
                  f"after {verification['received_after']}: "
                  f"{'verified_blocked' if verification['verified'] else 'VERIFICATION FAILED'}")
            if not verification["verified"]:
                failures.append("verification: " + "; ".join(verification["problems"]))
            if not await call(client, control, "health_check", {}):
                failures.append("control after quarantine")
            print(f"    measured: observed change -> verified block in {elapsed_ms:.0f} ms "
                  "(includes one Semgrep run)")

        print("[5] deliver this run's outbox to ClickHouse and read it back")
        local = store.outbox_status()
        try:
            settings = history.load_settings(args.env_file)
        except history.SettingsMissing as missing:
            print(f"    NOT DELIVERED: {missing}; {local['pending']} event(s) stay pending locally")
            return 2
        started = time.perf_counter()
        result = _deliver(store, settings)
        print(f"    delivered {result.delivered}, pending {result.pending} "
              f"in {(time.perf_counter() - started) * 1000:.0f} ms")
        if not result.ok:
            print(f"    delivery error (sanitized): {result.error}")
            print(f"    events stay pending in {trust_db_path(state_dir)}; retry with: "
                  f"{PROG} --state-dir {state_dir} --env-file {args.env_file} deliver")
            return 1
        secrets = history.secrets_of(settings)
        database = settings["CLICKHOUSE_DATABASE"]
        clickhouse = history.ClickHouseHTTP(settings)
        try:
            # Simulate a retry after a lost acknowledgement: resend already-delivered events.
            resent = store.delivered_payloads(limit=3)
            clickhouse.execute(f"INSERT INTO `{database}`.{history.TABLE} FORMAT JSONEachRow",
                               body="\n".join(json.dumps(row, sort_keys=True) for row in resent))
            print(f"    re-sent {len(resent)} delivered event(s) with the same IDs "
                  "(simulated retry after a lost acknowledgement)")
            started = time.perf_counter()
            read = history.read_history(clickhouse, database, run_id)
            read_ms = (time.perf_counter() - started) * 1000
        except Exception as exc:
            print(f"    read-back FAILED (sanitized): "
                  f"{history.sanitize(f'{type(exc).__name__}: {exc}', secrets)[:300]}")
            return 1
        expected = store.outbox_status()["delivered"]
    print(f"    ClickHouse rows for this run: {read['raw_rows']} raw, {read['events']} distinct "
          f"event IDs; local delivered events: {expected}; read in {read_ms:.0f} ms")
    if read["events"] != expected or len(read["timeline"]) != expected:
        failures.append("ClickHouse read-back mismatch")
    for row in read["timeline"]:
        if row["event_type"] == "observation_recorded":
            continue
        print(f"    {row['ts']}  {row['server_id']:22} {row['event_type']:22} "
              f"-> {row['to_state'] or '-'}")
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    print("M2 demo complete: all checks matched")
    return 0


async def cmd_demo_m3(args: argparse.Namespace) -> int:
    """M3 run: Semgrep finds nothing, the model (scoped Senso policy) decides, verified, ClickHouse.

    Exits 0 only if every required integration worked and every check matched.
    """
    state_dir = Path(tempfile.mkdtemp(prefix="mcp-trust-demo-m3-"))
    run_id = f"demo-m3-{uuid.uuid4()}"
    lookup, control = demo.MUTABLE_SERVER, demo.CONTROL_SERVER
    scenario = "private-content-without-address"
    fixture = demo.load_fixture(args.fixture)
    lookup_args = {"title": "Annual report"}
    failures: list[str] = []
    counter = demo.received_call_counter

    def shown(server_id: str) -> str:
        try:
            return str(counter(state_dir, server_id)())
        except demo.EvidenceUnavailable as exc:
            return f"unavailable ({exc})"

    async def call(client: ManagedClient, server_id: str, tool: str, arguments: dict) -> bool:
        try:
            result = await client.call_tool(server_id, tool, arguments)
            print(f"    call {server_id}/{tool}: ok")
            ok = not result.isError
        except CallBlocked as blocked:
            print(f"    call {server_id}/{tool}: BLOCKED before dispatch ({blocked.reason})")
            ok = False
        print(f"    server-side received tools/call count for {server_id}: {shown(server_id)}")
        return ok

    print(f"run id: {run_id}")
    print(f"state directory: {state_dir}  (all data synthetic_fixture)")
    try:
        stage = _model_stage(args)
        settings = history.load_settings(args.env_file)
        print(f"[0] pinned Semgrep verified: {verify_semgrep()}; model {stage['model']}; "
              "Senso, OpenAI, and ClickHouse settings present")
    except (SettingsMissing, history.SettingsMissing, DetectorError) as exc:
        print(f"[0] FAILED: required integration unavailable: {exc}")
        return 1

    binding = load_policy(args.policy).binding
    # The owned store outlives the client session: step 6 delivers its outbox.
    with owned_store(state_dir, args.client_id, run_id) as store:
        async with ManagedClient(store, _servers(state_dir, args.fixture),
                                 policy_revision=binding) as client:
            print("[1] operator explicitly approves both baselines; normal calls succeed")
            for server_id in (lookup, control):
                record = await client.observe(server_id)
                await client.approve(server_id, revision=record.observed_revision,
                                     expected_generation=record.generation, actor="operator-demo")
            if not await call(client, lookup, "lookup_document", lookup_args):
                failures.append("baseline lookup")
            if not await call(client, control, "health_check", {}):
                failures.append("baseline control")

            print(f"[2] the mutable server changes its description (scenario {scenario})")
            demo.write_definition(state_dir, demo.scenario_definition(fixture, scenario))
            changed = await client.observe(lookup)
            print(f"    new description: {changed.observed_tools[0]['description']!r}")
            print(f"    {lookup}: {changed.state.value} (approval invalidated), generation "
                  f"{changed.generation}")
            started = time.perf_counter()

            print("[3] deterministic hard-deny stage (real Semgrep)")
            hard = await review_server(client, lookup, policy_path=args.policy)
            hits = (hard.detection or {}).get("policy_ids", [])
            print(f"    Semgrep: {hard.outcome}; hard-deny policy IDs {hits or 'none'}")
            if hard.outcome == "detector_failed":
                failures.append(f"Semgrep failed: {hard.error}")

            print("[4] model stage: scoped Senso retrieval -> OpenAI -> validation -> apply")
            model = await model_review(client, lookup, policy_path=args.policy, **stage)
            _print_model(model)
            if model.outcome in ("failed", "stale"):
                failures.append(f"model stage {model.outcome}"
                                + (f" at {model.stage}" if model.stage else ""))
            state = client.store.get(lookup).state.value
            print(f"    trust state: {state}")

            print("[5] strict verification through the normal call path; control unaffected")
            quarantine = model.quarantine if model.quarantine else hard.quarantine
            if quarantine is None or quarantine.status != "applied":
                failures.append(f"no applied quarantine to verify (outcome {model.outcome})")
                await call(client, lookup, "lookup_document", lookup_args)
            else:
                verification = await verify_blocked(client, lookup, "lookup_document",
                                                    lookup_args, counter(state_dir, lookup),
                                                    quarantine=quarantine)
                print(f"    call {lookup}/lookup_document: blocked "
                      f"({verification['blocked_reason']}); server-side count "
                      f"{verification['received_before']} -> {verification['received_after']}: "
                      + ("verified_blocked" if verification["verified"] else
                         "VERIFICATION FAILED: " + "; ".join(verification["problems"])))
                if not verification["verified"]:
                    failures.append("verification")
            if not await call(client, control, "health_check", {}):
                failures.append("control after quarantine")
            print(f"    measured: observed change -> verification in "
                  f"{(time.perf_counter() - started) * 1000:.0f} ms (Semgrep + Senso + model)")

        print("[6] deliver this run's outbox to ClickHouse and read it back")
        database = settings["CLICKHOUSE_DATABASE"]
        result = _deliver(store, settings)
        print(f"    delivered {result.delivered}, pending {result.pending}")
        if not result.ok:
            print(f"    delivery error (sanitized): {result.error}")
            failures.append("ClickHouse delivery")
        else:
            try:
                read = history.read_history(history.ClickHouseHTTP(settings), database, run_id)
            except Exception as exc:
                secrets = history.secrets_of(settings)
                print(f"    read-back FAILED (sanitized): "
                      f"{history.sanitize(f'{type(exc).__name__}: {exc}', secrets)[:300]}")
                failures.append("ClickHouse read-back")
            else:
                expected = store.outbox_status()["delivered"]
                print(f"    ClickHouse: {read['raw_rows']} raw rows, {read['events']} distinct "
                      f"event IDs; local delivered events: {expected}")
                if read["events"] != expected or len(read["timeline"]) != expected:
                    failures.append("ClickHouse read-back mismatch")
                for row in read["timeline"]:
                    if row["event_type"] == "observation_recorded":
                        continue
                    print(f"    {row['ts']}  {row['server_id']:22} {row['event_type']:26} "
                          f"{row['actor']:20} -> {row['to_state'] or '-'}")
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    print("M3 demo complete: all integrations worked and all checks matched")
    return 0


def _needed_paths(args: argparse.Namespace) -> tuple[str, ...]:
    """The path settings a command actually uses (it never touches the others)."""
    if args.command == "mutate":
        return ("state_dir",) if args.baseline else ("state_dir", "fixture")
    if args.command == "review":
        return ("state_dir", "policy", "fixture") + (("env_file",) if args.model else ())
    return {
        "status": ("state_dir", "policy"),
        "observe": ("state_dir", "policy", "fixture"),
        "approve": ("state_dir", "policy"),
        "quarantine": ("state_dir",),
        "call": ("state_dir", "policy", "fixture"),
        "received": ("state_dir",),
        "senso-upload": ("policy", "env_file"),
        "evaluate": ("policy", "fixture", "env_file"),
        "deliver": ("state_dir", "env_file"),
        "demo": ("policy", "fixture"),
        "demo-m2": ("policy", "fixture", "env_file"),
        "demo-m3": ("policy", "fixture", "env_file"),
    }[args.command]


def _checkout_defaults(root: Path) -> dict[str, Path]:
    return {"state_dir": root / "runtime" / "state",
            "policy": root / "policies" / "demo-policy.json",
            "fixture": root / "fixtures" / "tool_changes.json",
            "env_file": root / ".env"}


def resolve_paths(args: argparse.Namespace) -> list[str]:
    """Fill checkout defaults; return the flags still missing outside a checkout."""
    root = checkout_root()
    defaults = _checkout_defaults(root) if root is not None else {}
    missing = []
    for name in _needed_paths(args):
        if getattr(args, name) is None:
            if name in defaults:
                setattr(args, name, defaults[name])
            else:
                missing.append("--" + name.replace("_", "-"))
    return missing


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state-dir", type=Path, default=None,
                        help="dedicated demo state directory (checkout default: runtime/state)")
    parser.add_argument("--policy", type=Path, default=None,
                        help="policy file (checkout default: policies/demo-policy.json)")
    parser.add_argument("--fixture", type=Path, default=None,
                        help="fixture file (checkout default: fixtures/tool_changes.json)")
    parser.add_argument("--env-file", type=Path, default=None,
                        help="credentials file read (and, by senso-upload, written) by the "
                             "Senso/OpenAI/ClickHouse commands (checkout default: .env)")
    parser.add_argument("--client-id", default="demo-client")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status", help="show trust records (read-only)").set_defaults(run=cmd_status)

    observe = commands.add_parser("observe", help="record a server's current tools/list revision")
    observe.add_argument("server", choices=demo.DEMO_SERVERS)
    observe.set_defaults(run=cmd_observe)

    approve = commands.add_parser("approve", help="explicitly approve one observed revision")
    approve.add_argument("server", choices=demo.DEMO_SERVERS)
    approve.add_argument("--revision", required=True, help="full observed revision digest")
    approve.add_argument("--generation", type=int, help="reject unless the record is still here")
    approve.add_argument("--restore", action="store_true", help="required to lift a quarantine")
    approve.set_defaults(run=cmd_approve)

    quarantine = commands.add_parser("quarantine", help="block all calls to a server")
    quarantine.add_argument("server", choices=demo.DEMO_SERVERS)
    quarantine.add_argument("--reason", default="operator request")
    quarantine.set_defaults(run=cmd_quarantine)

    call = commands.add_parser("call", help="call a tool through the managed client")
    call.add_argument("server", choices=demo.DEMO_SERVERS)
    call.add_argument("tool")
    call.add_argument("arguments", nargs="?", default="{}", help="JSON object")
    call.set_defaults(run=cmd_call)

    received = commands.add_parser("received", help="server-side received tools/call count")
    received.add_argument("server", choices=demo.DEMO_SERVERS)
    received.set_defaults(run=cmd_received)

    mutate = commands.add_parser("mutate", help="change what the mutable demo server advertises")
    target = mutate.add_mutually_exclusive_group(required=True)
    target.add_argument("--scenario", help="fixture scenario id")
    target.add_argument("--baseline", action="store_true", help="serve the fixture baseline")
    mutate.set_defaults(run=cmd_mutate)

    review = commands.add_parser("review", help="hard-deny review of one server (never approves)")
    review.add_argument("server", choices=demo.DEMO_SERVERS)
    review.add_argument("--model", action="store_true",
                        help="then run the Senso + OpenAI model stage (M3)")
    review.set_defaults(run=cmd_review)

    upload = commands.add_parser("senso-upload", help="upload the operator policy to Senso")
    upload.add_argument("--force", action="store_true", help="upload even if already configured")
    upload.set_defaults(run=cmd_senso_upload)

    evaluate = commands.add_parser("evaluate", help="live evaluation of the fixed cases")
    evaluate.add_argument("--json", help="also write the report as JSON to this path")
    evaluate.set_defaults(run=cmd_evaluate)

    commands.add_parser("deliver", help="deliver pending history events to ClickHouse"
                        ).set_defaults(run=cmd_deliver)
    commands.add_parser("demo", help="run the scripted M1 walkthrough").set_defaults(run=cmd_demo)
    commands.add_parser("demo-m2", help="run the M2 hard-deny walkthrough and ClickHouse read-back"
                        ).set_defaults(run=cmd_demo_m2)
    commands.add_parser("demo-m3", help="run the M3 model-review walkthrough (Senso + OpenAI)"
                        ).set_defaults(run=cmd_demo_m3)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    missing = resolve_paths(args)
    if missing:
        print(f"error: {PROG} is not running from a source checkout, so it has no default demo "
              f"paths; {args.command} requires {', '.join(missing)}. Nothing was created. "
              "These historical demonstrations use only dedicated demo state; for library state "
              "use `mcp-trust-monitor --config CONFIG`.", file=sys.stderr)
        return 2
    try:
        return asyncio.run(args.run(args))
    except TrustError as refused:  # includes StaleDecisionError and demo-state refusals
        print(f"refused: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
