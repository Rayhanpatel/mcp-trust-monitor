"""Command line for the managed client and the controlled demo servers.

Every command reads and writes the same persisted trust store, so a quarantine
issued here is honored by any running client on its next dispatch.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from . import demo_server as demo
from . import history
from .detector import DetectorError, verify_semgrep
from .managed_client import CallBlocked, ManagedClient, trust_db_path
from .policy import load_policy
from .review import review_server, verify_blocked
from .trust_store import StaleDecisionError, TrustError, TrustStore

DEFAULT_STATE_DIR = demo.REPO_ROOT / "runtime" / "state"
DEFAULT_POLICY = demo.REPO_ROOT / "policies" / "demo-policy.json"


def _client(args: argparse.Namespace, state_dir: Path | None = None,
            run_id: str | None = None) -> ManagedClient:
    state_dir = state_dir or args.state_dir
    store = TrustStore(trust_db_path(state_dir), client_id=args.client_id, run_id=run_id)
    servers = {sid: demo.server_config(sid, state_dir, args.fixture) for sid in demo.DEMO_SERVERS}
    return ManagedClient(store, servers, policy_revision=load_policy(args.policy).binding)


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
    store = TrustStore(trust_db_path(args.state_dir), client_id=args.client_id)
    print(f"active policy: {load_policy(args.policy).binding}")
    for record in store.records():
        _print_record(record)
        for tool in record.observed_tools:
            print(f"  tool {tool['name']}: {tool['description']!r}")
    return 0


async def cmd_observe(args: argparse.Namespace) -> int:
    async with _client(args) as client:
        _print_record(await client.observe(args.server))
    return 0


async def cmd_approve(args: argparse.Namespace) -> int:
    store = TrustStore(trust_db_path(args.state_dir), client_id=args.client_id)
    record = store.approve(
        args.server, revision=args.revision, policy_revision=load_policy(args.policy).binding,
        expected_generation=args.generation, actor="operator-cli", restore=args.restore,
    )
    _print_record(record)
    return 0


async def cmd_quarantine(args: argparse.Namespace) -> int:
    store = TrustStore(trust_db_path(args.state_dir), client_id=args.client_id)
    _print_record(store.quarantine(args.server, actor="operator-cli", reason=args.reason))
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
    calls = demo.received_requests(args.state_dir, args.server)
    print(f"{args.server} received {len(calls)} tools/call request(s)")
    return 0


async def cmd_mutate(args: argparse.Namespace) -> int:
    if args.baseline:
        demo.clear_definition(args.state_dir)
        print(f"{demo.MUTABLE_SERVER} now serves the fixture baseline")
    else:
        tool = demo.scenario_definition(demo.load_fixture(args.fixture), args.scenario)
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


async def cmd_review(args: argparse.Namespace) -> int:
    """One hard-deny review pass on persisted state; never approves."""
    async with _client(args) as client:
        report = await review_server(client, args.server, policy_path=args.policy)
    print(f"{args.server}: {report.outcome} after {report.attempts} attempt(s)"
          f"  revision {report.revision}")
    _print_detection(report.detection)
    if report.error:
        print(f"    detector error: {report.error}")
    return 0 if report.outcome in ("quarantined", "pending_review", "skipped") else 1


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
    store = TrustStore(trust_db_path(args.state_dir), client_id=args.client_id)
    try:
        settings = history.load_settings()
    except history.SettingsMissing as missing:
        print(f"not delivered: {missing}; {store.outbox_status()['pending']} event(s) stay pending")
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

    async with _client(args, state_dir, run_id) as client:
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
            store = client.store
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
        store = client.store

    print("[5] deliver this run's outbox to ClickHouse and read it back")
    local = store.outbox_status()
    try:
        settings = history.load_settings()
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
              f"python -m mcp_trust_monitor --state-dir {state_dir} deliver")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m mcp_trust_monitor", description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--fixture", type=Path, default=demo.DEFAULT_FIXTURE)
    parser.add_argument("--client-id", default="demo-client")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("status", help="show trust records").set_defaults(run=cmd_status)

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
    review.set_defaults(run=cmd_review)

    commands.add_parser("deliver", help="deliver pending history events to ClickHouse"
                        ).set_defaults(run=cmd_deliver)
    commands.add_parser("demo", help="run the scripted M1 walkthrough").set_defaults(run=cmd_demo)
    commands.add_parser("demo-m2", help="run the M2 hard-deny walkthrough and ClickHouse read-back"
                        ).set_defaults(run=cmd_demo_m2)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(args.run(args))
    except TrustError as refused:  # includes StaleDecisionError
        print(f"refused: {refused}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
