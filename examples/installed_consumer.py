"""Run after installing the wheel, from a directory outside every checkout.

Copy this file and external_stdio_server.py together into that directory. This
consumer creates its own policy and configured server: no checkout resources,
editable install, PYTHONPATH, cloud service, or demo-server helper is required.
"""
import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path

from mcp_trust_monitor.config import MonitorConfig, ServerConfig
from mcp_trust_monitor.managed_client import CallBlocked
from mcp_trust_monitor.sdk import TrustMonitor


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


async def run(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    definition = root / "tool.json"
    calls = root / "received-calls.jsonl"
    policy = root / "operator-policy.json"
    tool = {"name": "echo_public_note", "description": "Echo a caller-supplied public note.",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                            "required": ["text"], "additionalProperties": False}}
    write_json(definition, tool)
    write_json(policy, {"policy_id": "partner-policy", "revision": "1",
        "rules": [{"id": "PARTNER-001", "requirement": "Only echo caller-supplied public text."}]})
    server_id = "partner/public-notes"
    server = ServerConfig(server_id=server_id, command=sys.executable,
        args=(str(Path(__file__).with_name("external_stdio_server.py").resolve()),
              "--definition", str(definition.resolve()), "--calls", str(calls.resolve())),
        origin="synthetic_fixture")
    config = MonitorConfig(state_dir=root / "trust", policy_path=policy,
                           servers={server_id: server})
    async with TrustMonitor(config) as monitor:
        observed = await monitor.observe(server_id)
        await monitor.approve(server_id, revision=observed.observed_revision,
                              expected_generation=observed.generation, actor="example-operator")
        catalog = monitor.catalog(server_id)
        assert len(catalog) == 1, "Approved catalog unavailable"
        await monitor.call_tool(server_id, "echo_public_note", {"text": "hello"},
                                selection=catalog[0].selection)
        before = len(calls.read_text(encoding="utf-8").splitlines())
        assert before == 1, f"Expected one server-side call, got {before}"
        tool["description"] = "Echo a public note with newly changed formatting guidance."
        write_json(definition, tool)
        changed = await monitor.observe(server_id)
        assert changed.observed_revision != observed.observed_revision
        assert monitor.catalog(server_id) == (), "Changed metadata leaked into protected discovery"
        try:
            await monitor.call_tool(server_id, "echo_public_note", {"text": "blocked"})
        except CallBlocked as exc:
            print(f"Changed revision blocked before dispatch: {exc.reason}")
        else:
            raise AssertionError("Changed revision was dispatched")
        after = len(calls.read_text(encoding="utf-8").splitlines())
        assert after == before, "Server received the blocked call"
        print(json.dumps({"origin": "synthetic_fixture", "server_id": server_id,
            "state": changed.state.value, "server_calls_before": before,
            "server_calls_after": after, "installed_consumer": "passed"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path,
                        help="New directory for this run (must not exist)")
    args = parser.parse_args()
    if args.work_dir:
        asyncio.run(run(args.work_dir.resolve()))
    else:
        with tempfile.TemporaryDirectory(prefix="mtm-consumer-") as temp:
            asyncio.run(run(Path(temp) / "run"))
