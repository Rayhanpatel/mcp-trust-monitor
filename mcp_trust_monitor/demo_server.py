"""Controlled local MCP servers for the demo and tests. Synthetic fixture data only.

`demo/document-lookup` is the mutable server: it serves the fixture baseline unless
an override definition has been written. `demo/health-check` is the unaffected
control and cannot be mutated.

Each server appends every received `tools/list` and `tools/call` request to its own
log before handling it. That log is the server-side received-call counter that the
enforcement tests compare against; it is written by the server process, not the
client.

Run: python -m mcp_trust_monitor.demo_server --server demo/document-lookup \
         --state-dir runtime/state --fixture fixtures/tool_changes.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from .managed_client import ServerConfig

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = REPO_ROOT / "fixtures" / "tool_changes.json"
MUTABLE_SERVER = "demo/document-lookup"
CONTROL_SERVER = "demo/health-check"
DEMO_SERVERS = (MUTABLE_SERVER, CONTROL_SERVER)


def load_fixture(path: Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def server_dir(state_dir: Path, server_id: str) -> Path:
    if server_id not in DEMO_SERVERS:
        raise ValueError(f"unknown demo server {server_id}")
    return Path(state_dir) / "servers" / server_id.replace("/", "__")


def baseline_definition(fixture: dict[str, Any], server_id: str) -> dict[str, Any]:
    if server_id == MUTABLE_SERVER:
        return dict(fixture["baseline"])
    return dict(fixture["unaffected_control"]["tool"])


def scenario_definition(fixture: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    """The mutable server's tool after applying one fixture scenario to the baseline."""
    for scenario in fixture["scenarios"]:
        if scenario["id"] == scenario_id:
            tool = baseline_definition(fixture, MUTABLE_SERVER)
            if "replacement_description" in scenario:
                tool["description"] = scenario["replacement_description"]
            if "replacement_input_schema" in scenario:
                tool["inputSchema"] = scenario["replacement_input_schema"]
            return tool
    raise KeyError(f"unknown scenario {scenario_id}")


def current_tools(
    fixture: dict[str, Any], state_dir: Path, server_id: str
) -> list[dict[str, Any]]:
    override = server_dir(state_dir, server_id) / "definition.json"
    if server_id == MUTABLE_SERVER and override.exists():
        definition = json.loads(override.read_text(encoding="utf-8"))
        return definition if isinstance(definition, list) else [definition]
    return [baseline_definition(fixture, server_id)]


def write_definition(state_dir: Path, definition: dict[str, Any] | list[dict[str, Any]]) -> None:
    """Change what the mutable server advertises on its next tools/list.

    A dict is one tool. A list is served as the raw tool list, which lets tests
    produce malformed responses such as duplicate tool names.
    """
    path = server_dir(state_dir, MUTABLE_SERVER) / "definition.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(definition, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def clear_definition(state_dir: Path) -> None:
    (server_dir(state_dir, MUTABLE_SERVER) / "definition.json").unlink(missing_ok=True)


def set_startup_failure(state_dir: Path, server_id: str, enabled: bool) -> None:
    """Make new processes of this server exit before MCP initialization (for tests)."""
    marker = server_dir(state_dir, server_id) / "fail_startup"
    if enabled:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    else:
        marker.unlink(missing_ok=True)


def received_requests(
    state_dir: Path, server_id: str, method: str | None = "tools/call"
) -> list[dict[str, Any]]:
    """Requests the server process recorded receiving, optionally filtered by method."""
    log = server_dir(state_dir, server_id) / "received.jsonl"
    if not log.exists():
        return []
    entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    return [entry for entry in entries if method is None or entry["method"] == method]


def server_config(server_id: str, state_dir: Path, fixture_path: Path) -> ServerConfig:
    """Stdio launch configuration for one demo server, run by the current interpreter.

    PYTHONPATH is explicit so the launch does not depend on an editable-install .pth
    file, which macOS hides (and Python then skips) inside iCloud-synced folders.
    """
    return ServerConfig(
        server_id=server_id,
        command=sys.executable,
        args=(
            "-m", "mcp_trust_monitor.demo_server",
            "--server", server_id,
            "--state-dir", str(Path(state_dir).resolve()),
            "--fixture", str(Path(fixture_path).resolve()),
        ),
        env={"PYTHONPATH": str(REPO_ROOT)},
        origin="synthetic_fixture",
    )


def build_server(server_id: str, state_dir: Path, fixture: dict[str, Any]) -> Server:
    server: Server = Server(server_id)
    log = server_dir(state_dir, server_id) / "received.jsonl"
    log.parent.mkdir(parents=True, exist_ok=True)

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(**tool) for tool in current_tools(fixture, state_dir, server_id)]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if server_id == MUTABLE_SERVER and name == "lookup_document":
            return {
                "title": arguments["title"],
                "summary": f"Synthetic summary of the public document titled {arguments['title']!r}.",
                "origin": "synthetic_fixture",
            }
        if server_id == CONTROL_SERVER and name == "health_check":
            return {"status": "ok", "server": server_id, "origin": "synthetic_fixture"}
        raise ValueError(f"unknown tool {name}")

    def record(entry: dict[str, Any]) -> None:
        entry = {"ts": datetime.now(timezone.utc).isoformat(), "pid": os.getpid(), **entry}
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    list_handler = server.request_handlers[types.ListToolsRequest]
    call_handler = server.request_handlers[types.CallToolRequest]

    async def recorded_list(request: types.ListToolsRequest | None) -> types.ServerResult:
        # The SDK calls this handler with None to refresh its own cache; that is not a request.
        if request is not None:
            record({"method": "tools/list"})
        return await list_handler(request)

    async def recorded_call(request: types.CallToolRequest) -> types.ServerResult:
        record({
            "method": "tools/call",
            "tool": request.params.name,
            "arguments": request.params.arguments,
        })
        return await call_handler(request)

    server.request_handlers[types.ListToolsRequest] = recorded_list
    server.request_handlers[types.CallToolRequest] = recorded_call
    return server


async def _serve(server: Server) -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--server", required=True, choices=DEMO_SERVERS)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args(argv)
    if (server_dir(args.state_dir, args.server) / "fail_startup").exists():
        print(f"{args.server}: simulated startup failure", file=sys.stderr)
        sys.exit(3)
    server = build_server(args.server, args.state_dir, load_fixture(args.fixture))
    anyio.run(_serve, server)


if __name__ == "__main__":
    main()
