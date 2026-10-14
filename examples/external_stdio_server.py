"""Independent synthetic MCP server; imports no mcp_trust_monitor code.

The definition file is re-read on every tools/list. Calls are recorded by this
server before handling, providing independent nondispatch evidence to the example.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


async def serve(definition_path: Path, calls_path: Path, name: str) -> None:
    server = Server(name)
    calls_path.parent.mkdir(parents=True, exist_ok=True)
    calls_path.touch(exist_ok=True)

    @server.list_tools()
    async def tools_list():
        return [types.Tool(**json.loads(definition_path.read_text(encoding="utf-8")))]

    @server.call_tool()
    async def tool_call(tool_name: str, arguments: dict):
        return {"origin": "synthetic_fixture", "tool": tool_name,
                "echo": arguments.get("text", "")}

    original = server.request_handlers[types.CallToolRequest]

    async def record_call(request):
        with calls_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"method": "tools/call", "tool": request.params.name}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return await original(request)

    server.request_handlers[types.CallToolRequest] = record_call
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--definition", type=Path, required=True)
    parser.add_argument("--calls", type=Path, required=True)
    parser.add_argument("--name", default="partner-notes")
    args = parser.parse_args()
    asyncio.run(serve(args.definition.resolve(), args.calls.resolve(), args.name))
