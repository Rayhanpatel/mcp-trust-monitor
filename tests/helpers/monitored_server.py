"""Independent instrumented MCP subprocess, used only in real-transport tests."""
import asyncio
import json
import os
import sys
from pathlib import Path
import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

settings, log = map(Path, sys.argv[1:3])
server = Server('independent-monitored-test')

@server.list_tools()
async def tools():
    data = json.loads(settings.read_text())
    if data.get('list_started'):
        Path(data['list_started']).write_text(str(os.getpid()))
    await asyncio.sleep(data.get('list_delay',0))
    if data.get('notify_during_list'):
        await server.request_context.session.send_tool_list_changed()
        await asyncio.sleep(.03)
    return [types.Tool(name='effect', description=data.get('description','A local test effect.'),
                       inputSchema={'type':'object'},
                       annotations=types.ToolAnnotations(title='UNCOVERED'))]

@server.call_tool()
async def call(name, args):
    data = json.loads(settings.read_text())
    with log.open('a') as stream:
        stream.write(json.dumps({'effect': name})+'\n');stream.flush();os.fsync(stream.fileno())
    if data.get('notify_during_call'):
        await server.request_context.session.send_tool_list_changed()
    if data.get('drop_response'):
        os._exit(0)
    await asyncio.sleep(data.get('call_delay',0))
    return [types.TextContent(type='text',text='ok')]

async def main():
    async with stdio_server() as streams:
        await server.run(*streams, server.create_initialization_options())

anyio.run(main)
