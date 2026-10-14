"""Raw stdio MCP server that answers its first tools/call and then stops reading stdin.

Used only in real-transport tests of client backpressure (REQ-ENF-04/05). It models a
wedged or adversarial server: after the first call it never drains its input pipe, so
client writes eventually block in the operating system. Every tools/call it actually
reads is appended to the log given as argv[1] before it answers.
"""
import json
import sys
import time

log = sys.argv[1]
stdin = sys.stdin.buffer


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


while True:
    line = stdin.readline()
    if not line:
        break
    message = json.loads(line)
    method, request_id = message.get("method"), message.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": message["params"]["protocolVersion"],
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "stalling-test-server", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": [
            {"name": "effect", "description": "A local test effect.",
             "inputSchema": {"type": "object"}}]}})
    elif method == "tools/call":
        with open(log, "a", encoding="utf-8") as stream:
            stream.write("call\n")
        send({"jsonrpc": "2.0", "id": request_id, "result": {
            "content": [{"type": "text", "text": "ok"}], "isError": False}})
        while True:  # Never read stdin again; terminated by the client's close sequence.
            time.sleep(3600)
    elif request_id is not None:
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
