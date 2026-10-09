#!/usr/bin/env python3
"""
registry_probe_prototype.py — inherited research prototype, 2026-10-09.

Enumerates the official MCP registry, connects to each remote server over
streamable-HTTP, calls tools/list unauthenticated, and emits one JSON record
per attempted endpoint, with nested tools. See docs/EVIDENCE.md for limitations.

Reported by the original research session (not remeasured during repo setup):
    208 unique remote URLs across 6 registry pages
    120 probed -> 35 servers answered tools/list -> 287 tool definitions
    (82 HTTP 401/403, 3 connection errors)

Usage:
    python3 -I tools/registry_probe_prototype.py gather  # -> remotes.json
    python3 -I tools/registry_probe_prototype.py probe [N]  # -> tools_corpus.json

No dependencies beyond the stdlib. Network discovery is not run on import.
This is not the implemented application collector.
"""
import concurrent.futures as cf
import json
import sys
import time
import urllib.request

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
PROTOCOL = "2025-06-18"


def _post(url, body, sid=None, timeout=10):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL,
    }
    if sid:
        headers["Mcp-Session-Id"] = sid
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return dict(r.headers), r.read().decode("utf-8", "replace")


def _parse(text):
    """Remote MCP servers may answer JSON or SSE-framed JSON."""
    if "data:" in text:
        chunks = [l[5:].strip() for l in text.splitlines() if l.startswith("data:")]
        text = chunks[-1] if chunks else text
    try:
        return json.loads(text)
    except Exception:
        return None


def gather(pages=6, limit=100):
    """Page the registry, keeping only isLatest versions, dedup remote URLs."""
    out, seen, cursor = [], set(), None
    for _ in range(pages):
        url = f"{REGISTRY}?limit={limit}" + (f"&cursor={cursor}" if cursor else "")
        doc = json.load(urllib.request.urlopen(url, timeout=20))
        for entry in doc.get("servers", []):
            server = entry.get("server", {})
            meta = entry.get("_meta", {}).get(
                "io.modelcontextprotocol.registry/official", {}
            )
            if not meta.get("isLatest"):
                continue
            for remote in server.get("remotes") or []:
                u = remote.get("url")
                if u and u not in seen:
                    seen.add(u)
                    out.append(
                        {
                            "server": server.get("name"),
                            "version": server.get("version"),
                            "url": u,
                            "transport": remote.get("type"),
                            "published": meta.get("publishedAt"),
                        }
                    )
        cursor = doc.get("metadata", {}).get("nextCursor")
        if not cursor:
            break
    return out


def probe(item):
    """initialize -> notifications/initialized -> tools/list. Returns a record."""
    url = item["url"]
    t0 = time.perf_counter()
    try:
        headers, text = _post(
            url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "registry-probe", "version": "0.1"},
                },
            },
        )
        sid = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
        info = (_parse(text) or {}).get("result", {}).get("serverInfo", {})
        try:
            _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized",
                        "params": {}}, sid)
        except Exception:
            pass  # several servers reject the notification but still serve tools/list
        _, text2 = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                               "params": {}}, sid)
        tools = (_parse(text2) or {}).get("result", {}).get("tools", [])
        return {**item, "status": "ok", "server_info": info, "tools": tools,
                "latency_ms": int((time.perf_counter() - t0) * 1000)}
    except Exception as e:
        return {**item, "status": f"{type(e).__name__}", "error": str(e)[:120],
                "tools": [], "latency_ms": int((time.perf_counter() - t0) * 1000)}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if cmd == "gather":
        remotes = gather()
        json.dump(remotes, open("remotes.json", "w"), indent=1)
        print(f"gathered {len(remotes)} remote MCP endpoints -> remotes.json")
        return
    try:
        remotes = json.load(open("remotes.json"))
    except FileNotFoundError:
        remotes = gather()
        json.dump(remotes, open("remotes.json", "w"), indent=1)
    n = int(sys.argv[2]) if len(sys.argv) > 2 else len(remotes)
    results = []
    with cf.ThreadPoolExecutor(24) as ex:
        for r in ex.map(probe, remotes[:n]):
            results.append(r)
    ok = [r for r in results if r["status"] == "ok" and r["tools"]]
    json.dump(results, open("tools_corpus.json", "w"), indent=1)
    print(
        f"probed={len(results)} answered_tools_list={len(ok)} "
        f"tools={sum(len(r['tools']) for r in ok)} -> tools_corpus.json"
    )


if __name__ == "__main__":
    main()
