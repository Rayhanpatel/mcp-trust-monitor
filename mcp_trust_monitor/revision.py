"""Canonical metadata digests that bind trust decisions to exact revisions (REQ-REV-01)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

DIGEST_PREFIX = "sha256:"


def canonical_json(value: Any) -> bytes:
    """Serialize with sorted keys and fixed separators; text is preserved byte for byte."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(value: Any) -> str:
    return DIGEST_PREFIX + hashlib.sha256(canonical_json(value)).hexdigest()


def tool_metadata(tool: Mapping[str, Any]) -> dict[str, Any]:
    """The reviewed fields of one tool definition. Other MCP fields are not yet covered."""
    return {
        "name": tool["name"],
        "description": tool.get("description"),
        "inputSchema": tool.get("inputSchema"),
    }


def tool_revision(tool: Mapping[str, Any]) -> str:
    return digest(tool_metadata(tool))


def server_revision(tools: Iterable[Mapping[str, Any]]) -> str:
    """Digest over sorted (name, tool revision) pairs; additions and removals change it."""
    entries = sorted([tool["name"], tool_revision(tool)] for tool in tools)
    names = [name for name, _ in entries]
    if len(names) != len(set(names)):
        raise ValueError("tools/list returned duplicate tool names")
    return digest(entries)
