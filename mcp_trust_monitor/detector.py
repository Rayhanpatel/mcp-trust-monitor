"""Deterministic hard-deny detection with pinned local Semgrep (REQ-DEC-01, REQ-DEC-04).

Semgrep runs from an isolated `uvx` environment pinned to one version, so it never
changes the application's reviewed MCP dependency. Override the command with
`MCP_TRUST_SEMGREP` (for example an absolute path to a verified executable).

Each tool description is written to its own file in a fresh temporary directory and
only those explicit targets are scanned; with zero tools nothing is run, so the
working directory is never scanned. Evidence spans are sliced from the scanned bytes
using Semgrep's byte offsets (logged-out Semgrep replaces `extra.lines` with
"requires login") and reported as character offsets into the description. Any
error, timeout, unexpected version, unscanned target, or malformed result raises
`DetectorError`: a failed scan is never a clean result and never approves.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Collection, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES = REPO_ROOT / "rules" / "hard_deny.yaml"
SEMGREP_VERSION = "1.180.0"
RULE_PREFIX = "hard-deny."
DEFAULT_TIMEOUT_SECONDS = 120.0


class DetectorError(Exception):
    """The scan did not complete cleanly; the revision must stay pending review."""


@dataclass(frozen=True)
class Evidence:
    tool: str
    field: str
    start: int  # character offsets into the field's text
    end: int
    text: str


@dataclass(frozen=True)
class HardDenyMatch:
    rule_id: str
    policy_id: str
    evidence: Evidence


@dataclass(frozen=True)
class DetectorResult:
    matches: tuple[HardDenyMatch, ...]
    rules_digest: str
    semgrep_version: str
    scanned_tools: int

    @property
    def policy_ids(self) -> tuple[str, ...]:
        return tuple(sorted({match.policy_id for match in self.matches}))

    def as_dict(self) -> dict[str, Any]:
        return {
            "detector": "semgrep",
            "policy_ids": list(self.policy_ids),
            "rules_digest": self.rules_digest,
            "semgrep_version": self.semgrep_version,
            "scanned_tools": self.scanned_tools,
            "matches": [
                {"rule_id": m.rule_id, "policy_id": m.policy_id, "tool": m.evidence.tool,
                 "field": m.evidence.field, "start": m.evidence.start, "end": m.evidence.end,
                 "text": m.evidence.text}
                for m in self.matches
            ],
        }


def rules_digest_of(rules_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(rules_bytes).hexdigest()


def semgrep_command() -> list[str]:
    override = os.environ.get("MCP_TRUST_SEMGREP")
    if override:
        return shlex.split(override)
    uvx = shutil.which("uvx")
    if uvx is None:
        raise DetectorError("uvx is not on PATH; install uv or set MCP_TRUST_SEMGREP")
    return [uvx, "--from", f"semgrep=={SEMGREP_VERSION}", "semgrep"]


def _run(arguments: Sequence[str], *, timeout: float, cwd: str | None = None) -> str:
    command = [*semgrep_command(), *arguments]
    try:
        # Own process group, so a timeout also stops the Semgrep process uvx started.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, text=True, cwd=cwd,
                                   start_new_session=True)
    except OSError as exc:
        raise DetectorError(f"semgrep could not start: {exc}") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise DetectorError(f"semgrep timed out after {timeout:g}s") from exc
    if process.returncode != 0:
        raise DetectorError(f"semgrep exited {process.returncode}: {stderr[-300:]}")
    return stdout


def verify_semgrep(timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Check that the configured executable runs and is the pinned version."""
    version = _run(["--version"], timeout=timeout).strip()
    if version != SEMGREP_VERSION:
        raise DetectorError(f"semgrep reports version {version[:40]!r}, expected {SEMGREP_VERSION}")
    return version


def scan_tools(
    tools: Sequence[Mapping[str, Any]],
    *,
    rules_path: Path = DEFAULT_RULES,
    known_policy_ids: Collection[str] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> DetectorResult:
    try:
        rules_bytes = Path(rules_path).read_bytes()
    except OSError as exc:
        raise DetectorError(f"cannot read hard-deny rules: {exc}") from exc
    rules_digest = rules_digest_of(rules_bytes)
    if not tools:
        # Never invoke Semgrep without explicit targets: it would scan the working directory.
        return DetectorResult(matches=(), rules_digest=rules_digest,
                              semgrep_version="not-run", scanned_tools=0)
    with tempfile.TemporaryDirectory(prefix="mcp-trust-scan-") as tmp:
        # Scan a private copy, so the recorded digest is exactly the rules Semgrep read.
        rules_copy = Path(tmp) / "hard_deny_rules.yaml"
        rules_copy.write_bytes(rules_bytes)
        targets: dict[str, tuple[str, bytes]] = {}
        for index, tool in enumerate(tools):
            data = (tool.get("description") or "").encode("utf-8")
            path = (Path(tmp) / f"tool-{index}.txt").resolve()
            path.write_bytes(data)
            targets[str(path)] = (str(tool["name"]), data)
        stdout = _run(["scan", "--metrics=off", "--disable-version-check", "--quiet", "--json",
                       "--config", str(rules_copy.resolve()), *targets],
                      timeout=timeout_seconds, cwd=tmp)
        try:
            report = json.loads(stdout)
            if report.get("version") != SEMGREP_VERSION:
                raise DetectorError(f"semgrep output version {report.get('version')!r}")
            if report.get("errors"):
                raise DetectorError(f"semgrep reported errors: {report['errors']!r:.300}")
            scanned = {str(Path(p).resolve()) for p in report["paths"]["scanned"]}
            if not targets.keys() <= scanned:
                raise DetectorError("semgrep did not scan every tool description")
            matches = [_match(result, targets, known_policy_ids)
                       for result in report["results"]]
        except DetectorError:
            raise
        except Exception as exc:  # malformed JSON or shape: never a clean result
            raise DetectorError(f"semgrep returned malformed output: {exc!r:.200}") from exc
    return DetectorResult(matches=tuple(matches), rules_digest=rules_digest,
                          semgrep_version=report["version"], scanned_tools=len(targets))


def _match(result: Mapping[str, Any], targets: Mapping[str, tuple[str, bytes]],
           known_policy_ids: Collection[str] | None) -> HardDenyMatch:
    path = str(Path(result["path"]).resolve())
    if path not in targets:
        raise DetectorError("semgrep reported a result outside the scan targets")
    tool_name, data = targets[path]
    start, end = result["start"]["offset"], result["end"]["offset"]
    if not (isinstance(start, int) and isinstance(end, int) and 0 <= start < end <= len(data)):
        raise DetectorError(f"semgrep reported offsets {start!r}..{end!r} outside the target")
    try:
        prefix, span = data[:start].decode("utf-8"), data[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DetectorError("semgrep offsets split a UTF-8 character") from exc
    policy_id = result.get("extra", {}).get("metadata", {}).get("policy_id")
    if not policy_id or (known_policy_ids is not None and policy_id not in known_policy_ids):
        raise DetectorError(f"rule {result['check_id']} has an unknown policy_id {policy_id!r}")
    # Semgrep prefixes local rule ids with the config path ("rules.hard-deny...").
    check_id = result["check_id"]
    rule_id = check_id[check_id.find(RULE_PREFIX):] if RULE_PREFIX in check_id else check_id
    return HardDenyMatch(rule_id=rule_id, policy_id=policy_id,
                         evidence=Evidence(tool=tool_name, field="description",
                                           start=len(prefix), end=len(prefix) + len(span),
                                           text=span))
