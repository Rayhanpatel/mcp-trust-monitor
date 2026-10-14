#!/usr/bin/env python3
"""X1 Senso capability probe (BUILD_PLAN, "Senso capability gate"). Standard library only.

Checks, against Senso's documented API, whether one private synthetic knowledge-base
document can be uploaded, read back exactly by version, found by a scoped search that
never widens, revised, and deleted. Documentation basis: the OpenAPI document "Senso Org
API" 1.13.0 at https://docs.senso.ai/specs/sdk-api.yaml, checked on 12 October 2026
(SHA-256 of the checked copy below). Only these documented operations are used:
orgKBCreateRawContent, orgKBGetNode, orgKBGetContent, orgKBPatchRawContent,
orgKBDeleteNode and orgSearchContext.

Safety rules, each covered by tests/test_senso_probe.py:
- `--plan` prints the steps and exits; it reads no credentials and sends no request.
- A live run needs both `--env-file` and `--confirm-live`. Credentials come from that
  file only, read once; they are never written, exported into the environment or printed.
- The upload and the edit are sent once and never retried automatically. A lost
  upload response is recorded as a possible orphan with its synthetic title, not repeated.
- Edits and deletes target only the document this run created (an ID allowlist), and
  are refused for any configured policy content ID. The node's identity is re-read
  before each modification.
- Every search is scoped: `content_ids` is non-empty and `require_scoped_ids` is true.
  A result outside the requested IDs is recorded as widening and fails the gate.
- The evidence file holds field names, HTTP statuses, version numbers, digests,
  booleans and the IDs of the document this run created. It never holds response
  bodies, organization IDs or key values.

Gate (BUILD_PLAN): met only if the uploaded text reads back exactly with its version,
both versions read back exactly after an edit, and no search widens. Exit status: 0 gate
met, 1 gate unmet or a step failed, 2 refused (usage or missing settings).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:  # run as a script from any directory
    sys.path.insert(0, str(REPO_ROOT))

from mcp_trust_monitor.senso import SensoClient, SensoError  # noqa: E402

SPEC_URL = "https://docs.senso.ai/specs/sdk-api.yaml"
SPEC_VERSION = "1.13.0"
SPEC_SHA256 = "fcb5a6cba8df9a9114217f3f15718d1bb3a95a2e7453205b8fc8bf7ac96b34b1"
DOCS_CHECKED_ON = "2026-10-12"
ENDPOINTS = {
    "create": "POST /org/kb/raw (orgKBCreateRawContent)",
    "node": "GET /org/kb/nodes/{id} (orgKBGetNode)",
    "content": "GET /org/kb/nodes/{id}/content[?version=n] (orgKBGetContent)",
    "edit": "PATCH /org/kb/nodes/{id}/raw (orgKBPatchRawContent)",
    "delete": "DELETE /org/kb/nodes/{id} (orgKBDeleteNode)",
    "search": "POST /org/search/context (orgSearchContext)",
}
TITLE_MARKER = "zephyr-title-marker"
QUERY = "synthetic capability probe marker"
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PLAN = """X1 Senso capability probe: planned steps (no request is sent by --plan)
 1. Upload one synthetic raw-text document, once, never retried.        {create}
 2. Wait until processing completes.                                     {node}
 3. Read back the text and version; compare exactly.                     {content}
 4. Scoped search for it; record chunk fields, version_id, title.        {search}
 5. Edit the text once (version 2), never retried; identity re-checked.  {edit}
 6. Wait until version 2 is processed.                                   {node}
 7. Read back version 2 and ?version=1; compare exactly.                 {content}
 8. Scoped search again; record whether version 1 chunks remain.         {search}
 9. Scoped search for an unknown content ID; it must not widen.          {search}
10. Delete the document (identity re-checked); confirm it is gone and a
    scoped search for its ID does not widen.                            {delete}
Edits and deletes are allowed only for the document created in step 1, never for a
configured policy content ID. Evidence holds field names, statuses, versions,
digests, booleans and this run's IDs only."""


class ProbeRefused(Exception):
    """A safety rule refused the operation before any request was sent."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _norm(text: str) -> str:
    return " ".join(text.split())


def _uuid(value: Any, what: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError):
        raise SensoError(f"{what} is not a UUID") from None


def _status(exc: BaseException) -> str:
    match = re.search(r"HTTP (\d{3})", str(exc))
    return match.group(1) if match else type(exc).__name__


def read_env_file(path: Path, keys: Sequence[str]) -> dict[str, str]:
    """Values for `keys` from this file only: no environment fallback, never written."""
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        if key.strip() in keys:
            values[key.strip()] = value.strip().strip("'\"")
    return values


def _scoped_rejection(exc: SensoError) -> bool:
    """A 4xx answer to a scoped search returned nothing, so it did not widen."""
    return _status(exc).startswith("4")


class RequestLog:
    """Wraps the HTTP opener to record method, path template, status and timing."""

    def __init__(self, opener: Callable[..., Any]) -> None:
        self._open = opener
        self.entries: list[dict[str, Any]] = []

    def __call__(self, request: urllib.request.Request, timeout: float) -> Any:
        path = UUID_RE.sub("{id}", request.full_url.split("/api/v1", 1)[-1])
        entry: dict[str, Any] = {"method": request.get_method(), "path": path}
        started = time.monotonic()
        try:
            response = self._open(request, timeout=timeout)
            entry["status"] = getattr(response, "status", None) or getattr(response, "code", 200)
            return response
        except urllib.error.HTTPError as exc:
            entry["status"] = exc.code
            raise
        except Exception as exc:
            entry["status"] = type(exc).__name__
            raise
        finally:
            entry["ms"] = round((time.monotonic() - started) * 1000)
            self.entries.append(entry)


class ProbeSession:
    """The only way the probe modifies Senso: just the document this run created."""

    def __init__(self, client: SensoClient, protected_content_ids: Sequence[str]) -> None:
        self.client = client
        self.protected = frozenset(protected_content_ids)
        self.created_node: str | None = None
        self.created_content: str | None = None

    def create(self, title: str, text: str) -> dict[str, Any]:
        if self.created_node is not None:
            raise ProbeRefused("this run has already created its document")
        response = self.client.upload_raw(text, title)  # one request; never retried
        content_id = _uuid(response.get("id"), "created content id")
        node_id = _uuid(response.get("kb_node_id"), "created kb_node_id")
        if content_id in self.protected:
            raise ProbeRefused("the created content ID equals a protected policy ID")
        self.created_node, self.created_content = node_id, content_id
        return response

    def _check_target(self, node_id: str) -> None:
        if self.created_node is None or node_id != self.created_node:
            raise ProbeRefused("refusing to modify a node this run did not create")
        node = self.client.node(node_id)
        content_id = node.get("content_id") or (node.get("content") or {}).get("id")
        if content_id != self.created_content or content_id in self.protected:
            raise ProbeRefused("node identity check failed before modification")

    def edit_text(self, node_id: str, text: str) -> dict[str, Any]:
        self._check_target(node_id)
        return self.client.request("PATCH", f"/org/kb/nodes/{node_id}/raw", {"text": text},
                                   retry=False)

    def delete(self, node_id: str) -> dict[str, Any]:
        self._check_target(node_id)
        return self.client.request("DELETE", f"/org/kb/nodes/{node_id}", retry=False)

    def search(self, query: str, content_ids: Sequence[str]) -> dict[str, Any]:
        ids = [_uuid(value, "search content id") for value in content_ids]
        if not ids:
            raise ProbeRefused("refusing an unscoped search")
        return self.client.search_context(query, ids, max_results=5)


def _fields(value: Any) -> list[str]:
    return sorted(value) if isinstance(value, dict) else []


def _wait_for_version(session: ProbeSession, node_id: str, version: int | None, *,
                      timeout: float, poll: float, sleep: Callable[[float], None],
                      clock: Callable[[], float]) -> dict[str, Any]:
    started, polls = clock(), 0
    while True:
        node = session.client.node(node_id)
        polls += 1
        content = node.get("content") or {}
        status, current = content.get("processing_status"), content.get("version_num")
        done = status == "complete" and (version is None or current == version)
        if done or status == "failed" or clock() - started >= timeout:
            return {"ok": done, "polls": polls, "seconds": round(clock() - started, 1),
                    "processing_status": status, "version_num": current,
                    "node_fields": _fields(node), "node_content_fields": _fields(content)}
        sleep(poll)


def _chunks_summary(response: dict[str, Any], requested: Sequence[str], node_id: str | None,
                    body: str, title: str) -> dict[str, Any]:
    results = response.get("results")
    chunks = results if isinstance(results, list) else []
    fields: set[str] = set()
    for chunk in chunks:
        if isinstance(chunk, dict):
            fields |= set(chunk)
    in_scope = all(isinstance(c, dict) and c.get("content_id") in requested
                   and (node_id is None or c.get("kb_node_id") == node_id) for c in chunks)
    return {
        "results": len(chunks), "chunk_fields": sorted(fields), "in_scope": in_scope,
        "version_ids": sorted({str(c.get("version_id")) for c in chunks
                               if isinstance(c, dict) and c.get("version_id")}),
        "every_chunk_has_version_id": bool(chunks) and all(
            isinstance(c, dict) and c.get("version_id") for c in chunks),
        "title_marker_in_chunk_text": any(
            TITLE_MARKER in str(c.get("chunk_text", "")) for c in chunks if isinstance(c, dict)),
        "chunk_title_field_equals_title": bool(chunks) and all(
            isinstance(c, dict) and c.get("title") == title for c in chunks),
        "passages_within_body": bool(chunks) and all(
            isinstance(c, dict) and _norm(str(c.get("chunk_text", ""))) in _norm(body)
            for c in chunks),
    }


def _search_until(session: ProbeSession, content_ids: Sequence[str], node_id: str | None,
                  body: str, title: str, *, done: Callable[[dict[str, Any]], bool],
                  attempts: int, interval: float,
                  sleep: Callable[[float], None]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for attempt in range(1, attempts + 1):
        summary = _chunks_summary(session.search(QUERY, content_ids), content_ids, node_id,
                                  body, title)
        summary["attempts"] = attempt
        if not summary["in_scope"] or done(summary):
            break
        if attempt < attempts:
            sleep(interval)
    summary["ok"] = summary.get("in_scope", False)
    return summary


def run_probe(session: ProbeSession, *, operation_id: str | None = None,
              processing_timeout: float = 180.0, poll_interval: float = 3.0,
              search_attempts: int = 12, search_interval: float = 5.0,
              sleep: Callable[[float], None] = time.sleep,
              clock: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    """Run every step, always attempting cleanup. Returns the evidence record."""
    op = operation_id or str(uuid.uuid4())
    title = f"mtm X1 capability probe {op[:8]} {TITLE_MARKER}"
    v1 = (f"X1 Senso capability probe {op}. Synthetic test document with no private or "
          "customer data. Marker: amber lattice.")
    v2 = (f"X1 Senso capability probe {op}. Synthetic test document with no private or "
          "customer data. Revised marker: cobalt harbor.")
    steps: dict[str, Any] = {}
    evidence: dict[str, Any] = {
        "origin": "synthetic_fixture", "probe": "x1-senso-capability", "operation_id": op,
        "started_at": _now(),
        "documentation": {"spec": SPEC_URL, "spec_version": SPEC_VERSION,
                          "spec_sha256": SPEC_SHA256, "checked_on": DOCS_CHECKED_ON,
                          "endpoints": ENDPOINTS},
        "protected_policy_ids": len(session.protected),
        "document": {"title_sha256": _sha(title), "v1_sha256": _sha(v1), "v2_sha256": _sha(v2)},
        "steps": steps, "created": None, "orphan": None, "possible_orphan": None,
    }
    waits = dict(timeout=processing_timeout, poll=poll_interval, sleep=sleep, clock=clock)

    def step(name: str, action: Callable[[], dict[str, Any]]) -> dict[str, Any] | None:
        try:
            result = action()
        except (SensoError, ProbeRefused) as exc:
            steps[name] = {"ok": False, "error": str(exc)[:300], "status": _status(exc),
                           "refused": isinstance(exc, ProbeRefused)}
            return None
        steps[name] = result
        return result if result.get("ok") else None

    v1_num: int | None = None
    v1_version_id: str | None = None
    v2_version_id: str | None = None

    def create() -> dict[str, Any]:
        nonlocal v1_num, v1_version_id
        response = session.create(title, v1)
        evidence["created"] = {"content_id": session.created_content,
                               "kb_node_id": session.created_node}
        v1_num = response.get("version_num")
        v1_version_id = response.get("latest_content_version_id")
        return {"ok": True, "response_fields": _fields(response), "version_num": v1_num,
                "processing_status": response.get("processing_status"),
                "has_latest_content_version_id": bool(v1_version_id)}

    try:
        if not step("1_upload", create):
            failure = steps.get("1_upload") or {}
            if not failure.get("refused") and not str(failure.get("status", "")).startswith("4"):
                # The request may have reached Senso; it is not retried. Find it by title.
                evidence["possible_orphan"] = {"title": title, "reason": failure.get("error")}
            return evidence
        node = session.created_node
        assert node is not None and session.created_content is not None
        content_id = session.created_content
        if not step("2_processed_v1",
                    lambda: _wait_for_version(session, node, v1_num, **waits)):
            return evidence
        if v1_num is None:  # the create response lacked it; use the processed node's
            v1_num = steps["2_processed_v1"].get("version_num")
            steps["1_upload"]["version_num_from_node"] = v1_num

        def read_v1() -> dict[str, Any]:
            got = session.client.node_content(node)
            text = got.get("text")
            exact = text == v1 and got.get("version_num") == v1_num
            return {"ok": exact, "response_fields": _fields(got),
                    "version_num": got.get("version_num"), "text_exact": text == v1,
                    "text_whitespace_equal": isinstance(text, str) and _norm(text) == _norm(v1),
                    "title_equal": got.get("title") == title}
        step("3_read_back_v1", read_v1)

        def search_v1() -> dict[str, Any]:
            found = _search_until(session, [content_id], node, v1, title,
                                  done=lambda s: s["results"] > 0, attempts=search_attempts,
                                  interval=search_interval, sleep=sleep)
            found["version_id_equals_created_version"] = (
                bool(v1_version_id) and found["version_ids"] == [str(v1_version_id)])
            return found
        step("4_scoped_search_v1", search_v1)

        def edit() -> dict[str, Any]:
            nonlocal v2_version_id
            response = session.edit_text(node, v2)
            v2_version_id = response.get("latest_content_version_id")
            return {"ok": True, "response_fields": _fields(response),
                    "version_num": response.get("version_num"),
                    "processing_status": response.get("processing_status"),
                    "has_latest_content_version_id": bool(v2_version_id)}
        expected_v2 = v1_num + 1 if isinstance(v1_num, int) else None
        if step("5_edit_to_v2", edit) and step(
                "6_processed_v2", lambda: _wait_for_version(session, node, expected_v2, **waits)):

            def read_versions() -> dict[str, Any]:
                if not isinstance(v1_num, int):
                    raise SensoError("version 1 number unknown; cannot read it back")
                latest = session.client.node_content(node)
                first = session.client.node_content(node, version=v1_num)
                result = {
                    "latest_version_num": latest.get("version_num"),
                    "latest_text_exact": latest.get("text") == v2,
                    "v1_version_num": first.get("version_num"),
                    "v1_text_exact": first.get("text") == v1,
                }
                result["ok"] = (result["latest_text_exact"] and result["v1_text_exact"]
                                and result["latest_version_num"] == expected_v2
                                and result["v1_version_num"] == v1_num)
                return result
            step("7_read_back_versions", read_versions)

            def search_v2() -> dict[str, Any]:
                found = _search_until(
                    session, [content_id], node, v2, title,
                    done=lambda s: s["results"] > 0 and s["passages_within_body"],
                    attempts=search_attempts, interval=search_interval, sleep=sleep)
                found["version_id_equals_v2_version"] = (
                    bool(v2_version_id) and found["version_ids"] == [str(v2_version_id)])
                found["v1_version_id_still_returned"] = (
                    bool(v1_version_id) and str(v1_version_id) in found["version_ids"])
                return found
            step("8_scoped_search_v2", search_v2)

        unknown = str(uuid.uuid4())
        while unknown in session.protected or unknown == content_id:
            unknown = str(uuid.uuid4())

        def search_unknown() -> dict[str, Any]:
            try:
                response = session.search(QUERY, [unknown])
            except SensoError as exc:
                if not _scoped_rejection(exc):
                    raise
                return {"ok": True, "results": 0, "in_scope": True,
                        "rejected_status": _status(exc)}
            summary = _chunks_summary(response, [unknown], None, "", title)
            return {"ok": summary["results"] == 0, "results": summary["results"],
                    "in_scope": summary["in_scope"]}
        step("9_scoped_search_unknown_id", search_unknown)
    finally:
        _cleanup(session, steps, evidence, waits)
    return evidence


def _cleanup(session: ProbeSession, steps: dict[str, Any], evidence: dict[str, Any],
             waits: dict[str, Any]) -> None:
    node, content_id = session.created_node, session.created_content
    if node is None or content_id is None:
        return
    record: dict[str, Any] = {"ok": False}
    steps["10_delete"] = record
    try:
        ready = _wait_for_version(session, node, None, **waits)
        record["processing_status_before_delete"] = ready["processing_status"]
        if not ready["ok"]:
            raise SensoError("document never finished processing; not deleted")
        session.delete(node)
        record["deleted"] = True
        try:
            session.client.node(node)
            record["gone_after_delete"] = False
        except SensoError as exc:
            record["gone_after_delete"] = _status(exc) == "404"
            record["status_after_delete"] = _status(exc)
        try:
            after = _chunks_summary(session.search(QUERY, [content_id]), [content_id], node,
                                    "", "")
        except SensoError as exc:
            if not _scoped_rejection(exc):
                raise
            after = {"results": 0, "in_scope": True}
            record["search_after_delete_rejected_status"] = _status(exc)
        record["search_after_delete_results"] = after["results"]
        record["search_after_delete_in_scope"] = after["in_scope"]
        record["ok"] = record["gone_after_delete"] and after["in_scope"]
    except (SensoError, ProbeRefused) as exc:
        record["error"] = str(exc)[:300]
        record["status"] = _status(exc)
    if not record.get("deleted"):
        evidence["orphan"] = {"content_id": content_id, "kb_node_id": node,
                              "reason": record.get("error", "not deleted")}


def gate(evidence: dict[str, Any]) -> dict[str, Any]:
    steps = evidence["steps"]
    ok = lambda name, key="ok": bool((steps.get(name) or {}).get(key))  # noqa: E731
    searches = [steps.get(name) for name in ("4_scoped_search_v1", "8_scoped_search_v2",
                                              "9_scoped_search_unknown_id")]
    deleted = steps.get("10_delete") or {}
    never_widened = all(s is None or s.get("in_scope", False) for s in searches) and (
        not deleted.get("deleted") or deleted.get("search_after_delete_in_scope", False))
    result = {
        "upload_read_back_exact": ok("3_read_back_v1"),
        "versioned_read_back_exact": ok("7_read_back_versions"),
        "scoped_search_never_widened": never_widened and ok("9_scoped_search_unknown_id"),
        # Informative: they shape later design, not the gate.
        "chunk_version_id_maps_to_created_version": ok("4_scoped_search_v1",
                                                       "version_id_equals_created_version"),
        "search_reflects_edit": ok("8_scoped_search_v2", "version_id_equals_v2_version"),
        "title_text_in_chunks": ok("4_scoped_search_v1", "title_marker_in_chunk_text"),
        "remote_delete_confirmed": bool(deleted.get("ok")),
    }
    result["met"] = (result["upload_read_back_exact"] and result["versioned_read_back_exact"]
                     and result["scoped_search_never_widened"])
    return result


def build_session(api_key: str, protected: Sequence[str], *,
                  opener: Callable[..., Any] = urllib.request.urlopen,
                  sleep: Callable[[float], None] = time.sleep) -> tuple[ProbeSession, RequestLog]:
    log = RequestLog(opener)
    return ProbeSession(SensoClient(api_key, opener=log, sleep=sleep), protected), log


def main(argv: Sequence[str] | None = None, *,
         opener: Callable[..., Any] = urllib.request.urlopen,
         sleep: Callable[[float], None] = time.sleep) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--plan", action="store_true", help="print the steps; no request")
    parser.add_argument("--env-file", type=Path, help="credentials file, read only")
    parser.add_argument("--confirm-live", action="store_true",
                        help="required for any request to Senso")
    parser.add_argument("--out", type=Path, help="evidence JSON path (default under runtime/)")
    args = parser.parse_args(argv)
    if args.plan:
        print(PLAN.format(**ENDPOINTS))
        return 0
    if not args.confirm_live or args.env_file is None:
        print("refused: a live probe needs --env-file and --confirm-live (or use --plan)")
        return 2
    if not args.env_file.is_file():
        print("refused: --env-file does not name a readable file")
        return 2
    settings = read_env_file(args.env_file, ["SENSO_API_KEY", "SENSO_POLICY_CONTENT_IDS"])
    if not settings.get("SENSO_API_KEY"):
        print("refused: SENSO_API_KEY is missing from --env-file")
        return 2
    protected = [item.strip() for item in settings.get("SENSO_POLICY_CONTENT_IDS", "").split(",")
                 if item.strip()]
    session, log = build_session(settings["SENSO_API_KEY"], protected, opener=opener, sleep=sleep)
    evidence = run_probe(session, sleep=sleep)
    evidence["requests"] = log.entries
    evidence["gate"] = gate(evidence)
    evidence["finished_at"] = _now()
    out = args.out or REPO_ROOT / "runtime" / (
        "senso-capability-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(evidence, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for name, value in evidence["gate"].items():
        print(f"{name}: {value}")
    if evidence["orphan"]:
        print(f"ORPHAN left in Senso, delete manually: kb_node_id {evidence['orphan']['kb_node_id']}")
    if evidence["possible_orphan"]:
        print("upload outcome unknown and not retried; check Senso for the title in the evidence")
    print(f"evidence written to {out}")
    return 0 if evidence["gate"]["met"] else 1


if __name__ == "__main__":
    sys.exit(main())
