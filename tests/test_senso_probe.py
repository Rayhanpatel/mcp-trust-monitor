"""X1 Senso capability probe (scripts/senso_capability_probe.py), against a FAKE Senso.

The fake follows the request and response shapes of the documented API ("Senso Org
API" 1.13.0) so the probe's safety rules and gate logic can be tested without
credentials or network. Passing here says nothing about the real service; the live
probe is a separate, approved step. Synthetic values only.
"""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import sys
import urllib.error
import uuid

import pytest

from mcp_trust_monitor.senso import SensoClient, SensoError

from conftest import REPO_ROOT

_spec = importlib.util.spec_from_file_location(
    "senso_capability_probe", REPO_ROOT / "scripts" / "senso_capability_probe.py")
probe = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = probe
_spec.loader.exec_module(probe)

KEY = "synthetic-key-not-real-7f3a"
ORG = "00000000-0000-4000-8000-00000000a11c"
POLICY_ID = "11111111-1111-4111-8111-111111111111"


class Response:
    def __init__(self, payload, status=200):
        self.status = status
        self._body = b"" if payload is None else json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def http_error(url, code, text="error"):
    return urllib.error.HTTPError(url, code, "error", {}, io.BytesIO(text.encode("utf-8")))


class FakeSenso:
    """In-memory knowledge base and scoped context search, documented shapes only."""

    def __init__(self, polls_until_complete=1):
        self.docs: dict[str, dict] = {}
        self.requests: list[tuple[str, str, dict | None]] = []
        self.fail: dict[tuple[str, str], list[tuple[int, str]]] = {}
        self.polls_until_complete = polls_until_complete
        self.fixed_content_id: str | None = None
        self.node_reports_content_id: str | None = None
        self.alter_text = None
        self.no_history = False
        self.widen_with: str | None = None
        self.omit_version_id = False
        self.title_in_chunk = False
        self.never_complete = False
        self.search_lag = 0
        self.stale_after_edit = 0
        self.upload_lost = False
        self.reject_unknown_ids = False

    def count(self, method, template):
        return sum(1 for m, p, _ in self.requests
                   if m == method and probe.UUID_RE.sub("{id}", p.split("?")[0]) == template)

    def __call__(self, request, timeout):
        method, url = request.get_method(), request.full_url
        path = url.split("/api/v1", 1)[1]
        body = json.loads(request.data) if request.data else None
        self.requests.append((method, path, body))
        assert request.get_header("X-api-key") == KEY
        template = probe.UUID_RE.sub("{id}", path.split("?")[0])
        queue = self.fail.get((method, template))
        if queue:
            code, text = queue.pop(0)
            raise http_error(url, code, text)
        node_id = (probe.UUID_RE.findall(path) or [None])[0]
        if (method, template) == ("POST", "/org/kb/raw"):
            return self._create(body)
        if node_id not in self.docs:
            if template == "/org/search/context":
                return self._search(url, body)
            raise http_error(url, 404, "not found")
        doc = self.docs[node_id]
        if (method, template) == ("GET", "/org/kb/nodes/{id}"):
            doc["polls_left"] -= 1
            if doc["polls_left"] <= 0 and not self.never_complete:
                doc["status"] = "complete"
            return Response({
                "kb_node_id": node_id, "org_id": ORG, "parent_id": None, "type": "content",
                "name": doc["title"], "tags": [], "is_public": False, "is_public_root": False,
                "created_at": "t", "updated_at": "t",
                "content_id": self.node_reports_content_id or doc["content_id"],
                "content": {"id": doc["content_id"], "type": "raw", "version_num": doc["latest"],
                            "processing_status": doc["status"]}})
        if (method, template) == ("GET", "/org/kb/nodes/{id}/content"):
            number = doc["latest"]
            if "?version=" in path and not self.no_history:
                number = int(path.split("?version=")[1])
            text = doc["versions"][number]["text"]
            if self.alter_text:
                text = self.alter_text(text)
            return Response({"id": doc["content_id"], "org_id": ORG, "type": "raw",
                             "content_type": "text/markdown", "created_at": "t",
                             "updated_at": "t", "title": doc["title"], "version_num": number,
                             "processing_status": doc["status"], "text": text})
        if (method, template) == ("PATCH", "/org/kb/nodes/{id}/raw"):
            doc["latest"] += 1
            doc["versions"][doc["latest"]] = {"text": body["text"], "version_id": str(uuid.uuid4())}
            doc["status"], doc["polls_left"] = "pending", self.polls_until_complete
            doc["edited"] = True
            return Response(self._content_response(node_id, doc))
        if (method, template) == ("DELETE", "/org/kb/nodes/{id}"):
            if doc["status"] != "complete":
                raise http_error(url, 409, "still ingesting")
            del self.docs[node_id]
            return Response(None, status=204)
        if template == "/org/search/context":
            return self._search(url, body)
        raise AssertionError(f"undocumented call {method} {path}")

    def _content_response(self, node_id, doc):
        return {"id": doc["content_id"], "org_id": ORG, "type": "raw",
                "content_type": "text/markdown", "created_at": "t", "updated_at": "t",
                "title": doc["title"], "version_num": doc["latest"],
                "latest_content_version_id": doc["versions"][doc["latest"]]["version_id"],
                "processing_status": doc["status"], "kb_node_id": node_id}

    def _create(self, body):
        node_id = str(uuid.uuid4())
        doc = {"content_id": self.fixed_content_id or str(uuid.uuid4()), "title": body["title"],
               "latest": 1, "status": "pending", "polls_left": self.polls_until_complete,
               "versions": {1: {"text": body["text"], "version_id": str(uuid.uuid4())}}}
        self.docs[node_id] = doc
        if self.upload_lost:
            raise urllib.error.URLError(socket.timeout("timed out"))
        return Response(self._content_response(node_id, doc), status=202)

    def _search(self, url, body):
        ids = body.get("content_ids") or []
        if body.get("require_scoped_ids") is not True or not ids:
            raise http_error(url, 400, "content_ids required")
        matches = [(n, d) for n, d in self.docs.items()
                   if d["content_id"] in ids and d["status"] == "complete"]
        if not matches and self.reject_unknown_ids:
            raise http_error(url, 400, "unknown content id")
        results = []
        if matches and self.search_lag > 0:
            self.search_lag -= 1
            matches = []
        for node_id, doc in matches:
            number = doc["latest"]
            if doc.get("edited") and self.stale_after_edit > 0:
                self.stale_after_edit -= 1
                number -= 1
            text = doc["versions"][number]["text"]
            chunk = {"content_chunk_id": str(uuid.uuid4()), "content_id": doc["content_id"],
                     "kb_node_id": node_id, "chunk_index": 0,
                     "chunk_text": (doc["title"] + "\n" + text) if self.title_in_chunk else text,
                     "score": 0.9, "rank": 1, "title": doc["title"]}
            if not self.omit_version_id:
                chunk["version_id"] = doc["versions"][number]["version_id"]
            results.append(chunk)
        if self.widen_with:
            results.append({"content_chunk_id": str(uuid.uuid4()), "content_id": self.widen_with,
                            "kb_node_id": str(uuid.uuid4()), "version_id": str(uuid.uuid4()),
                            "chunk_index": 0, "chunk_text": "foreign", "score": 0.5,
                            "rank": len(results) + 1})
        return Response({"query": body["query"], "search_type": "hybrid", "results": results,
                         "total_results": len(results), "max_results": 5})


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        self.t += 1.0
        return self.t


def session_for(fake, protected=(POLICY_ID,)):
    session, log = probe.build_session(KEY, protected, opener=fake, sleep=lambda _: None)
    return session, log


def run(fake, protected=(POLICY_ID,), **kwargs):
    session, log = session_for(fake, protected)
    options = dict(poll_interval=0, search_attempts=4, search_interval=0, sleep=lambda _: None,
                   clock=Clock(), processing_timeout=10)
    options.update(kwargs)
    evidence = probe.run_probe(session, **options)
    evidence["requests"] = log.entries
    evidence["gate"] = probe.gate(evidence)
    return evidence


def env_file(tmp_path, text=f"SENSO_API_KEY={KEY}\nSENSO_POLICY_CONTENT_IDS={POLICY_ID}\n"):
    path = tmp_path / "credentials.env"
    path.write_text(text, encoding="utf-8")
    return path


def mutation_targets(fake):
    return [p for m, p, _ in fake.requests if m in ("PATCH", "DELETE")]


# CLI refusals: nothing is sent without both flags; --plan never reads credentials.

def test_plan_sends_nothing_and_reads_no_credentials(tmp_path, capsys):
    def never(*_a, **_k):
        raise AssertionError("no request expected")
    assert probe.main(["--plan", "--env-file", str(tmp_path / "absent.env")], opener=never) == 0
    assert "never retried" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [[], ["--confirm-live"], ["--env-file", "{env}"],
                                  ["--confirm-live", "--env-file", "{missing}"]])
def test_live_run_requires_an_env_file_and_confirmation(tmp_path, argv):
    def never(*_a, **_k):
        raise AssertionError("no request expected")
    values = {"env": str(env_file(tmp_path)), "missing": str(tmp_path / "missing.env")}
    assert probe.main([a.format(**values) for a in argv], opener=never) == 2


def test_credentials_come_from_the_named_file_only(tmp_path, monkeypatch):
    monkeypatch.setenv("SENSO_API_KEY", "environment-key-must-not-be-used")
    path = env_file(tmp_path)
    before = path.read_bytes()
    fake = FakeSenso()  # asserts every request carries the file's key
    assert probe.main(["--confirm-live", "--env-file", str(path), "--out",
                       str(tmp_path / "out.json")], opener=fake, sleep=lambda _: None) == 0
    assert path.read_bytes() == before  # never written
    keyless = env_file(tmp_path, "SENSO_POLICY_CONTENT_IDS=x\n")
    assert probe.main(["--confirm-live", "--env-file", str(keyless)], opener=fake) == 2


def test_probe_never_imports_credential_writers_or_the_environment_loader():
    source = (REPO_ROOT / "scripts" / "senso_capability_probe.py").read_text(encoding="utf-8")
    for name in ("save_env_value", "upload_policy", "load_env", "os.environ"):
        assert name not in source
    assert not hasattr(probe, "save_env_value") and not hasattr(probe, "upload_policy")


# The full run against a well-behaved fake.

def test_well_behaved_service_meets_the_gate_and_evidence_holds_no_secrets(tmp_path):
    fake = FakeSenso()
    out = tmp_path / "evidence.json"
    code = probe.main(["--confirm-live", "--env-file", str(env_file(tmp_path)), "--out", str(out)],
                      opener=fake, sleep=lambda _: None)
    text = out.read_text(encoding="utf-8")
    evidence = json.loads(text)
    assert code == 0 and evidence["gate"]["met"] is True
    informative = {"title_text_in_chunks"}  # this fake keeps titles out of chunk text
    assert all(v for k, v in evidence["gate"].items() if k not in informative)
    assert evidence["gate"]["title_text_in_chunks"] is False
    assert KEY not in text and ORG not in text  # field names only, never key or org values
    assert fake.count("POST", "/org/kb/raw") == 1
    assert fake.count("PATCH", "/org/kb/nodes/{id}/raw") == 1
    assert fake.count("DELETE", "/org/kb/nodes/{id}") == 1
    assert fake.docs == {} and evidence["orphan"] is None
    created = evidence["created"]["kb_node_id"]
    assert all(created in path for path in mutation_targets(fake))
    searches = [body for m, p, body in fake.requests if p == "/org/search/context"]
    assert searches and all(b["require_scoped_ids"] is True and b["content_ids"] for b in searches)
    assert POLICY_ID not in json.dumps(searches)
    assert evidence["documentation"]["spec_version"] == "1.13.0"
    assert len(evidence["documentation"]["spec_sha256"]) == 64
    assert len(evidence["documentation"]["endpoints"]) == 6
    assert "org_id" in evidence["steps"]["3_read_back_v1"]["response_fields"]
    assert {e["method"] for e in evidence["requests"]} == {"POST", "GET", "PATCH", "DELETE"}


# Uploads and edits are sent once and never retried.

def test_upload_server_error_is_sent_once_and_recorded_as_a_possible_orphan():
    fake = FakeSenso()
    fake.fail[("POST", "/org/kb/raw")] = [(503, "busy")] * 3
    evidence = run(fake)
    assert fake.count("POST", "/org/kb/raw") == 1
    assert mutation_targets(fake) == [] and evidence["created"] is None
    assert evidence["possible_orphan"]["title"].startswith("mtm X1 capability probe")
    assert evidence["gate"]["met"] is False


def test_lost_upload_response_is_recorded_not_repeated():
    fake = FakeSenso()
    fake.upload_lost = True  # Senso created the document, but the response never arrived
    evidence = run(fake)
    assert fake.count("POST", "/org/kb/raw") == 1 and len(fake.docs) == 1
    assert mutation_targets(fake) == []  # the unknown document is never touched
    assert evidence["possible_orphan"] is not None and evidence["gate"]["met"] is False


def test_rejected_upload_is_not_a_possible_orphan():
    fake = FakeSenso()
    fake.fail[("POST", "/org/kb/raw")] = [(400, "bad request")]
    evidence = run(fake)
    assert fake.count("POST", "/org/kb/raw") == 1 and evidence["possible_orphan"] is None


def test_edit_server_error_is_sent_once_and_cleanup_still_deletes_the_document():
    fake = FakeSenso()
    fake.fail[("PATCH", "/org/kb/nodes/{id}/raw")] = [(503, "busy")] * 3
    evidence = run(fake)
    assert fake.count("PATCH", "/org/kb/nodes/{id}/raw") == 1
    assert fake.count("DELETE", "/org/kb/nodes/{id}") == 1 and fake.docs == {}
    assert evidence["gate"]["versioned_read_back_exact"] is False
    assert evidence["gate"]["met"] is False


# Allowlist and policy protection: refusals happen before any request.

def test_modifications_outside_the_allowlist_are_refused_before_any_request():
    fake = FakeSenso()
    session, _ = session_for(fake)
    other = str(uuid.uuid4())
    with pytest.raises(probe.ProbeRefused):
        session.edit_text(other, "x")  # nothing created yet
    with pytest.raises(probe.ProbeRefused):
        session.delete(other)
    assert fake.requests == []
    session.create("t", "x")
    with pytest.raises(probe.ProbeRefused):
        session.delete(other)
    with pytest.raises(probe.ProbeRefused):
        session.create("t", "again")  # one document per run
    assert fake.count("POST", "/org/kb/raw") == 1 and mutation_targets(fake) == []


def test_a_created_id_equal_to_a_policy_id_is_refused_and_never_modified():
    fake = FakeSenso()
    fake.fixed_content_id = POLICY_ID
    evidence = run(fake)
    assert evidence["steps"]["1_upload"]["refused"] is True
    assert mutation_targets(fake) == [] and evidence["gate"]["met"] is False


def test_identity_is_rechecked_before_each_modification():
    fake = FakeSenso()
    session, _ = session_for(fake)
    created = session.create("t", "x")
    fake.node_reports_content_id = POLICY_ID  # the node now claims to back a policy document
    with pytest.raises(probe.ProbeRefused):
        session.edit_text(created["kb_node_id"], "y")
    with pytest.raises(probe.ProbeRefused):
        session.delete(created["kb_node_id"])
    assert mutation_targets(fake) == []


def test_unscoped_searches_are_refused_before_any_request():
    fake = FakeSenso()
    session, _ = session_for(fake)
    with pytest.raises(probe.ProbeRefused):
        session.search(probe.QUERY, [])
    with pytest.raises(SensoError):
        SensoClient(KEY, opener=fake).search_context(probe.QUERY, [])
    assert fake.requests == []


# Gate logic.

def test_a_widened_search_fails_the_gate_and_the_foreign_id_is_never_modified():
    fake = FakeSenso()
    fake.widen_with = POLICY_ID
    evidence = run(fake)
    assert evidence["gate"]["scoped_search_never_widened"] is False
    assert evidence["gate"]["met"] is False
    assert all(POLICY_ID not in path for path in mutation_targets(fake))


def test_a_4xx_rejection_of_an_unknown_or_deleted_id_is_not_widening():
    fake = FakeSenso()
    fake.reject_unknown_ids = True
    evidence = run(fake)
    assert evidence["steps"]["9_scoped_search_unknown_id"]["rejected_status"] == "400"
    assert evidence["steps"]["10_delete"]["search_after_delete_rejected_status"] == "400"
    assert evidence["gate"]["met"] is True


def test_read_back_must_be_exact_not_merely_whitespace_equal():
    fake = FakeSenso()
    fake.alter_text = lambda text: text.replace(". ", ".  ")
    evidence = run(fake)
    step = evidence["steps"]["3_read_back_v1"]
    assert step["text_exact"] is False and step["text_whitespace_equal"] is True
    assert evidence["gate"]["upload_read_back_exact"] is False and evidence["gate"]["met"] is False


def test_versioned_read_back_needs_the_earlier_version():
    fake = FakeSenso()
    fake.no_history = True  # ?version=1 silently returns the latest text
    evidence = run(fake)
    assert evidence["steps"]["7_read_back_versions"]["v1_text_exact"] is False
    assert evidence["gate"]["versioned_read_back_exact"] is False and evidence["gate"]["met"] is False


def test_search_lag_and_stale_chunks_are_retried_within_bounds_and_recorded():
    fake = FakeSenso()
    fake.search_lag, fake.stale_after_edit = 2, 1
    evidence = run(fake, search_attempts=4)
    assert evidence["steps"]["4_scoped_search_v1"]["attempts"] == 3
    assert evidence["steps"]["8_scoped_search_v2"]["attempts"] == 2
    assert evidence["gate"]["met"] is True and evidence["gate"]["search_reflects_edit"] is True


def test_informative_findings_do_not_decide_the_gate():
    fake = FakeSenso()
    fake.omit_version_id, fake.title_in_chunk = True, True
    evidence = run(fake)
    assert evidence["gate"]["chunk_version_id_maps_to_created_version"] is False
    assert evidence["gate"]["title_text_in_chunks"] is True
    assert evidence["steps"]["4_scoped_search_v1"]["passages_within_body"] is False
    assert evidence["gate"]["met"] is True  # exact read-back carries the gate


def test_unfinished_processing_leaves_a_recorded_orphan_and_no_delete():
    fake = FakeSenso()
    fake.never_complete = True
    evidence = run(fake, processing_timeout=5)
    assert evidence["steps"]["2_processed_v1"]["ok"] is False
    assert fake.count("DELETE", "/org/kb/nodes/{id}") == 0
    assert evidence["orphan"]["kb_node_id"] == evidence["created"]["kb_node_id"]
    assert evidence["gate"]["met"] is False


def test_errors_in_evidence_are_redacted():
    fake = FakeSenso()
    fake.fail[("PATCH", "/org/kb/nodes/{id}/raw")] = [(400, f"bad key {KEY}")]
    evidence = run(fake)
    error = evidence["steps"]["5_edit_to_v2"]["error"]
    assert KEY not in json.dumps(evidence) and "<redacted>" in error


def test_node_content_reads_a_specific_version():
    fake = FakeSenso()
    session, _ = session_for(fake)
    created = session.create("t", "first")
    node_id = created["kb_node_id"]
    session.client.node(node_id)  # completes processing in the fake
    session.edit_text(node_id, "second")
    assert session.client.node_content(node_id)["text"] == "second"
    assert session.client.node_content(node_id, version=1)["text"] == "first"
    assert fake.requests[-1][1].endswith("/content?version=1")
