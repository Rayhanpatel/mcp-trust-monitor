"""Scoped operator-policy retrieval from Senso (REQ-SRC-01). Standard library only.

Uses the documented REST API (`https://apiv2.senso.ai/api/v1`, header `X-API-Key`):
`POST /org/kb/raw` uploads the policy text, `GET /org/kb/nodes/{id}` reports
processing status, and `POST /org/search/context` returns passages. Every search
sends explicit `content_ids` with `require_scoped_ids: true`, so Senso refuses
rather than widening to the whole organization, and gap signals are off. A result
from any other content ID, an empty result, or text that does not match the
operator's policy file is a retrieval failure: there is no organization-wide
fallback. Timeouts and retries are bounded, and the API key is never printed.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .revision import digest

BASE_URL = "https://apiv2.senso.ai/api/v1"
POLICY_QUERY = ("operator security policy rules POL-001 POL-002 requirement hard_deny_condition "
                "decision_authority benign_changes private workspace content")
REDACTED = "<redacted>"
USER_AGENT = "mcp-trust-monitor/0.1 (python)"


class SensoError(Exception):
    """A Senso request or a retrieval check failed. Never a clean result."""


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, REDACTED) if secret else text


class SensoClient:
    def __init__(self, api_key: str, *, base_url: str = BASE_URL, timeout_seconds: float = 20.0,
                 attempts: int = 3, backoff_seconds: float = 1.0,
                 opener: Callable[..., Any] = urllib.request.urlopen,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if not api_key:
            raise SensoError("SENSO_API_KEY is not set")
        self._key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds
        self.attempts = attempts
        self.backoff = backoff_seconds
        self._open = opener
        self._sleep = sleep

    def request(self, method: str, path: str, body: Mapping[str, Any] | None = None,
                *, retry: bool = True) -> dict[str, Any]:
        # Senso's edge rejects urllib's default user agent (Cloudflare 1010), so name ours.
        headers = {"X-API-Key": self._key, "Accept": "application/json",
                   "X-Senso-Signals": "off", "User-Agent": USER_AGENT}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        last = "no attempt made"
        for attempt in range(self.attempts if retry else 1):
            request = urllib.request.Request(self.base_url + path, data=data, headers=headers,
                                             method=method)
            try:
                with self._open(request, timeout=self.timeout) as response:
                    payload = response.read().decode("utf-8")
                return json.loads(payload) if payload.strip() else {}
            except urllib.error.HTTPError as exc:
                text = _redact(exc.read().decode("utf-8", "replace"), self._key)
                last = f"HTTP {exc.code} on {method} {path}: {text.strip()[:300]}"
                if exc.code not in (429, 500, 502, 503, 504):
                    raise SensoError(last) from None
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last = _redact(f"{type(exc).__name__} on {method} {path}: {exc}", self._key)[:300]
            if attempt + 1 < (self.attempts if retry else 1):
                self._sleep(self.backoff * 2 ** attempt)
        raise SensoError(last)

    def whoami(self) -> dict[str, Any]:
        return self.request("GET", "/org/me")

    def upload_raw(self, text: str, title: str) -> dict[str, Any]:
        # Not retried: a retry after an ambiguous failure could create a second document.
        return self.request("POST", "/org/kb/raw", {"text": text, "title": title}, retry=False)

    def node(self, kb_node_id: str) -> dict[str, Any]:
        return self.request("GET", f"/org/kb/nodes/{kb_node_id}")

    def search_context(self, query: str, content_ids: Sequence[str],
                       max_results: int = 20) -> dict[str, Any]:
        if not content_ids:
            raise SensoError("refusing an unscoped search: no policy content IDs configured")
        return self.request("POST", "/org/search/context", {
            "query": query, "content_ids": list(content_ids), "require_scoped_ids": True,
            "max_results": max_results})


def wait_until_processed(client: SensoClient, kb_node_id: str, *, timeout_seconds: float = 180.0,
                         poll_seconds: float = 3.0,
                         sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        node = client.node(kb_node_id)
        status = (node.get("content") or {}).get("processing_status")
        if status == "complete":
            return node
        if status == "failed":
            raise SensoError(f"Senso failed to process node {kb_node_id}")
        if time.monotonic() >= deadline:
            raise SensoError(f"node {kb_node_id} still {status!r} after {timeout_seconds:g}s")
        sleep(poll_seconds)


@dataclass(frozen=True)
class RetrievedPolicy:
    """Policy passages retrieved from Senso, verified against the operator's policy file."""

    policy_id: str
    revision: str
    policy_digest: str  # digest of the parsed policy document the passages were verified against
    content_ids: tuple[str, ...]
    passages: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"policy_id": self.policy_id, "revision": self.revision,
                "policy_digest": self.policy_digest, "content_ids": list(self.content_ids),
                "passages": len(self.passages)}


def _normalize(text: str) -> str:
    return " ".join(text.split())


def retrieve_policy(client: SensoClient, content_ids: Sequence[str], policy_path: Path,
                    *, query: str = POLICY_QUERY) -> RetrievedPolicy:
    """Scoped retrieval, then verification that the passages are the intended policy.

    Every passage must come from a configured content ID and appear verbatim
    (whitespace-normalized) in the local policy file; every configured content ID
    must contribute at least one such passage; and together the passages must
    contain every rule ID and requirement. Anything else raises SensoError, so the
    returned `content_ids` are exactly the IDs that supplied validated text.
    """
    ids = tuple(dict.fromkeys(content_ids))
    report = client.search_context(query, ids)
    results = report.get("results")
    if not isinstance(results, list) or not results:
        raise SensoError("scoped Senso search returned no passages")
    policy_text = Path(policy_path).read_text(encoding="utf-8")
    document = json.loads(policy_text)
    normalized_policy = _normalize(policy_text)
    passages: list[tuple[int, str]] = []
    for result in results:
        if result.get("content_id") not in ids:
            raise SensoError("Senso returned a passage outside the configured policy content IDs")
        text = result.get("chunk_text")
        if not isinstance(text, str) or not text.strip():
            raise SensoError("Senso returned an empty or malformed passage")
        if _normalize(text) not in normalized_policy:
            raise SensoError("a retrieved passage does not match the operator policy file")
        passages.append((int(result.get("chunk_index") or 0), text))
    # Every reported content ID must have contributed a validated passage; otherwise a
    # model could cite an ID that returned nothing (REQ-DEC-03). No wider search.
    contributing = {result["content_id"] for result in results}
    silent = [content_id for content_id in ids if content_id not in contributing]
    if silent:
        raise SensoError(f"configured content IDs returned no validated passage: {silent}")
    joined = _normalize(" ".join(text for _, text in passages))
    for rule in document["rules"]:
        if rule["id"] not in joined or _normalize(rule["requirement"]) not in joined:
            raise SensoError(f"retrieved passages do not include policy rule {rule['id']}")
    ordered = tuple(text for _, text in sorted(dict.fromkeys(passages)))
    return RetrievedPolicy(policy_id=document["policy_id"], revision=str(document["revision"]),
                           policy_digest=digest(document), content_ids=ids, passages=ordered)


def upload_policy(client: SensoClient, policy_path: Path, env_file: Path, *,
                  force: bool = False) -> dict[str, Any]:
    """Upload only the operator policy file and record its content ID in `.env`.

    Skips the upload when `SENSO_POLICY_CONTENT_IDS` is already configured, unless
    `force`. The uploaded text is the policy file exactly as stored.
    """
    existing = load_env(["SENSO_POLICY_CONTENT_IDS"], env_file).get("SENSO_POLICY_CONTENT_IDS")
    if existing and not force:
        return {"uploaded": False, "content_ids": existing.split(",")}
    text = Path(policy_path).read_text(encoding="utf-8")
    document = json.loads(text)
    title = f"{document['policy_id']} revision {document['revision']} (policies/demo-policy.json)"
    created = client.upload_raw(text, title)
    content_id, node_id = created.get("id"), created.get("kb_node_id")
    if not content_id or not node_id:
        raise SensoError("Senso upload response lacked a content ID or node ID")
    node = wait_until_processed(client, node_id)
    if node.get("content_id") not in (None, content_id):
        raise SensoError("Senso node reports a different content ID than the upload")
    save_env_value(env_file, "SENSO_POLICY_CONTENT_IDS", content_id)
    return {"uploaded": True, "content_ids": [content_id], "kb_node_id": node_id,
            "policy_digest": digest(document)}


def load_env(keys: Sequence[str], env_file: Path) -> dict[str, str]:
    """Values for `keys` from the environment, falling back to `.env`. Never printed."""
    values: dict[str, str] = {}
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.removeprefix("export ").split("=", 1)
            if key.strip() in keys:
                values[key.strip()] = value.strip().strip("'\"")
    for key in keys:
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values


def save_env_value(env_file: Path, key: str, value: str) -> None:
    """Set one key in `.env`, keeping every other line and the file's permissions.

    Writes through a symlink to its target, atomically.
    """
    target = Path(env_file).resolve()
    lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
    replaced, out = False, []
    for line in lines:
        stripped = line.strip().removeprefix("export ")
        if stripped.split("=", 1)[0].strip() == key and "=" in stripped:
            if not replaced:
                out.append(f"{key}={value}")
                replaced = True
            continue
        out.append(line)
    if not replaced:
        out.append(f"{key}={value}")
    mode = target.stat().st_mode & 0o777 if target.exists() else 0o600
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text("\n".join(out) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, target)
