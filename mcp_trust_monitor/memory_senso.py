"""Private Senso backend for governed memory; requires recorded capability evidence.

Search UUID version identifiers are not numeric content versions. The memory service
pins numeric versions and verifies complete read-back bodies and returned passages.
This adapter does not infer version identity from a search result or publish content.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from .senso import BASE_URL, SensoClient
from .memory import (MemoryIntegrityError, NodeStatus, RemoteContent, SearchPassage,
                     UploadReceipt)


def _id(value: Any) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise MemoryIntegrityError("Senso returned an invalid identifier") from None


class SensoMemoryBackend:
    def __init__(self, client: SensoClient, *, capability_evidence: Path) -> None:
        raw = Path(capability_evidence).read_bytes()
        evidence = json.loads(raw)
        gate = evidence.get("gate", {})
        required = ("met", "upload_read_back_exact", "versioned_read_back_exact",
                    "scoped_search_never_widened")
        if evidence.get("probe") != "x1-senso-capability" or not all(
                gate.get(name) is True for name in required):
            raise MemoryIntegrityError("Senso capability evidence has not passed")
        if client.base_url != BASE_URL:
            raise MemoryIntegrityError("capability evidence covers the official Senso endpoint only")
        self.client = client
        self.capability_verified = True
        self.capability_evidence = "sha256:" + hashlib.sha256(raw).hexdigest()

    async def _request(self, name: str, *args):
        native = getattr(self.client, name + "_async", None)
        if native is not None:
            return await native(*args)
        return await asyncio.to_thread(getattr(self.client, name), *args)

    async def upload_raw(self, text: str, title: str) -> UploadReceipt:
        # SensoClient.upload_raw explicitly disables retries. A timeout remains ambiguous.
        response = await self._request("upload_raw", text, title)
        return UploadReceipt(content_id=_id(response.get("id")),
                             node_id=_id(response.get("kb_node_id")))

    async def node(self, node_id: str) -> NodeStatus:
        node_id = _id(node_id)
        response = await self._request("node", node_id)
        if _id(response.get("kb_node_id")) != node_id:
            raise MemoryIntegrityError("Senso node identity mismatch")
        # New uploads are private; refuse a remotely shared/public lesson.
        if response.get("is_public") is not False or response.get("is_public_root") is not False:
            raise MemoryIntegrityError("Senso lesson privacy cannot be verified")
        content = response.get("content", {})
        content_id = _id(response.get("content_id"))
        if _id(content.get("id")) != content_id:
            raise MemoryIntegrityError("Senso content identity mismatch")
        status = {"pending": "processing", "processing": "processing",
                  "complete": "completed", "failed": "failed"}.get(content.get("processing_status"))
        if status is None:
            raise MemoryIntegrityError("Senso processing status is unknown")
        return NodeStatus(node_id=node_id, content_id=content_id, status=status)

    async def node_content(self, node_id: str, *, version: str | None = None) -> RemoteContent:
        node_id = _id(node_id)
        number = None
        if version is not None:
            if not version.isdecimal() or int(version) < 1:
                raise MemoryIntegrityError("Senso content version must be a positive integer")
            number = int(version)
        node = await self.node(node_id)
        response = await self._request("node_content", node_id, number)
        value = response.get("version_num")
        if (type(value) is not int or value < 1 or not isinstance(response.get("text"), str)
                or _id(response.get("id")) != node.content_id
                or (number is not None and value != number)):
            raise MemoryIntegrityError("Senso content identity/body/version mismatch")
        return RemoteContent(node_id=node_id, content_id=node.content_id,
                             version=str(value), text=response["text"])

    async def search_context(self, query: str, *, content_ids: tuple[str, ...],
                             top_k: int) -> tuple[SearchPassage, ...]:
        ids = tuple(_id(value) for value in content_ids)
        if not ids or not 1 <= top_k <= 20:
            raise MemoryIntegrityError("memory search requires scoped IDs and top_k from 1 to 20")
        response = await self._request("search_context", query, ids, top_k)
        rows = response.get("results")
        if not isinstance(rows, list):
            raise MemoryIntegrityError("Senso search response lacks a results list")
        result = []
        for row in rows:
            if not isinstance(row, dict) or _id(row.get("content_id")) not in ids:
                raise MemoryIntegrityError("Senso returned a foreign memory source")
            text = row.get("chunk_text")
            if not isinstance(text, str) or not text.strip():
                raise MemoryIntegrityError("Senso returned an invalid memory passage")
            result.append(SearchPassage(content_id=_id(row["content_id"]), text=text,
                                        version=None, source_version_id=(
                                            _id(row["version_id"]) if row.get("version_id") else None)))
        return tuple(result)
