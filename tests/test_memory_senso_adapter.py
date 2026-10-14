import json
from uuid import uuid4

import pytest

from mcp_trust_monitor.memory import MemoryIntegrityError
from mcp_trust_monitor.memory_senso import SensoMemoryBackend
from mcp_trust_monitor.senso import BASE_URL

pytestmark = pytest.mark.anyio
CONTENT, NODE = str(uuid4()), str(uuid4())


class FakeSenso:
    base_url = BASE_URL
    uploads = 0
    public = False
    results = None
    def upload_raw(self, text, title):
        self.uploads += 1
        raise TimeoutError("unknown upload")
    def node(self, node):
        return {"kb_node_id": NODE, "content_id": CONTENT, "is_public": self.public,
                "is_public_root": False, "content": {"id": CONTENT, "processing_status": "complete"}}
    def node_content(self, node, version=None):
        return {"id": CONTENT, "version_num": version or 1, "text": "approved text"}
    def search_context(self, query, ids, top_k):
        return self.results if self.results is not None else {
            "results": [{"content_id": CONTENT, "chunk_text": "approved text"}]}


def backend(tmp_path, client=None):
    path = tmp_path / "capability.json"
    path.write_text(json.dumps({"probe": "x1-senso-capability", "gate": {
        "met": True, "upload_read_back_exact": True, "versioned_read_back_exact": True,
        "scoped_search_never_widened": True}}))
    return SensoMemoryBackend(client or FakeSenso(), capability_evidence=path)


async def test_unknown_upload_never_retried(tmp_path):
    client = FakeSenso()
    with pytest.raises(TimeoutError):
        await backend(tmp_path, client).upload_raw("approved text", "title")
    assert client.uploads == 1


async def test_body_pin_scope_and_private_boundary(tmp_path):
    client = FakeSenso()
    adapter = backend(tmp_path, client)
    content = await adapter.node_content(NODE, version="1")
    assert content.version == "1" and content.text == "approved text"
    assert len(await adapter.search_context("query", content_ids=(CONTENT,), top_k=3)) == 1
    client.results = {"results": [{"content_id": str(uuid4()), "chunk_text": "foreign"}]}
    with pytest.raises(MemoryIntegrityError):
        await adapter.search_context("query", content_ids=(CONTENT,), top_k=3)
    client.results = {}
    with pytest.raises(MemoryIntegrityError):
        await adapter.search_context("query", content_ids=(CONTENT,), top_k=3)
    client.public = True
    with pytest.raises(MemoryIntegrityError):
        await adapter.node_content(NODE)


async def test_capability_failure_refused(tmp_path):
    path = tmp_path / "failed.json"
    path.write_text('{"gate":{"met":false}}')
    with pytest.raises(MemoryIntegrityError):
        SensoMemoryBackend(FakeSenso(), capability_evidence=path)
