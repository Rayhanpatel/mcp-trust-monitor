"""REQ-REV-01: revisions identify exact reviewed metadata."""

import pytest

from mcp_trust_monitor.revision import server_revision, tool_revision

TOOL = {
    "name": "lookup_document",
    "description": "Find a public document by its title and return its summary.",
    "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}},
                    "required": ["title"]},
}


def test_tool_revision_ignores_key_order():
    reordered = {"inputSchema": {"required": ["title"], "type": "object",
                                 "properties": {"title": {"type": "string"}}},
                 "description": TOOL["description"], "name": TOOL["name"]}
    assert tool_revision(reordered) == tool_revision(TOOL)


@pytest.mark.parametrize("change", [
    {"description": TOOL["description"] + " "},
    {"description": TOOL["description"].replace("public", "Public")},
    {"inputSchema": {**TOOL["inputSchema"], "additionalProperties": True}},
    {"name": "lookup_document_v2"},
])
def test_any_reviewed_field_change_changes_the_revision(change):
    assert tool_revision({**TOOL, **change}) != tool_revision(TOOL)


def test_server_revision_detects_additions_and_removals_but_not_order():
    other = {"name": "health_check", "description": "Health.", "inputSchema": {"type": "object"}}
    assert server_revision([TOOL, other]) == server_revision([other, TOOL])
    assert server_revision([TOOL, other]) != server_revision([TOOL])
    assert server_revision([]) != server_revision([TOOL])


def test_duplicate_tool_names_are_not_a_valid_observation():
    with pytest.raises(ValueError):
        server_revision([TOOL, {**TOOL, "description": "shadow"}])
