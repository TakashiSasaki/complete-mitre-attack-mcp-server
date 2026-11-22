"""Verify MCP ToolAnnotations on all registered MITRE ATT&CK MCP tools."""

import asyncio

from mcp.types import ToolAnnotations

from mitre_mcp_server.server import mcp

EXPECTED_TOOL_COUNT = 67


def test_all_tools_have_read_only_local_annotations():
    """All 67 registered tools must declare explicit local read-only ToolAnnotations."""
    tools = asyncio.run(mcp.list_tools())
    assert len(tools) == EXPECTED_TOOL_COUNT, (
        f"Expected {EXPECTED_TOOL_COUNT} registered tools, got {len(tools)}"
    )

    missing_annotations = [t.name for t in tools if t.annotations is None]
    assert not missing_annotations, f"Tools missing annotations: {missing_annotations}"

    mismatches = []
    for tool in tools:
        ann = tool.annotations
        if not isinstance(ann, ToolAnnotations):
            mismatches.append((tool.name, f"unexpected type {type(ann).__name__}"))
            continue
        if (
            ann.readOnlyHint is not True
            or ann.destructiveHint is not False
            or ann.idempotentHint is not True
            or ann.openWorldHint is not False
        ):
            mismatches.append((tool.name, ann.model_dump()))

    assert not mismatches, f"Tools with unexpected annotations: {mismatches}"
