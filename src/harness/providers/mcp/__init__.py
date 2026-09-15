"""MCP as a provider boundary, not an orchestration layer.

Design D13 is explicit that MCP servers are interchangeable sources of capabilities behind the same
registry as native tools. This package implements the protocol side only: it never decides what to
run, and it never grants a server authority the run did not already hold.
"""

from __future__ import annotations

from harness.providers.mcp.client import McpStdioClient, McpTransport, StdioTransport
from harness.providers.mcp.provider import McpProvider

__all__ = ["McpProvider", "McpStdioClient", "McpTransport", "StdioTransport"]
