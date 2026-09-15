"""A minimal MCP stdio server used to test the client against a real process.

It exists because an in-process fake proves the client's logic but not its framing: line-delimited
JSON-RPC over a pipe is exactly the kind of thing that works in a fake and deadlocks in reality. This
server speaks just enough of the protocol -- ``initialize``, ``tools/list`` with pagination, and
``tools/call`` -- for the handshake and one call to be exercised end to end.

Run it directly: ``python tests/helpers/mcp_server.py``
"""

from __future__ import annotations

import json
import sys
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
TOOLS = [
    {
        "name": "service.enumerate",
        "description": "Report services the server believes are exposed.",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}},
    },
    {
        "name": "log.read",
        "description": "Read a bounded log file.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
    },
]

#: Page size is deliberately 1 so pagination is exercised by the default two-tool server.
PAGE_SIZE = 1


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    """Return the response for a request, or ``None`` for a notification."""
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        return None
    params = message.get("params") or {}

    if method == "initialize":
        return _ok(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fake-scanner", "version": "9.9.9"},
            },
        )
    if method == "tools/list":
        cursor = params.get("cursor")
        start = int(cursor) if cursor else 0
        page = TOOLS[start : start + PAGE_SIZE]
        result: dict[str, Any] = {"tools": page}
        if start + PAGE_SIZE < len(TOOLS):
            result["nextCursor"] = str(start + PAGE_SIZE)
        return _ok(request_id, result)
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name == "service.enumerate":
            return _ok(
                request_id,
                {
                    "content": [{"type": "text", "text": "1 service reported"}],
                    "isError": False,
                    "structuredContent": {
                        "observations": [
                            {
                                "kind": "service",
                                "value": {
                                    "target": arguments.get("target", "lab-web-01"),
                                    "port": 22,
                                    "protocol": "tcp",
                                    "state": "open",
                                    "service": "ssh",
                                    "product": "OpenSSH",
                                    "version": "8.2p1",
                                    "cpe": "cpe:/a:openbsd:openssh:8.2p1",
                                },
                            }
                        ]
                    },
                },
            )
        if name == "log.read":
            return _ok(request_id, {"content": [{"type": "text", "text": ""}], "isError": True})
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "unknown tool " + str(name)},
        }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "unknown method " + str(method)},
    }


def _ok(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    for line in sys.stdin:
        text = line.strip()
        if not text:
            continue
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        response = handle(message)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
