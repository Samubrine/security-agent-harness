"""AEGIS asset inventory: a small MCP server (stdio, JSON-RPC 2.0) that the harness can plug in.

What it represents: the record an operations team keeps of what *should* be installed on each lab
machine (a CMDB / asset inventory). That is an independent second source next to the network scan:
when the scan and the inventory agree about a service version, the finding rests on two sources;
when they disagree, the harness records a conflict instead of silently picking one.

Why it is an MCP server and not a Python module: it proves the extension path the project was
designed around. The harness does not import this file. It starts it as a separate process,
asks it which tools it has (`tools/list`), maps one of them to a capability in
`config/mcp_servers.json`, and treats everything it returns as untrusted (T3) data.

Standard library only. Run it by hand to see the protocol:

    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | python mcp_servers/asset_inventory.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "aegis-asset-inventory", "version": "1.0.0"}
DATA_FILE = Path(__file__).with_name("asset_inventory.json")

TOOLS = [
    {
        "name": "inventory_services",
        "description": (
            "List the services the asset inventory records as installed on a lab machine, with "
            "product and version. Read-only; does not contact the machine."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Scope alias, e.g. lab-web-01."},
                "profile": {
                    "type": "string",
                    "description": "Accepted so the tool can stand in for a scan request; an inventory has no scan profiles, so it is ignored.",
                },
            },
            "required": ["target"],
        },
    }
]


def load_inventory() -> dict[str, Any]:
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def inventory_services(arguments: dict[str, Any]) -> dict[str, Any]:
    target = str(arguments.get("target") or "")
    host = load_inventory().get("hosts", {}).get(target)
    if not isinstance(host, dict):
        return {
            "content": [{"type": "text", "text": f"no inventory record for {target!r}"}],
            "isError": False,
            "structuredContent": {
                "observations": [],
                "gaps": [{"kind": "partial_coverage", "impact": f"the asset inventory has no record for {target}"}],
            },
        }
    observations = []
    for svc in host.get("services", []):
        if not isinstance(svc, dict):
            continue
        value = {
            "target": target,
            "port": svc.get("port"),
            "protocol": svc.get("protocol", "tcp"),
            "state": "open",
            "service": svc.get("service"),
            "product": svc.get("product"),
            "version": svc.get("version"),
        }
        if svc.get("cpe"):
            value["cpe"] = svc["cpe"]
        observations.append({"kind": "service", "value": {k: v for k, v in value.items() if v is not None}})
    summary = f"{len(observations)} service(s) recorded for {target} (inventory updated {host.get('updated', 'unknown')})"
    return {
        "content": [{"type": "text", "text": summary}],
        "isError": False,
        "structuredContent": {"observations": observations},
    }


def handle(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:  # a notification, e.g. notifications/initialized
        return None
    params = message.get("params") or {}
    if method == "initialize":
        return _ok(request_id, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO})
    if method == "tools/list":
        return _ok(request_id, {"tools": TOOLS})
    if method == "tools/call":
        if params.get("name") == "inventory_services":
            return _ok(request_id, inventory_services(params.get("arguments") or {}))
        return _error(request_id, -32602, "unknown tool " + str(params.get("name")))
    if method == "ping":
        return _ok(request_id, {})
    return _error(request_id, -32601, "unknown method " + str(method))


def _ok(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main() -> int:
    for line in sys.stdin:
        text = line.strip()
        if not text:
            continue
        try:
            message = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(message, dict):
            response = handle(message)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
