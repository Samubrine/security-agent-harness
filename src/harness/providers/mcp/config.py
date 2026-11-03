"""Load MCP servers from a JSON file and turn them into ordinary providers.

This is the "import an MCP server" step of the design: a server is described by data (how to start
it, which of its tools serves which capability, how risky calling it is), not by code. The harness
starts each server as a subprocess, performs the MCP handshake, and refuses a server whose tools do
not include the ones the file maps.

    {"servers": [{"id": "mcp:asset-inventory",
                  "command": ["python", "mcp_servers/asset_inventory.py"],
                  "capabilities": {"service.enumerate": "inventory_services"},
                  "risk": "MEDIUM", "trust_class": "local_mcp"}]}

``python``/``python3`` as the first word is replaced by the interpreter running the harness, and a
relative script path is resolved against the repository root, so the same file works on Windows
and Linux and inside a virtual environment.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from harness.errors import ConfigError
from harness.providers.mcp.client import McpStdioClient, StdioTransport
from harness.providers.mcp.provider import McpProvider

RISKS = {"LOW", "MEDIUM", "HIGH"}
TRUST_CLASSES = {"local_mcp", "external_provider"}


def load_mcp_providers(path: Path, *, root: Path) -> list[McpProvider]:
    """Start every server listed in ``path``. On any failure, servers already started are closed."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"MCP config {path} could not be read: {exc}") from exc
    servers = data.get("servers") if isinstance(data, dict) else None
    if not isinstance(servers, list):
        raise ConfigError(f"MCP config {path} must be an object with a 'servers' list")

    providers: list[McpProvider] = []
    try:
        for index, entry in enumerate(servers):
            providers.append(_provider(entry, index=index, root=Path(root)))
    except Exception:
        close_all(providers)
        raise
    return providers


def close_all(providers: list[Any]) -> None:
    for provider in providers:
        client = getattr(provider, "client", None)
        try:
            if client is not None:
                client.close()
        except Exception:  # noqa: BLE001 - closing is best effort; the run is already over
            pass


def _provider(entry: Any, *, index: int, root: Path) -> McpProvider:
    if not isinstance(entry, dict):
        raise ConfigError(f"MCP server #{index} must be an object")
    provider_id = str(entry.get("id") or "")
    command = entry.get("command")
    capabilities = entry.get("capabilities")
    risk = str(entry.get("risk") or "MEDIUM").upper()
    trust = str(entry.get("trust_class") or "local_mcp")
    if not provider_id.startswith("mcp:"):
        raise ConfigError(f"MCP server #{index}: id must start with 'mcp:' (got {provider_id!r})")
    if not isinstance(command, list) or not command or not all(isinstance(c, str) for c in command):
        raise ConfigError(f"MCP server {provider_id}: command must be a non-empty list of strings")
    if not isinstance(capabilities, dict) or not capabilities:
        raise ConfigError(f"MCP server {provider_id}: capabilities must map capability -> tool name")
    if risk not in RISKS:
        raise ConfigError(f"MCP server {provider_id}: risk must be one of {sorted(RISKS)}")
    if trust not in TRUST_CLASSES:
        raise ConfigError(f"MCP server {provider_id}: trust_class must be one of {sorted(TRUST_CLASSES)}")

    argv = list(command)
    if argv[0] in {"python", "python3"}:
        argv[0] = sys.executable
    argv = [argv[0]] + [str(root / a) if a.endswith(".py") and not Path(a).is_absolute() else a for a in argv[1:]]

    client = McpStdioClient(StdioTransport(argv, cwd=str(root)))
    try:
        return McpProvider.from_advertised_tools(
            provider_id=provider_id,
            client=client,
            capability_map={str(k): str(v) for k, v in capabilities.items()},
            risk=risk,
            trust_class=trust,
            description=str(entry.get("description") or ""),
        )
    except Exception as exc:
        client.close()
        raise ConfigError(f"MCP server {provider_id} could not be started: {exc}") from exc
