"""MCP server configuration management for security-agent-harness.

Allows operators to register, inspect, enable, and disable Model Context Protocol
servers in ~/.config/security-agent-harness/mcp_servers.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from harness.config import get_config_dir

MCP_CONFIG_FILE_NAME = "mcp_servers.json"


def get_mcp_config_path() -> Path:
    return get_config_dir() / MCP_CONFIG_FILE_NAME


class MCPServerEntry(BaseModel):
    name: str = Field(description="Unique identifier for the MCP server")
    command: str = Field(description="Command to spawn the MCP server executable")
    args: list[str] = Field(default_factory=list, description="Arguments for the command")
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables")
    trust_class: str = Field(default="external_provider", description="Trust class (e.g. external_provider, local_tool)")
    enabled: bool = Field(default=True, description="Whether this MCP server is enabled")


def load_mcp_servers() -> list[MCPServerEntry]:
    path = get_mcp_config_path()
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [MCPServerEntry.model_validate(item) for item in data]
        if isinstance(data, dict) and "mcp_servers" in data:
            servers = data["mcp_servers"]
            if isinstance(servers, list):
                return [MCPServerEntry.model_validate(item) for item in servers]
            if isinstance(servers, dict):
                result = []
                for name, cfg in servers.items():
                    cfg["name"] = name
                    result.append(MCPServerEntry.model_validate(cfg))
                return result
        return []
    except Exception:
        return []


def save_mcp_servers(servers: list[MCPServerEntry]) -> Path:
    path = get_mcp_config_path()
    from harness.util import atomic_write_json
    atomic_write_json(path, [s.model_dump(mode="json") for s in servers])
    return path


def add_mcp_server(entry: MCPServerEntry) -> None:
    servers = load_mcp_servers()
    filtered = [s for s in servers if s.name != entry.name]
    filtered.append(entry)
    save_mcp_servers(filtered)


def remove_mcp_server(name: str) -> bool:
    servers = load_mcp_servers()
    new_servers = [s for s in servers if s.name != name]
    if len(new_servers) == len(servers):
        return False
    save_mcp_servers(new_servers)
    return True


def toggle_mcp_server(name: str, enabled: bool) -> bool:
    servers = load_mcp_servers()
    found = False
    for s in servers:
        if s.name == name:
            s.enabled = enabled
            found = True
            break
    if found:
        save_mcp_servers(servers)
    return found
