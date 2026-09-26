"""Tests for user configuration, MCP server management, and CLI user interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from harness.cli import app
from harness.config import (
    UserConfig,
    load_user_config,
    resolve_api_key,
    save_user_config,
)
from harness.mcp_config import (
    MCPServerEntry,
    add_mcp_server,
    load_mcp_servers,
    remove_mcp_server,
    save_mcp_servers,
    toggle_mcp_server,
)
from harness.tui import InteractiveSession, LiveInvestigationHUD, probe_ollama_models
from rich.console import Console

runner = CliRunner()


def test_user_config_defaults_and_roundtrip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg = load_user_config()
    assert cfg.default_backend == "scripted"
    assert cfg.enable_remote_egress is False

    cfg.default_backend = "deepseek"
    cfg.default_model = "deepseek-chat"
    cfg.enable_remote_egress = True
    cfg.api_keys["deepseek"] = "sk-test-secret"
    save_user_config(cfg)

    loaded = load_user_config()
    assert loaded.default_backend == "deepseek"
    assert loaded.default_model == "deepseek-chat"
    assert loaded.enable_remote_egress is True
    assert loaded.api_keys["deepseek"] == "sk-test-secret"


def test_resolve_api_key_precedence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    # 1. Config fallback
    cfg = UserConfig(api_keys={"deepseek": "cfg-key"})
    save_user_config(cfg)
    assert resolve_api_key("deepseek") == "cfg-key"

    # 2. Env variable precedence
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")
    assert resolve_api_key("deepseek") == "env-key"


def test_mcp_server_crud(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert load_mcp_servers() == []

    entry = MCPServerEntry(name="nvd-lookup", command="trivy", args=["mcp"])
    add_mcp_server(entry)

    servers = load_mcp_servers()
    assert len(servers) == 1
    assert servers[0].name == "nvd-lookup"
    assert servers[0].enabled is True

    # Toggle
    assert toggle_mcp_server("nvd-lookup", False) is True
    assert load_mcp_servers()[0].enabled is False

    # Remove
    assert remove_mcp_server("nvd-lookup") is True
    assert load_mcp_servers() == []
    assert remove_mcp_server("non-existent") is False


def test_cli_tools_command() -> None:
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0
    assert "service.enumerate" in result.stdout or "service.enume" in result.stdout
    assert "log.read" in result.stdout and "native:log" in result.stdout


def test_cli_config_commands(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    show = runner.invoke(app, ["config", "show"])
    assert show.exit_code == 0
    assert "default_backend" in show.stdout

    set_cmd = runner.invoke(app, ["config", "set", "default_backend", "ollama"])
    assert set_cmd.exit_code == 0
    assert "ollama" in set_cmd.stdout

    cfg = load_user_config()
    assert cfg.default_backend == "ollama"


def test_cli_mcp_commands(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    lst = runner.invoke(app, ["mcp", "list"])
    assert lst.exit_code == 0

    add = runner.invoke(app, ["mcp", "add", "my-scanner", "python", "scan.py"])
    assert add.exit_code == 0
    assert "my-scanner" in add.stdout

    lst2 = runner.invoke(app, ["mcp", "list"])
    assert "my-scanner" in lst2.stdout

    rem = runner.invoke(app, ["mcp", "remove", "my-scanner"])
    assert rem.exit_code == 0


def test_cli_init_command(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    res = runner.invoke(app, ["init"])
    assert res.exit_code == 0
    assert (tmp_path / "security-agent-harness" / "lab_scope.signed.json").is_file()
    assert (tmp_path / "security-agent-harness" / "scope_ed25519_public.pem").is_file()


def test_interactive_session_methods(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    console = Console(record=True)
    session = InteractiveSession(console)

    session.cmd_help()
    session.cmd_tools()
    session.cmd_skills()
    session.cmd_scope()
    session.cmd_mcp("list")
    session.cmd_init()
    assert session.scope_path.is_file()

    session.run_investigation("Enumerate exposed services on lab-web-01.")
    assert len(session.last_findings) >= 1
    session.cmd_findings()
