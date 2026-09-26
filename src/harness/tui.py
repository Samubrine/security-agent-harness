"""Interactive Terminal User Interface (TUI / REPL) for security-agent-harness.

Provides a modern, interactive console experience (similar to Claude Code, Codex, and DeepSeek harness)
with live execution HUD, slash commands, model auto-detection/BYOK, tool/MCP inspection,
and immediate feedback.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from harness import __version__
from harness.config import (
    UserConfig,
    get_config_dir,
    load_user_config,
    resolve_api_key,
    save_user_config,
)
from harness.errors import HarnessError
from harness.mcp_config import (
    MCPServerEntry,
    add_mcp_server,
    load_mcp_servers,
    remove_mcp_server,
    toggle_mcp_server,
)
from harness.models import EventRecord
from harness.runtime.replay import Replayer
from harness.runtime.runner import RunArtifacts, RunRequest, execute_run
from harness.runtime.verify import audit_run_dir


class LiveInvestigationHUD:
    """Formats and prints live FSM execution events in real time."""

    def __init__(self, console: Console) -> None:
        self.console = console
        self.step = 0
        self.injection_count = 0
        self.redaction_count = 0

    def handle_event(self, event: EventRecord) -> None:
        etype = event.type
        d = event.data or {}

        if etype == "RUN_STARTED":
            self.console.print(f"[bold cyan]> Investigation started[/bold cyan] [dim](run: {event.run_id})[/dim]")
        elif etype == "PROPOSAL_RECEIVED":
            self.step = d.get("step", self.step + 1)
            cap = d.get("capability", "unknown")
            hypothesis = d.get("hypothesis_id", "")
            hyp_str = f" [dim](hyp: {hypothesis})[/dim]" if hypothesis else ""
            self.console.print(f" [bold cyan]* Step {self.step}: PROPOSAL[/bold cyan] -> Requested capability [bold]{cap}[/bold]{hyp_str}")
        elif etype == "PROVIDER_EXPANSION":
            reason = d.get("expansion_reason", "unknown")
            selected = d.get("selected", [])
            self.console.print(f"   [yellow]! PROVIDER EXPANSION[/yellow] -> {reason} ({', '.join(selected)})")
        elif etype == "NECESSITY_DECIDED":
            sel = d.get("selected", [])
            reasons = d.get("selection_reasons", {})
            reason_str = ", ".join(f"{p}: {r}" for p, r in reasons.items()) if reasons else "minimum_sufficient"
            self.console.print(f"   [green][OK] NECESSITY[/green] -> Selected [bold]{', '.join(sel)}[/bold] [dim]({reason_str})[/dim]")
        elif etype == "POLICY_DECIDED":
            verdict = d.get("verdict", "unknown")
            grant = d.get("grant_id", "")
            reasons = d.get("reasons", [])
            color = "green" if verdict == "allow" else ("yellow" if verdict == "ask" else "red")
            self.console.print(f"   [{color}][OK] POLICY[/{color}] -> [bold]{verdict.upper()}[/bold] via Grant {grant} [dim]({', '.join(reasons)})[/dim]")
        elif etype == "PROVIDER_EXECUTED":
            prov = d.get("provider", "")
            dur = d.get("duration_seconds", 0.0)
            bytes_len = d.get("artifact_bytes", 0)
            digest = d.get("artifact_digest", "")
            short_digest = digest[:18] + "..." if digest else ""
            self.console.print(f"   [blue][OK] EXECUTION[/blue] -> {prov} finished in {dur:.2f}s ({bytes_len} bytes, {short_digest})")
        elif etype == "OBSERVATIONS_PARSED":
            count = d.get("count", 0)
            media = d.get("media_type", "")
            self.console.print(f"   [magenta][OK] PARSER[/magenta] -> Extracted [bold]{count}[/bold] observations ({media})")
        elif etype == "FINDINGS_EXTRACTED":
            count = d.get("count", 0)
            self.console.print(f"   [yellow][OK] FINDINGS[/yellow] -> Formed [bold]{count}[/bold] evidence-bound findings")
        elif etype == "INJECTION_ATTEMPT_DETECTED":
            self.injection_count += 1
            snippet = str(d.get("snippet", ""))[:60]
            self.console.print(
                Panel(
                    f"[bold yellow]Instruction-shaped text found in untrusted input:[/bold yellow]\n"
                    f"[dim]Snippet:[/dim] {snippet}\n"
                    f"[green]Safely isolated in nonce-delimited untrusted block (taint: T1_UNTRUSTED).[/green]",
                    title="[bold red][WARN]  PROMPT INJECTION NEUTRALIZED[/bold red]",
                    border_style="red",
                )
            )
        elif etype == "PROMPT_EGRESS_REDACTED":
            self.redaction_count += 1
            count = d.get("count", 0)
            classes = ", ".join(d.get("classes", []))
            self.console.print(
                f"   [yellow][SAFE] PROMPT EGRESS REDACTION[/yellow] -> Redacted {count} markers before sending to remote model [dim]({classes})[/dim]"
            )
        elif etype == "FOLLOW_UP_SCHEDULED":
            cap = d.get("capability", "")
            self.console.print(f"   [cyan]ℹ️  FOLLOW-UP SCHEDULED[/cyan] -> Conflict resolution scheduled for {cap}")
        elif etype == "RUN_FAILED":
            reason = d.get("reason", "unknown")
            self.console.print(f" [bold red]✖ RUN FAILED:[/bold red] {reason}")
        elif etype == "RUN_BUDGET_EXHAUSTED":
            budget = d.get("budget", "tokens/steps")
            self.console.print(f" [bold yellow]✖ BUDGET EXHAUSTED:[/bold yellow] Reached limit for {budget}")


def probe_ollama_models(endpoint: str = "http://127.0.0.1:11434") -> list[str]:
    """Check if local Ollama server is running and return list of pulled model names."""
    try:
        resp = httpx.get(f"{endpoint.rstrip('/')}/api/tags", timeout=1.5)
        if resp.status_code == 200:
            data = resp.json()
            return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    except Exception:
        pass
    return []


def probe_openai_compat(endpoint: str = "http://127.0.0.1:1234/v1") -> list[str]:
    """Check LM Studio / vLLM / llama.cpp local endpoint."""
    try:
        resp = httpx.get(f"{endpoint.rstrip('/')}/models", timeout=1.5)
        if resp.status_code == 200:
            data = resp.json()
            return [m.get("id", "") for m in data.get("data", []) if m.get("id")]
    except Exception:
        pass
    return []


def ensure_dev_bootstrap() -> tuple[Path, Path]:
    """Ensure default scope and keypair exist, generating development ones if missing."""
    config_dir = get_config_dir()
    scope_path = config_dir / "lab_scope.signed.json"
    pub_key_path = config_dir / "scope_ed25519_public.pem"
    priv_key_path = config_dir / "scope_ed25519_private.pem"

    repo_scope = Path("tests/fixtures/scope/lab_scope.json")
    repo_pub = Path("tests/fixtures/scope/scope_ed25519_public.pem")

    if scope_path.is_file() and pub_key_path.is_file():
        return scope_path, pub_key_path

    # If repo fixtures exist, generate keypair and sign
    from datetime import timedelta
    from harness.models import ScopeFile, ScopeNetwork, ScopeWindow
    from harness.policy.scope import generate_keypair, sign_scope
    from harness.util import atomic_write_json, utcnow

    if not pub_key_path.is_file() or not priv_key_path.is_file():
        generate_keypair(priv_key_path, pub_key_path, force=True)

    scope = ScopeFile(
        payload_version=2,
        scope_id="lab-scenario",
        authorized_by="security-agent-harness-operator",
        networks=[
            ScopeNetwork(
                cidr="10.77.0.0/24",
                include=["10.77.0.11", "10.77.0.12"],
                ports=[22, 80, 443, 8080],
            )
        ],
        filesystem=["/lab/logs"],
        aliases={
            "lab-web-01": "net:10.77.0.11",
            "lab-web-02": "net:10.77.0.12",
            "lab-logs": "fs:/lab/logs",
        },
        window=ScopeWindow(
            **{"from": utcnow() - timedelta(days=1), "to": utcnow() + timedelta(days=365)}
        ),
    )
    signed = sign_scope(scope, priv_key_path)
    atomic_write_json(scope_path, signed.model_dump(mode="json"))
    return scope_path, pub_key_path


class InteractiveSession:
    """Full-featured interactive REPL for the security agent harness."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.config = load_user_config()
        self.scope_path, self.public_key_path = ensure_dev_bootstrap()
        self.last_artifacts: RunArtifacts | None = None
        self.last_findings: list[dict[str, Any]] = []

    def render_banner(self) -> None:
        self.console.clear()
        banner_text = Text()
        banner_text.append("[SEC]  SECURITY AGENT HARNESS ", style="bold cyan")
        banner_text.append(f"v{__version__}\n", style="bold white")
        banner_text.append("Deterministic policy spine with agentic capability routing\n", style="dim")

        # Model status line
        backend = self.config.default_backend
        model_id = self.config.default_model
        ep = self.config.default_endpoint or "(default)"
        is_remote = self.config.enable_remote_egress or backend in {"openai", "deepseek", "openrouter", "groq"}
        status_style = "yellow" if is_remote else "green"
        status_label = "Remote / Egress Allowed" if is_remote else "Local Loopback"

        # Providers count
        mcp_servers = load_mcp_servers()
        active_mcp = sum(1 for s in mcp_servers if s.enabled)
        providers_str = f"4 native + {active_mcp} MCP active"

        # Memory status
        mem_path = Path("MEMORY.md")
        mem_kb = f"{mem_path.stat().st_size / 1024:.1f} KB" if mem_path.exists() else "empty"

        table = Table.grid(padding=(0, 2))
        table.add_column("Key", style="bold")
        table.add_column("Val")
        table.add_row("Model:", f"[bold]{backend}/{model_id}[/bold] [dim]({ep})[/dim] • [{status_style}]● {status_label}[/{status_style}]")
        table.add_row("Scope:", f"[bold]lab-scenario[/bold] [dim]({self.scope_path.name})[/dim] • [green]Ed25519 Anchored[/green]")
        table.add_row("Providers:", f"[cyan]{providers_str}[/cyan]")
        table.add_row("Memory:", f"[dim]Active: {mem_kb}[/dim]")

        panel = Panel(
            table,
            title=banner_text,
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(panel)
        self.console.print("[dim]Type your investigation objective directly, or use [bold cyan]/help[/bold cyan] for commands.[/dim]\n")

    def cmd_help(self) -> None:
        table = Table(title="Interactive Command Reference", border_style="cyan")
        table.add_column("Command", style="bold cyan")
        table.add_column("Description")
        table.add_row("/help", "Show this command reference")
        table.add_row("/model", "Inspect or switch active model backend, endpoint & API key")
        table.add_row("/tools", "List all capabilities, registered providers, trust classes & risk")
        table.add_row("/mcp", "Manage MCP servers (list, add, remove, toggle)")
        table.add_row("/skills", "View available skills (port_scan, log_analysis, entry_point)")
        table.add_row("/scope", "Inspect authorized target aliases, networks & port window")
        table.add_row("/findings", "Display security findings discovered during the last run")
        table.add_row("/verify [run_id]", "Run cryptographic reference-graph audit on a run directory")
        table.add_row("/replay [run_id]", "Verify bit-for-bit offline replay of an investigation")
        table.add_row("/memory", "Inspect active working memory and long-term knowledge shards")
        table.add_row("/init", "Regenerate/bootstrap local scope authority and keypair")
        table.add_row("/config", "View or update persistent preferences in ~/.config/security-agent-harness")
        table.add_row("/clear", "Clear the terminal screen")
        table.add_row("/exit, /quit", "Exit interactive session")
        self.console.print(table)

    def cmd_model(self) -> None:
        self.console.print(Panel.fit(
            f"Current Backend: [bold cyan]{self.config.default_backend}[/bold cyan]\n"
            f"Current Model:   [bold]{self.config.default_model}[/bold]\n"
            f"Current Endpoint:[dim]{self.config.default_endpoint or '(default)'}[/dim]\n"
            f"Remote Egress:   [yellow]{self.config.enable_remote_egress}[/yellow]",
            title="Active Model Configuration"
        ))

        # Check local servers
        ollama_models = probe_ollama_models()
        openai_models = probe_openai_compat()

        self.console.print("\n[bold]Switch Backend or Provider:[/bold]")
        options = [
            ("1", "scripted", "Deterministic scripted planner (zero dependencies, fast)"),
            ("2", "ollama", f"Local Ollama server (Found {len(ollama_models)} models)"),
            ("3", "lmstudio", "Local LM Studio / vLLM / llama.cpp (OpenAI-compatible)"),
            ("4", "deepseek", "DeepSeek API (api.deepseek.com)"),
            ("5", "openrouter", "OpenRouter API (openrouter.ai)"),
            ("6", "groq", "Groq Cloud API (api.groq.com)"),
            ("7", "openai", "OpenAI API / Custom OpenAI-compatible URL"),
            ("0", "cancel", "Keep current model"),
        ]
        for num, name, desc in options:
            self.console.print(f"  [bold cyan][{num}][/bold cyan] [bold]{name:12}[/bold] {desc}")

        choice = Prompt.ask("\nSelect option", choices=[o[0] for o in options], default="0")
        if choice == "0":
            return

        if choice == "1":
            self.config.default_backend = "scripted"
            self.config.default_model = "scripted-planner"
            self.config.default_endpoint = None
            self.config.enable_remote_egress = False
        elif choice == "2":
            self.config.default_backend = "ollama"
            if ollama_models:
                self.console.print(f"Available Ollama models: {', '.join(ollama_models)}")
                self.config.default_model = Prompt.ask("Model ID", default=ollama_models[0])
            else:
                self.config.default_model = Prompt.ask("Model ID", default="llama3")
            self.config.default_endpoint = Prompt.ask("Endpoint", default="http://127.0.0.1:11434")
            self.config.enable_remote_egress = False
        elif choice == "3":
            self.config.default_backend = "openai"
            self.config.default_model = Prompt.ask("Model ID", default="local-model")
            self.config.default_endpoint = Prompt.ask("Endpoint", default="http://127.0.0.1:1234/v1")
            self.config.enable_remote_egress = False
        elif choice in {"4", "5", "6", "7"}:
            backend_map = {"4": "deepseek", "5": "openrouter", "6": "groq", "7": "openai"}
            bname = backend_map[choice]
            self.config.default_backend = bname
            default_models = {
                "deepseek": "deepseek-chat",
                "openrouter": "anthropic/claude-3.5-sonnet",
                "groq": "llama-3.3-70b-versatile",
                "openai": "gpt-4o",
            }
            self.config.default_model = Prompt.ask("Model ID", default=default_models.get(bname, "gpt-4o"))
            self.config.enable_remote_egress = True
            # API Key handling
            current_key = resolve_api_key(bname)
            if current_key:
                mask = current_key[:4] + "..." + current_key[-4:] if len(current_key) > 8 else "***"
                self.console.print(f"Detected existing API key for {bname}: [dim]{mask}[/dim]")
                if Confirm.ask("Use this key?"):
                    pass
                else:
                    new_key = Prompt.ask(f"Enter {bname.upper()} API Key", password=True)
                    if new_key.strip():
                        self.config.api_keys[bname] = new_key.strip()
            else:
                new_key = Prompt.ask(f"Enter {bname.upper()} API Key (or leave blank to use env var)", password=True)
                if new_key.strip():
                    self.config.api_keys[bname] = new_key.strip()

        save_user_config(self.config)
        self.console.print(f"[bold green][OK] Model updated to {self.config.default_backend}/{self.config.default_model}[/bold green]")

    def cmd_tools(self) -> None:
        from harness.runtime.runner import _build_registry, VulnerabilitySnapshot
        snap_path = Path("tests/fixtures/vuln/snapshot_2026-09.json")
        snap = VulnerabilitySnapshot.load(snap_path) if snap_path.exists() else VulnerabilitySnapshot(snapshot_id="empty", created_at=datetime.now(), cpe_matches=[])
        req = RunRequest(
            objective="inspect",
            skill="port_scan",
            scope_path=self.scope_path,
            public_key_path=self.public_key_path,
        )
        registry = _build_registry(req, snap, lambda: [], "inspect-run")

        table = Table(title="Registered Capabilities & Providers", border_style="cyan")
        table.add_column("Capability", style="bold cyan", no_wrap=True)
        table.add_column("Provider ID", style="bold")
        table.add_column("Kind")
        table.add_column("Trust Class")
        table.add_column("Risk")
        table.add_column("Egress Req")

        for cap in registry.capabilities():
            providers = registry.by_capability(cap)
            for p in providers:
                spec = p.spec
                egress_color = "red" if spec.requires_network_egress else "green"
                table.add_row(
                    cap,
                    spec.id,
                    spec.kind,
                    spec.trust_class,
                    spec.risk,
                    f"[{egress_color}]{spec.requires_network_egress}[/{egress_color}]",
                )
        self.console.print(table)

    def cmd_mcp(self, arg: str = "") -> None:
        parts = arg.strip().split()
        sub = parts[0] if parts else "list"

        if sub == "list":
            servers = load_mcp_servers()
            if not servers:
                self.console.print("[dim]No MCP servers registered. Use [bold]/mcp add <name> <command> [args...][/bold] to register one.[/dim]")
                return
            table = Table(title="Configured Model Context Protocol (MCP) Servers", border_style="cyan")
            table.add_column("Name", style="bold")
            table.add_column("Command")
            table.add_column("Args")
            table.add_column("Trust Class")
            table.add_column("Status")
            for s in servers:
                status = "[green]Enabled[/green]" if s.enabled else "[dim red]Disabled[/dim red]"
                table.add_row(s.name, s.command, " ".join(s.args), s.trust_class, status)
            self.console.print(table)
        elif sub == "add":
            if len(parts) < 3:
                name = Prompt.ask("Server name")
                cmd = Prompt.ask("Executable command")
                args_str = Prompt.ask("Command arguments (space separated)", default="")
                args = args_str.split() if args_str else []
            else:
                name = parts[1]
                cmd = parts[2]
                args = parts[3:]
            add_mcp_server(MCPServerEntry(name=name, command=cmd, args=args))
            self.console.print(f"[green][OK] Added MCP server '{name}'[/green]")
        elif sub == "remove":
            name = parts[1] if len(parts) > 1 else Prompt.ask("Server name to remove")
            if remove_mcp_server(name):
                self.console.print(f"[green][OK] Removed MCP server '{name}'[/green]")
            else:
                self.console.print(f"[yellow]Server '{name}' not found[/yellow]")
        elif sub == "toggle":
            name = parts[1] if len(parts) > 1 else Prompt.ask("Server name to toggle")
            servers = load_mcp_servers()
            target = next((s for s in servers if s.name == name), None)
            if target:
                toggle_mcp_server(name, not target.enabled)
                self.console.print(f"[green][OK] Toggled '{name}' to enabled={not target.enabled}[/green]")
            else:
                self.console.print(f"[yellow]Server '{name}' not found[/yellow]")
        else:
            self.console.print("[yellow]Usage: /mcp [list | add | remove | toggle][/yellow]")

    def cmd_skills(self) -> None:
        from harness.skills import list_skills
        skills = list_skills()
        table = Table(title="Available Security Skills", border_style="cyan")
        table.add_column("Skill", style="bold cyan")
        table.add_column("Description")
        table.add_column("Required Capabilities")
        table.add_column("Corroboration")
        for s in skills:
            table.add_row(
                s.name,
                s.description,
                ", ".join(s.capabilities),
                "Yes" if (s.verification and s.verification.independent_for) else "No",
            )
        self.console.print(table)

    def cmd_scope(self) -> None:
        from harness.policy.scope import load_scope
        try:
            loaded = load_scope(self.scope_path, public_key_path=self.public_key_path)
        except Exception as exc:
            self.console.print(f"[red]Failed to load scope: {exc}[/red]")
            return

        table = Table(title=f"Scope Authorization: {loaded.scope_id}", border_style="cyan")
        table.add_column("Field", style="bold")
        table.add_column("Value")
        table.add_row("Authorized By", loaded.authorized_by)
        table.add_row("Validity Window", f"{loaded.window.from_at} to {loaded.window.to}")
        table.add_row("Networks", ", ".join(n.cidr for n in loaded.networks))
        ports_list = [', '.join(str(p) for p in n.ports) for n in loaded.networks if n.ports]
        table.add_row("Port Window", ", ".join(ports_list) if ports_list else "(all ports)")
        table.add_row("Aliases", ", ".join(f"{k} -> {v}" for k, v in sorted(loaded.aliases.items())))
        self.console.print(table)

    def cmd_findings(self) -> None:
        if not self.last_findings:
            self.console.print("[dim]No findings from this session yet. Run an investigation first.[/dim]")
            return

        table = Table(title="Discovered Security Findings", border_style="yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Title", style="bold")
        table.add_column("Status")
        table.add_column("Confidence")
        table.add_column("Evidence Location")

        for f in self.last_findings:
            sev = f.get("severity", "LOW").upper()
            color = "red" if sev in {"CRITICAL", "HIGH"} else ("yellow" if sev == "MEDIUM" else "cyan")
            status = f.get("status", "possible")
            conf = f.get("confidence", "medium")
            title = f.get("title", "")
            evidence = ""
            claims = f.get("claims", [])
            if claims and isinstance(claims[0], dict):
                obs = claims[0].get("observations", [])
                evidence = obs[0] if obs else ""
            table.add_row(f"[{color}]{sev}[/{color}]", title, status, conf, evidence)
        self.console.print(table)

    def cmd_verify(self, arg: str = "") -> None:
        run_dir_str = arg.strip()
        if not run_dir_str:
            if self.last_artifacts:
                run_dir = self.last_artifacts.run_dir
            else:
                run_dir = Path("tests/fixtures/run/port_scan")
        else:
            run_dir = Path(run_dir_str)

        audit = audit_run_dir(run_dir)
        colour = "green" if audit.ok else "red"
        checked = ", ".join(f"{name}={count}" for name, count in sorted(audit.checked.items()))
        self.console.print(f"[{colour}]run {audit.run_id}: {'ok' if audit.ok else 'problems'}[/{colour}]")
        if checked:
            self.console.print(f"  checked: {checked}")
        for issue in audit.issues:
            style = "red" if issue.severity == "error" else "yellow"
            self.console.print(f"  [{style}]{issue.severity}:[/{style}] {issue.code} {issue.subject}: {issue.detail}")

    def cmd_replay(self, arg: str = "") -> None:
        run_dir_str = arg.strip()
        if not run_dir_str:
            if self.last_artifacts:
                run_dir = self.last_artifacts.run_dir
            else:
                run_dir = Path("tests/fixtures/run/port_scan")
        else:
            run_dir = Path(run_dir_str)

        replayer = Replayer(run_dir)
        report = replayer.report()
        colour = "green" if report["verified"] else "red"
        self.console.print(
            f"[{colour}]verified={report['verified']}[/{colour}] events={report['event_count']} "
            f"observations={report['observation_count']} findings={report['finding_count']}"
        )
        for problem in report.get("problems", []):
            self.console.print(f"  [red]problem:[/red] {problem}")

    def cmd_memory(self) -> None:
        from harness.memory.index import LongTermIndex
        from harness.memory.manager import MemoryManager
        manager = MemoryManager(Path("."))
        active = manager.load_active()
        self.console.print(Panel(active.strip() or "(empty)", title="Active Memory (MEMORY.md)"))
        index_path = Path("memory/long_term/index.sqlite")
        if index_path.exists():
            entries = LongTermIndex(index_path).all()
            table = Table(title=f"Long-lived Memory Shards ({len(entries)} entries)")
            table.add_column("ID", style="cyan")
            table.add_column("Kind")
            table.add_column("Confidence")
            table.add_column("Summary")
            for e in entries:
                table.add_row(e.id, e.kind, e.confidence, e.summary[:75])
            self.console.print(table)

    def cmd_init(self) -> None:
        s, p = ensure_dev_bootstrap()
        self.scope_path = s
        self.public_key_path = p
        self.console.print(f"[bold green][OK] Initialized authority keypair and scope at {get_config_dir()}[/bold green]")

    def run_investigation(self, objective: str) -> None:
        """Execute an investigation based on user prompt with the live HUD."""
        # Choose skill heuristically or use default
        lower = objective.lower()
        skill = "port_scan"
        if "log" in lower or "burst" in lower or "brute" in lower:
            skill = "log_analysis"
        elif "correlate" in lower or "entry" in lower or "cross-source" in lower:
            skill = "entry_point"

        target = self.config.default_target or "lab-web-01"

        self.console.print()
        self.console.print(Panel(
            f"[bold]Objective:[/bold] {objective}\n"
            f"[bold]Skill:[/bold]     {skill}    [bold]Target:[/bold] {target}\n"
            f"[bold]Model:[/bold]     {self.config.default_backend}/{self.config.default_model}",
            title="[bold cyan][RUN] Launching Investigation[/bold cyan]",
            border_style="cyan",
        ))

        hud = LiveInvestigationHUD(self.console)
        api_key = resolve_api_key(self.config.default_backend)

        req = RunRequest(
            objective=objective,
            skill=skill,
            scope_path=self.scope_path,
            public_key_path=self.public_key_path,
            model_backend=self.config.default_backend,
            model_id=self.config.default_model,
            endpoint=self.config.default_endpoint,
            allow_remote=self.config.enable_remote_egress,
            api_key=api_key,
            target_alias=target if skill == "port_scan" else None,
            event_listener=hud.handle_event,
        )

        try:
            artifacts = execute_run(req)
            self.last_artifacts = artifacts
            # Load findings for inspection
            findings_json = artifacts.run_dir / "findings.json"
            if findings_json.is_file():
                self.last_findings = json.loads(findings_json.read_text(encoding="utf-8"))
            else:
                self.last_findings = []

            self.console.print()
            self.console.print(f"[bold green][OK] Investigation completed with status: {artifacts.summary.status}[/bold green]")
            self.cmd_findings()
            self.console.print(f"\n[dim]Report written to: [bold]{artifacts.report_markdown}[/bold][/dim]")
        except HarnessError as exc:
            self.console.print(Panel.fit(f"[red]{type(exc).__name__}: {exc}[/red]", title="Run Refused"))
        except Exception as exc:
            self.console.print(f"[red]Unexpected error during run: {exc}[/red]")

    def loop(self) -> None:
        self.render_banner()
        while True:
            try:
                prompt_text = Prompt.ask("[bold cyan]harness[/bold cyan]")
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[dim]Goodbye![/dim]")
                break

            raw = prompt_text.strip()
            if not raw:
                continue

            if raw in {"/exit", "/quit", "exit", "quit"}:
                self.console.print("[dim]Goodbye![/dim]")
                break
            elif raw in {"/clear", "clear"}:
                self.render_banner()
            elif raw.startswith("/help"):
                self.cmd_help()
            elif raw.startswith("/model"):
                self.cmd_model()
            elif raw.startswith("/tools") or raw.startswith("/providers"):
                self.cmd_tools()
            elif raw.startswith("/mcp"):
                arg = raw[4:].strip()
                self.cmd_mcp(arg)
            elif raw.startswith("/skills"):
                self.cmd_skills()
            elif raw.startswith("/scope"):
                self.cmd_scope()
            elif raw.startswith("/findings"):
                self.cmd_findings()
            elif raw.startswith("/verify"):
                arg = raw[7:].strip()
                self.cmd_verify(arg)
            elif raw.startswith("/replay"):
                arg = raw[7:].strip()
                self.cmd_replay(arg)
            elif raw.startswith("/memory"):
                self.cmd_memory()
            elif raw.startswith("/init"):
                self.cmd_init()
            elif raw.startswith("/"):
                self.console.print(f"[yellow]Unknown command '{raw}'. Type /help for available commands.[/yellow]")
            else:
                self.run_investigation(raw)


def start_tui() -> None:
    session = InteractiveSession()
    session.loop()
