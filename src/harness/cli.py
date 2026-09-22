"""Command line interface.

The CLI is deliberately thin: it parses arguments, calls the runner, and prints. Anything that
looks like a decision belongs in the spine, where it can be tested without a terminal.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from harness import __version__
from harness.errors import HarnessError
from harness.runtime.replay import Replayer
from harness.runtime.runner import RunRequest, execute_run

app = typer.Typer(
    add_completion=False,
    help="Local-first agentic security investigation harness.",
    no_args_is_help=True,
)
scope_app = typer.Typer(help="Sign and verify scope authorisation records.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")

console = Console()

DEFAULT_SCOPE = Path("tests/fixtures/scope/lab_scope.json")


def _repo_root() -> Path:
    return Path.cwd()


@app.command()
def run(
    objective: Annotated[str, typer.Option("--objective", "-o", help="What to investigate.")],
    skill: Annotated[str, typer.Option("--skill", "-s", help="Skill name, e.g. port_scan.")] = "port_scan",
    scope: Annotated[Path, typer.Option("--scope", help="Signed scope record.")] = DEFAULT_SCOPE,
    public_key: Annotated[Path | None, typer.Option("--public-key", help="Ed25519 public key for the scope record.")] = None,
    dev_embedded_key: Annotated[
        bool,
        typer.Option(
            "--dev-embedded-key",
            help="Verify the scope against the key embedded in the record itself (development only).",
        ),
    ] = False,
    target: Annotated[str | None, typer.Option("--target", help="Scope alias to investigate.")] = None,
    model_backend: Annotated[str, typer.Option("--model-backend", help="scripted | ollama | openai | replay")] = "scripted",
    model: Annotated[str, typer.Option("--model", help="Model id for the chosen backend.")] = "scripted-planner",
    endpoint: Annotated[str | None, typer.Option("--endpoint", help="Local model endpoint.")] = None,
    approvals: Annotated[str, typer.Option("--approvals", help="deny | approve | scripted")] = "deny",
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Render intentions without executing.")] = False,
    allow_remote: Annotated[bool, typer.Option("--allow-remote-egress", help="Permit a non-loopback model endpoint.")] = False,
    run_id: Annotated[str | None, typer.Option("--run-id", help="Override the generated run id.")] = None,
    out: Annotated[Path | None, typer.Option("--out", help="Write the run directory exactly here instead of under runs/.")] = None,
    snapshot: Annotated[Path | None, typer.Option("--vuln-snapshot", help="Offline vulnerability snapshot.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print the run summary as JSON.")] = False,
) -> None:
    """Run one investigation."""
    request = RunRequest(
        objective=objective,
        skill=skill,
        scope_path=scope,
        public_key_path=public_key,
        dev_embedded_key=dev_embedded_key,
        root=_repo_root(),
        model_backend=model_backend,
        model_id=model,
        endpoint=endpoint,
        target_alias=target,
        approval_mode=approvals,
        dry_run=dry_run,
        allow_remote=allow_remote,
        run_id=run_id,
        run_dir=out,
        snapshot_path=snapshot,
    )
    try:
        artifacts = execute_run(request)
    except HarnessError as exc:
        console.print(Panel.fit(f"[red]{type(exc).__name__}[/red]\n{exc}", title="run refused"))
        raise typer.Exit(code=2) from exc

    if json_output:
        console.print_json(
            json.dumps(
                {
                    "run_id": artifacts.run_id,
                    "run_dir": str(artifacts.run_dir),
                    "status": artifacts.summary.status,
                    "steps": artifacts.summary.steps,
                    "provider_calls": artifacts.summary.provider_calls,
                    "findings": artifacts.summary.findings,
                    "gaps": artifacts.summary.gaps,
                    "stop_reason": artifacts.stop_reason,
                }
            )
        )
        return

    table = Table(title=f"run {artifacts.run_id}", show_header=False)
    table.add_row("status", artifacts.summary.status)
    table.add_row("steps", str(artifacts.summary.steps))
    table.add_row("provider calls", str(artifacts.summary.provider_calls))
    table.add_row("findings", str(artifacts.summary.findings))
    table.add_row("gaps", str(artifacts.summary.gaps))
    if artifacts.stop_reason:
        table.add_row("stopped because", artifacts.stop_reason)
    table.add_row("report", str(artifacts.report_markdown))
    console.print(table)


@app.command()
def verify(
    run_dir: Annotated[Path, typer.Argument(help="A finished run directory.")],
    json_output: Annotated[bool, typer.Option("--json", help="Print the audit as JSON.")] = False,
) -> None:
    """Audit a run's reference graph: executions, decisions, grants, observations, findings.

    `harness replay` answers "do this run's own claims hold together?"; this answers "does anything it
    names actually exist?". Until v1.2 the second question was only answerable from code -
    `runtime.verify.audit_run_dir` had no caller outside the tests - so a run directory with a
    dangling decision or grant reference could be read, replayed and reported on without anyone being
    told (K2).
    """
    from harness.runtime.verify import audit_run_dir

    audit = audit_run_dir(run_dir)
    if json_output:
        console.print_json(json.dumps(audit.model_dump(mode="json")))
    else:
        colour = "green" if audit.ok else "red"
        checked = ", ".join(f"{name}={count}" for name, count in sorted(audit.checked.items()))
        console.print(f"[{colour}]run {audit.run_id}: {'ok' if audit.ok else 'problems'}[/{colour}]")
        if checked:
            console.print(f"  checked: {checked}")
        for issue in audit.issues:
            style = "red" if issue.severity == "error" else "yellow"
            console.print(f"  [{style}]{issue.severity}:[/{style}] {issue.code} {issue.subject}: {issue.detail}")
    if not audit.ok:
        raise typer.Exit(code=1)


@app.command()
def replay(
    run_dir: Annotated[Path, typer.Argument(help="A finished run directory.")],
    json_output: Annotated[bool, typer.Option("--json", help="Print the replay report as JSON.")] = False,
) -> None:
    """Re-derive a recorded run without touching the network."""
    replayer = Replayer(run_dir)
    report = replayer.report()
    if json_output:
        console.print_json(json.dumps(report))
    else:
        colour = "green" if report["verified"] else "red"
        console.print(f"[{colour}]verified={report['verified']}[/{colour}] events={report['event_count']} "
                      f"observations={report['observation_count']} findings={report['finding_count']}")
        for problem in report["problems"]:
            console.print(f"  [red]problem:[/red] {problem}")
    if not report["verified"]:
        raise typer.Exit(code=1)


@app.command()
def doctor() -> None:
    """Check that this machine can run the harness, and report what is missing."""
    import shutil
    import sqlite3

    checks: list[tuple[str, str, str]] = []
    checks.append(("python", sys.version.split()[0], "ok" if sys.version_info >= (3, 12) else "too old"))
    for module in ("pydantic", "lxml", "cryptography", "httpx", "yaml", "jinja2", "typer"):
        try:
            __import__(module)
            checks.append((module, "installed", "ok"))
        except ImportError:
            checks.append((module, "missing", "run: make install"))
    try:
        con = sqlite3.connect(":memory:")
        con.execute("create virtual table t using fts5(x)")
        checks.append(("sqlite fts5", sqlite3.sqlite_version, "ok"))
    except Exception as exc:  # noqa: BLE001
        checks.append(("sqlite fts5", "unavailable", str(exc)))
    checks.append(("nmap", shutil.which("nmap") or "absent", "ok" if shutil.which("nmap") else "optional: the synthetic provider is used instead"))
    checks.append(("docker", shutil.which("docker") or "absent", "ok" if shutil.which("docker") else "optional: needed only for make lab-up"))
    scope = DEFAULT_SCOPE
    checks.append(("lab scope", str(scope), "ok" if scope.exists() else "missing"))

    table = Table(title=f"harness {__version__} doctor")
    table.add_column("check")
    table.add_column("value")
    table.add_column("note")
    for name, value, note in checks:
        table.add_row(name, value, note)
    console.print(table)


@scope_app.command("sign")
def scope_sign(
    scope: Annotated[Path, typer.Argument(help="Unsigned scope record to sign.")],
    private_key: Annotated[Path, typer.Option("--private-key", help="Ed25519 private key, outside the repo.")],
    output: Annotated[Path | None, typer.Option("--out", help="Where to write the signed record.")] = None,
) -> None:
    """Attach an Ed25519 signature to a scope record."""
    from harness.policy.scope import key_protection, load_scope, sign_scope
    from harness.util import read_json

    from harness.models import ScopeFile

    unsigned = ScopeFile.model_validate(read_json(scope))
    signed = sign_scope(unsigned, private_key)
    destination = output or scope
    from harness.util import atomic_write_json

    atomic_write_json(destination, signed.model_dump(mode="json"))
    console.print(f"signed [bold]{destination}[/bold] with key {private_key}")
    # What protects the key that just signed, asked of the platform: "signed" says nothing about
    # whether anyone else on the machine can sign with the same key.
    protection = key_protection(private_key)
    console.print(f"private key protection: {protection}")
    if protection == "none":
        console.print(
            "[yellow]warning[/yellow] this platform does not restrict the key to your account; "
            "anyone who can read it can sign scope records"
        )


@scope_app.command("verify")
def scope_verify(
    scope: Annotated[Path, typer.Argument(help="Scope record to verify.")],
    public_key: Annotated[Path, typer.Option("--public-key", help="Ed25519 public key.")],
) -> None:
    """Verify a scope signature and its validity window."""
    from harness.policy.scope import load_scope

    loaded = load_scope(scope, public_key_path=public_key)
    console.print(f"[green]verified[/green] {loaded.scope_id} by {loaded.authorized_by}")
    console.print(f"window {loaded.window.from_at} .. {loaded.window.to}")
    console.print(f"aliases {sorted(loaded.aliases)}")


@app.command("memory")
def memory_show(
    root: Annotated[Path, typer.Option("--root", help="Repository root holding MEMORY.md.")] = Path("."),
) -> None:
    """Show the bounded active memory and what long-lived memory holds."""
    from harness.memory.index import LongTermIndex
    from harness.memory.manager import MemoryManager

    manager = MemoryManager(root)
    active = manager.load_active()
    console.print(Panel(active.strip() or "(empty)", title="MEMORY.md (active)"))
    index_path = Path(root) / "memory" / "long_term" / "index.sqlite"
    if not index_path.exists():
        console.print("no long-lived memory index yet")
        return
    entries = LongTermIndex(index_path).all()
    table = Table(title=f"long-lived memory ({len(entries)} entries)")
    for column in ("id", "kind", "confidence", "summary"):
        table.add_column(column)
    for entry in entries:
        table.add_row(entry.id, entry.kind, entry.confidence, entry.summary[:80])
    console.print(table)


@app.command("eval")
def eval_run(
    scenario: Annotated[str | None, typer.Option("--scenario", help="Scenario name; omit for all.")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Print the commands without running them.")] = False,
) -> None:
    """Run the evaluation scenarios and print the metrics table."""
    try:
        from eval.runner import main as eval_main
    except ImportError as exc:
        console.print(f"[red]eval harness not available:[/red] {exc}")
        raise typer.Exit(code=3) from exc
    raise typer.Exit(code=eval_main(scenario=scenario, dry_run=dry_run))


@app.command()
def schemas(
    dest: Annotated[Path, typer.Option("--out", help="Directory for exported JSON Schemas.")] = Path("schemas"),
) -> None:
    """Export the structured contracts as JSON Schema."""
    from harness.llm.schemas import export_schemas

    written = export_schemas(dest)
    for name, path in sorted(written.items()):
        console.print(f"{name}: {path}")


def main() -> None:  # pragma: no cover - console entry point
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
