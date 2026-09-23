"""The operator surface: what a grader actually types.

These run the real Typer commands in-process, in a working directory the test owns, so a command
that only works because of state left behind in the repository would fail here.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from harness.cli import app

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


@pytest.fixture
def cli_workspace(lab_environment, monkeypatch):
    """Run the CLI from inside the environment's workspace, as an operator would."""
    monkeypatch.chdir(lab_environment.root)
    return lab_environment


def runs_dir(environment) -> Path:
    """Where the CLI writes: the run root defaults to ``runs/`` under the working directory."""
    return environment.root / "runs"


def test_help_lists_the_commands_without_needing_a_model() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("run", "replay", "doctor", "scope", "memory", "eval", "schemas"):
        assert command in result.stdout


def test_the_eval_command_delegates_to_the_eval_runner(monkeypatch) -> None:
    """`harness eval` must actually reach `eval.runner.main`.

    The documented console command was unusable: `eval/` is not part of the installed
    distribution, so the import raised `ImportError`, and the call passed `scenario=`/`dry_run=`
    keywords to a function that takes argv, which would have been a `TypeError`. A dry run needs
    no authority material, so it is the cheapest proof that the wiring exists.
    """
    monkeypatch.chdir(REPO_ROOT)
    result = runner.invoke(app, ["eval", "--scenario", "entry_point", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "scenarios: entry_point" in result.output


def test_every_subcommand_help_works() -> None:
    for command in ("run", "replay", "doctor", "schemas", "memory"):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, command


def test_doctor_reports_its_checks() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "python" in result.stdout
    assert "sqlite fts5" in result.stdout


def test_scope_sign_then_verify_round_trips(cli_workspace, tmp_path: Path) -> None:
    unsigned = tmp_path / "unsigned.json"
    payload = json.loads(cli_workspace.scope_path.read_text(encoding="utf-8"))
    payload.pop("signature", None)
    payload.pop("signer_public_key", None)
    unsigned.write_text(json.dumps(payload), encoding="utf-8")
    signed = tmp_path / "signed.json"

    sign = runner.invoke(
        app,
        ["scope", "sign", str(unsigned), "--private-key", str(cli_workspace.private_key), "--out", str(signed)],
    )
    assert sign.exit_code == 0, sign.stdout
    assert signed.exists()

    verify = runner.invoke(
        app, ["scope", "verify", str(signed), "--public-key", str(cli_workspace.public_key)]
    )
    assert verify.exit_code == 0, verify.stdout
    assert "verified" in verify.stdout.lower()


def test_scope_verify_rejects_an_edited_signature(cli_workspace, tmp_path: Path) -> None:
    """A scope record is an authorisation, so a byte of it changing must invalidate it."""
    payload = json.loads(cli_workspace.scope_path.read_text(encoding="utf-8"))
    payload["authorized_by"] = "somebody-else"
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(
        app, ["scope", "verify", str(edited), "--public-key", str(cli_workspace.public_key)]
    )
    assert result.exit_code != 0


def test_run_completes_and_writes_a_report(cli_workspace) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--objective",
            "Enumerate exposed services on lab-web-01.",
            "--skill",
            "port_scan",
            "--target",
            "lab-web-01",
            "--scope",
            str(cli_workspace.scope_path),
            "--public-key",
            str(cli_workspace.public_key),
            "--model-backend",
            "scripted",
            "--run-id",
            "run-cli-1",
        ],
    )
    assert result.exit_code == 0, result.stdout
    run_dir = runs_dir(cli_workspace) / "run-cli-1"
    assert (run_dir / "report.md").exists()
    assert (run_dir / "report.json").exists()
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["stats"]["findings"] >= 1


def test_run_emits_machine_readable_summary_with_json_flag(cli_workspace) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--objective", "Enumerate exposed services on lab-web-01.",
            "--skill", "port_scan",
            "--target", "lab-web-01",
            "--scope", str(cli_workspace.scope_path),
            "--public-key", str(cli_workspace.public_key),
            "--model-backend", "scripted",
            "--run-id", "run-cli-json",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["run_id"] == "run-cli-json"
    assert payload["status"] == "completed"


def test_run_refuses_a_scope_that_does_not_verify(cli_workspace, tmp_path: Path) -> None:
    """No valid signature means the process stops before the model is ever called."""
    payload = json.loads(cli_workspace.scope_path.read_text(encoding="utf-8"))
    payload["networks"] = [{"cidr": "10.0.0.0/8", "include": ["10.99.0.5"]}]
    payload["aliases"] = {"lab-web-01": "net:10.99.0.5"}
    widened = tmp_path / "widened.json"
    widened.write_text(json.dumps(payload), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "run",
            "--objective", "Enumerate exposed services on lab-web-01.",
            "--skill", "port_scan",
            "--target", "lab-web-01",
            "--scope", str(widened),
            "--public-key", str(cli_workspace.public_key),
            "--model-backend", "scripted",
            "--run-id", "run-cli-widened",
        ],
    )
    assert result.exit_code != 0
    # Nothing was executed, so nothing can have been scanned.
    assert not (runs_dir(cli_workspace) / "run-cli-widened" / "executions.jsonl").exists()


def test_replay_command_verifies_a_good_run(cli_workspace) -> None:
    run = runner.invoke(
        app,
        [
            "run", "--objective", "Enumerate exposed services on lab-web-01.",
            "--skill", "port_scan", "--target", "lab-web-01",
            "--scope", str(cli_workspace.scope_path),
            "--public-key", str(cli_workspace.public_key),
            "--model-backend", "scripted", "--run-id", "run-cli-replay",
        ],
    )
    assert run.exit_code == 0, run.stdout
    result = runner.invoke(app, ["replay", str(runs_dir(cli_workspace) / "run-cli-replay")])
    assert result.exit_code == 0, result.stdout
    assert "verified=True" in result.stdout.replace(" ", "")


def test_replay_command_fails_nonzero_on_a_broken_chain(cli_workspace) -> None:
    run = runner.invoke(
        app,
        [
            "run", "--objective", "Enumerate exposed services on lab-web-01.",
            "--skill", "port_scan", "--target", "lab-web-01",
            "--scope", str(cli_workspace.scope_path),
            "--public-key", str(cli_workspace.public_key),
            "--model-backend", "scripted", "--run-id", "run-cli-broken",
        ],
    )
    assert run.exit_code == 0, run.stdout
    run_dir = runs_dir(cli_workspace) / "run-cli-broken"
    lines = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    lines.pop(2)
    (run_dir / "events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["replay", str(run_dir)])
    assert result.exit_code == 1


def test_verify_reports_a_dangling_reference_from_the_command_line(recorded_run_dir: Path, tmp_path: Path) -> None:
    """K2: the reference audit had no operator path - `audit_run_dir` was callable only from code."""
    run = tmp_path / "run"
    shutil.copytree(recorded_run_dir, run)

    clean = runner.invoke(app, ["verify", str(run)])
    assert clean.exit_code == 0, clean.stdout

    executions = json.loads((run / "executions.json").read_text(encoding="utf-8"))
    executions[0]["necessity_decision"] = "d-fabricated"
    (run / "executions.json").write_text(json.dumps(executions), encoding="utf-8")

    broken = runner.invoke(app, ["verify", str(run)])
    assert broken.exit_code == 1, broken.stdout
    assert "d-fabricated" in broken.stdout
    assert "execution_necessity_decision_missing" in broken.stdout

    as_json = runner.invoke(app, ["verify", str(run), "--json"])
    assert as_json.exit_code == 1
    assert json.loads(as_json.stdout)["issues"][0]["code"] == "execution_necessity_decision_missing"
