"""Scenario runner: execute the harness CLI once per scenario and score the result.

Two decisions shape this module.

**The CLI is a subprocess, addressed as an argv list.** The runner never imports the CLI and never
builds a shell string. That keeps the evaluator independent of the code under test (an evaluator
that imports its subject cannot report that the subject fails to start), and it means no scenario
name, objective or path can ever be reinterpreted by a shell. ``--entrypoint`` takes one or more
argv tokens, so pointing the evaluation at a different binary is a flag rather than an edit.

**A run that could not happen is reported as such.** Each scenario is invoked as
``<entrypoint> <args...>`` and expected to write its run directory where ``--out`` asked for it.
If the process fails, or writes nothing, the scenario is recorded with that status and its metrics
are computed from whatever *was* recorded - missing inputs surface as ``not_measured`` instead of
being quietly dropped from the table.

Usage::

    python -m eval.runner --dry-run                  # print the commands, execute nothing
    python -m eval.runner                            # run every scenario, write the metrics table
    python -m eval.runner --scenario port_scan       # one scenario
    python -m eval.runner --entrypoint .venv/bin/harness
    python -m eval.runner --entrypoint python -m harness.cli   # tokens, not a shell string
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from eval import REPO_ROOT
from eval.replay_pass import augment_replay_json
from eval.metrics import (
    METRIC_NAMES,
    GroundTruth,
    Metric,
    compute_metrics,
    load_ground_truth,
    load_run_bundle,
    metrics_document,
    render_table,
)
from harness.util import atomic_write_json, atomic_write_text

DEFAULT_SCENARIOS_DIR = REPO_ROOT / "eval" / "scenarios"
DEFAULT_RESULTS_DIR = REPO_ROOT / "eval" / "results"
DEFAULT_GROUND_TRUTH = REPO_ROOT / "eval" / "ground_truth.json"

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


class ScenarioError(ValueError):
    """A scenario file is malformed or references ground truth that does not exist."""


# ----------------------------------------------------------------------------------------------
# Scenarios
# ----------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    """One declarative evaluation scenario, as authored in ``eval/scenarios/*.json``."""

    path: Path
    scenario_id: str
    title: str
    skill: str
    objective: str
    scope_path: str
    aliases: tuple[str, ...]
    run_id: str
    args: tuple[str, ...]
    metrics: tuple[str, ...]
    expected_outcome: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def load_scenario(path: Path) -> Scenario:
    """Load and validate one scenario file.

    Validation is strict because a scenario is authored configuration: a typo in a metric name or
    a missing objective would otherwise turn into a silently unmeasured run.
    """
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScenarioError(f"{path}: scenario must be a JSON object")

    for key in ("scenario_id", "skill", "objective", "scope", "invocation", "metrics"):
        if key not in data:
            raise ScenarioError(f"{path}: missing required key {key!r}")

    scope = data["scope"] or {}
    if not isinstance(scope, dict) or not scope.get("path"):
        raise ScenarioError(f"{path}: scope.path is required")
    aliases = tuple(str(alias) for alias in scope.get("aliases") or ())
    if not aliases:
        raise ScenarioError(f"{path}: scope.aliases must name at least one granted alias")

    invocation = data["invocation"] or {}
    args = invocation.get("args")
    if not isinstance(args, list) or not args or not all(isinstance(item, str) for item in args):
        raise ScenarioError(f"{path}: invocation.args must be a non-empty list of argv tokens")
    run_id = str(invocation.get("run_id") or data["scenario_id"])

    metrics = data["metrics"]
    if not isinstance(metrics, list) or not metrics:
        raise ScenarioError(f"{path}: metrics must be a non-empty list")
    unknown = [str(name) for name in metrics if str(name) not in METRIC_NAMES]
    if unknown:
        raise ScenarioError(f"{path}: unknown metric(s) {unknown}; known metrics: {list(METRIC_NAMES)}")

    expected = data.get("expected_outcome") or {}
    if not isinstance(expected, dict):
        raise ScenarioError(f"{path}: expected_outcome must be an object")

    return Scenario(
        path=path,
        scenario_id=str(data["scenario_id"]),
        title=str(data.get("title") or data["scenario_id"]),
        skill=str(data["skill"]),
        objective=str(data["objective"]),
        scope_path=str(scope["path"]),
        aliases=aliases,
        run_id=run_id,
        args=tuple(args),
        metrics=tuple(str(name) for name in metrics),
        expected_outcome=dict(expected),
        raw=dict(data),
    )


def load_scenarios(scenarios_dir: Path) -> list[Scenario]:
    """Load every scenario in a directory, in filename order for reproducible output."""
    paths = sorted(Path(scenarios_dir).glob("*.json"))
    if not paths:
        raise ScenarioError(f"no scenario files found in {scenarios_dir}")
    scenarios = [load_scenario(path) for path in paths]
    seen: set[str] = set()
    for scenario in scenarios:
        if scenario.scenario_id in seen:
            raise ScenarioError(f"duplicate scenario_id {scenario.scenario_id!r} in {scenarios_dir}")
        seen.add(scenario.scenario_id)
    return scenarios


def validate_scenario_references(scenarios: Sequence[Scenario], truth: GroundTruth) -> list[str]:
    """Return the cross-reference problems between scenarios and ground truth.

    Scenarios and ground truth are edited by different people at different times; the failure mode
    that matters is a scenario citing a ground-truth id that was renamed or deleted, which would
    otherwise show up as an unexplained recall drop long after the fact.
    """
    problems: list[str] = []
    expectation_ids = {str(item.get("id")) for item in truth.expectations}
    control_ids = {str(item.get("id")) for item in truth.controls}
    covered_expectations: set[str] = set()
    covered_controls: set[str] = set()
    covered_metrics: set[str] = set()

    for scenario in scenarios:
        expected = scenario.expected_outcome
        for gt_id in expected.get("ground_truth_required") or ():
            if str(gt_id) not in expectation_ids:
                problems.append(f"{scenario.scenario_id}: unknown ground-truth finding {gt_id!r}")
            covered_expectations.add(str(gt_id))
        for control_id in expected.get("control_entries_checked") or ():
            if str(control_id) not in control_ids:
                problems.append(f"{scenario.scenario_id}: unknown control entry {control_id!r}")
            covered_controls.add(str(control_id))
        covered_metrics.update(scenario.metrics)

    for missing in sorted(expectation_ids - covered_expectations):
        problems.append(f"ground truth finding {missing} is not required by any scenario")
    for missing in sorted(control_ids - covered_controls):
        problems.append(f"control entry {missing} is not checked by any scenario")
    for missing in sorted(set(METRIC_NAMES) - covered_metrics):
        problems.append(f"metric {missing} is not fed by any scenario")
    return problems


# ----------------------------------------------------------------------------------------------
# Command construction
# ----------------------------------------------------------------------------------------------


def expand_arguments(args: Sequence[str], context: dict[str, str]) -> list[str]:
    """Substitute ``{placeholder}`` tokens in scenario arguments.

    Substitution is done here rather than by ``str.format`` so an unknown or misspelled placeholder
    is a loud error: silently keeping ``{scop_path}`` would pass a literal brace sequence to the
    CLI and fail somewhere less useful.
    """

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in context:
            raise ScenarioError(
                f"unknown placeholder {{{name}}}; available: {', '.join(sorted(context))}"
            )
        return context[name]

    return [_PLACEHOLDER.sub(_replace, token) for token in args]


def default_entrypoint(repo_root: Path) -> list[str]:
    """The installed CLI when present, otherwise the module form.

    Both are returned as argv tokens, so callers treat the entry point as a list and never as a
    string to be interpreted by a shell.
    """
    console = Path(repo_root) / ".venv" / "bin" / "harness"
    if console.is_file():
        return [str(console)]
    return [sys.executable, "-m", "harness.cli"]


def build_command(
    scenario: Scenario,
    *,
    entrypoint: Sequence[str],
    repo_root: Path,
    run_dir: Path,
    ground_truth_path: Path,
    scope_override: Path | None = None,
    public_key: Path | None = None,
) -> list[str]:
    """The full argv for one scenario: entry point tokens followed by the scenario arguments."""
    context = {
        "scenario_id": scenario.scenario_id,
        "skill": scenario.skill,
        "objective": scenario.objective,
        "scope_path": str(_resolve_scope(repo_root, scenario, scope_override)),
        # The trust anchor travels with the command: a run refuses to start without one, because
        # verifying a record against the key it carries proves only that it is self-consistent
        # (R2-06).
        "public_key": str(_resolve_public_key(public_key)),
        "run_id": scenario.run_id,
        "run_dir": str(Path(run_dir)),
        "aliases": ",".join(scenario.aliases),
        "repo_root": str(repo_root),
        "ground_truth": str(ground_truth_path),
    }
    return [*entrypoint, *expand_arguments(scenario.args, context)]


def _subprocess_env(repo_root: Path) -> dict[str, str]:
    """Environment for the child CLI: `src` on the path so a bare checkout works uninstalled."""
    env = os.environ.copy()
    src = str((Path(repo_root) / "src").resolve())
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = f"{src}{os.pathsep}{existing}" if existing else src
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _resolve_public_key(override: Path | None) -> Path:
    """The Ed25519 public key the scope record must verify against.

    Defaulted to the location ``make scope`` writes, because a run without an anchor is refused: the
    key embedded in the record proves the record agrees with itself, not that the operator signed it
    (R2-06).
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "security-agent-harness" / "scope_ed25519_public.pem"


def _resolve_scope(repo_root: Path, scenario: Scenario, override: Path | None) -> Path:
    """The scope record a scenario should run under.

    A signed record is required, and the signing key deliberately lives outside the repository, so
    the scenarios stay declarative and the runner takes the signed path as an argument. Without an
    override the scenario's own path is used, which is what makes a scenario file readable on its
    own and what makes a missing record fail with a path rather than a mystery.
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    return (Path(repo_root) / scenario.scope_path).resolve()


# ----------------------------------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    scenario_id: str
    title: str
    skill: str
    run_dir: Path
    command: list[str]
    status: str
    returncode: int | None = None
    metrics: list[Metric] = field(default_factory=list)
    error: str | None = None

    def as_dict(self, *, truth: GroundTruth | None = None) -> dict[str, Any]:
        document = metrics_document(self.metrics, scenario_id=self.scenario_id, run_dir=self.run_dir)
        document.update(
            {
                "title": self.title,
                "skill": self.skill,
                "status": self.status,
                "returncode": self.returncode,
                "command": list(self.command),
                "error": self.error,
            }
        )
        if truth is not None:
            document["metric_targets"] = truth.raw.get("metric_targets") or {}
        return document


def run_scenario(
    scenario: Scenario,
    *,
    entrypoint: Sequence[str],
    repo_root: Path,
    results_dir: Path,
    ground_truth_path: Path,
    truth: GroundTruth,
    timeout_s: float,
    dry_run: bool,
    scope_override: Path | None = None,
    public_key: Path | None = None,
) -> ScenarioResult:
    """Run one scenario and score whatever it recorded."""
    scenario_dir = Path(results_dir) / scenario.scenario_id
    run_dir = scenario_dir / "run"
    command = build_command(
        scenario,
        entrypoint=entrypoint,
        repo_root=repo_root,
        run_dir=run_dir,
        ground_truth_path=ground_truth_path,
        scope_override=scope_override,
        public_key=public_key,
    )
    result = ScenarioResult(
        scenario_id=scenario.scenario_id,
        title=scenario.title,
        skill=scenario.skill,
        run_dir=run_dir,
        command=command,
        status="dry_run" if dry_run else "unknown",
    )
    if dry_run:
        return result

    # Checked before spawning: a missing scope record produces a one-line, actionable failure
    # instead of a CLI error log that a reader has to interpret.
    resolved_scope = _resolve_scope(repo_root, scenario, scope_override)
    if not resolved_scope.exists():
        result.status = "failed"
        result.error = (
            f"no scope record at {resolved_scope}; run 'make scope' to generate and sign one, "
            "or pass --scope with its location"
        )
        return result
    resolved_key = _resolve_public_key(public_key)
    if not resolved_key.exists():
        result.status = "failed"
        result.error = (
            f"no trust anchor at {resolved_key}; a run verifies the scope against the operator's "
            "public key, so pass --public-key with the one that signed the record"
        )
        return result

    scenario_dir.mkdir(parents=True, exist_ok=True)
    env = _subprocess_env(repo_root)
    try:
        completed = subprocess.run(  # noqa: S603 - argv list, no shell, no interpolation
            list(command),
            cwd=str(repo_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result.status = "failed"
        result.error = f"timed out after {timeout_s:g}s"
        atomic_write_text(scenario_dir / "stdout.log", "")
        atomic_write_text(scenario_dir / "stderr.log", result.error + "\n")
        return result
    except FileNotFoundError as exc:
        result.status = "failed"
        result.error = f"entry point not runnable: {exc}"
        return result

    atomic_write_text(scenario_dir / "stdout.log", completed.stdout or "")
    atomic_write_text(scenario_dir / "stderr.log", completed.stderr or "")
    result.returncode = completed.returncode

    if not run_dir.is_dir():
        result.status = "failed"
        result.error = (
            f"the CLI exited {completed.returncode} without creating {run_dir}; "
            "nothing could be scored"
        )
        return result

    # The replay pass runs before the metrics are computed, so replay fidelity is measured rather
    # than reported as not_measured. It re-derives findings from the run's own recorded
    # observations and writes them to replay-report.json; replay.json is left alone because it is
    # the model/provider trace that offline replay reads. A failure here must not lose the
    # scenario: the pass only adds a measurement, so it is recorded and the rest proceeds.
    try:
        replay_pass = augment_replay_json(run_dir)
        if replay_pass.problems:
            result.error = "; ".join(replay_pass.problems)
    except Exception as exc:  # noqa: BLE001 - a broken replay pass must not hide the run
        result.error = f"replay pass failed: {type(exc).__name__}: {exc}"

    bundle = load_run_bundle(run_dir)
    result.metrics = compute_metrics(
        bundle,
        truth,
        scenario.metrics,
        required_ids=scenario.expected_outcome.get("ground_truth_required") or None,
    )
    result.status = "completed" if completed.returncode == 0 else "failed"
    if completed.returncode != 0:
        result.error = f"the CLI exited {completed.returncode}; metrics were computed from the partial run"
    return result


# ----------------------------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------------------------


def write_results(results: Sequence[ScenarioResult], truth: GroundTruth, results_dir: Path) -> dict[str, Path]:
    """Write per-scenario metrics, a combined document, and the markdown table."""
    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    targets = truth.raw.get("metric_targets") or {}
    written: dict[str, Path] = {}

    for result in results:
        if result.status == "dry_run":
            continue
        path = results_dir / result.scenario_id / "metrics.json"
        atomic_write_json(path, result.as_dict(truth=truth))
        written[result.scenario_id] = path

    combined = {
        "ground_truth_id": truth.ground_truth_id,
        "metrics_available": list(METRIC_NAMES),
        "scenarios": [result.as_dict(truth=truth) for result in results],
    }
    combined_path = results_dir / "metrics.json"
    atomic_write_json(combined_path, combined)
    written["metrics.json"] = combined_path

    blocks: list[str] = []
    for result in results:
        blocks.append(f"### {result.scenario_id} - {result.title}")
        blocks.append("")
        status = f"status: **{result.status}**"
        if result.returncode is not None:
            status += f" (exit {result.returncode})"
        blocks.append(status)
        if result.error:
            blocks.append("")
            blocks.append(f"note: {result.error}")
        blocks.append("")
        if result.metrics:
            blocks.append(render_table(result.metrics, targets=targets))
        else:
            blocks.append("_no metrics: the run did not produce a scorable directory_")
        blocks.append("")
        blocks.append("```")
        blocks.append(" ".join(result.command))
        blocks.append("```")
        blocks.append("")

    markdown = "\n".join(blocks)
    markdown_path = results_dir / "metrics.md"
    atomic_write_text(markdown_path, markdown)
    written["metrics.md"] = markdown_path
    return written


# ----------------------------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m eval.runner",
        description="Run every evaluation scenario against the harness CLI and score the results.",
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT, help="repository root (default: %(default)s)")
    parser.add_argument("--scenarios-dir", type=Path, default=None, help="directory of scenario JSON files")
    parser.add_argument("--results-dir", type=Path, default=None, help="where run directories and metrics are written")
    parser.add_argument("--ground-truth", type=Path, default=None, help="ground-truth JSON (default: eval/ground_truth.json)")
    parser.add_argument(
        "--scope",
        type=Path,
        default=None,
        help=(
            "signed scope record to run every scenario under. The signing key lives outside the "
            "repository, so the signed record has to be supplied; 'make scope' writes one."
        ),
    )
    parser.add_argument(
        "--entrypoint",
        nargs="+",
        default=None,
        metavar="TOKEN",
        help="argv prefix used to invoke the CLI, given as separate tokens (default: .venv/bin/harness, else python -m harness.cli)",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=None,
        help=(
            "Ed25519 public key that signed the scope record; a run refuses to start without a "
            "trust anchor (default: the key `make scope` writes)"
        ),
    )
    parser.add_argument("--scenario", action="append", default=[], help="run only this scenario_id (repeatable)")
    parser.add_argument("--timeout", type=float, default=900.0, help="per-scenario wall-clock limit in seconds")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the exact argv for each scenario and execute nothing",
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="stop at the first scenario that does not complete (default: score the remaining scenarios too)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    scenarios_dir = Path(args.scenarios_dir) if args.scenarios_dir else repo_root / "eval" / "scenarios"
    results_dir = Path(args.results_dir) if args.results_dir else repo_root / "eval" / "results"
    ground_truth_path = Path(args.ground_truth) if args.ground_truth else repo_root / "eval" / "ground_truth.json"
    entrypoint = list(args.entrypoint) if args.entrypoint else default_entrypoint(repo_root)

    try:
        truth = load_ground_truth(ground_truth_path)
        scenarios = load_scenarios(scenarios_dir)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.scenario:
        wanted = set(args.scenario)
        scenarios = [scenario for scenario in scenarios if scenario.scenario_id in wanted]
        missing = wanted - {scenario.scenario_id for scenario in scenarios}
        if missing:
            print(f"error: unknown scenario(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 2

    problems = validate_scenario_references(scenarios, truth)
    if problems:
        # A scenario/ground-truth mismatch is a configuration error, and running anyway would
        # produce a table nobody could trust.
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2

    print(f"entry point: {' '.join(entrypoint)}")
    print(f"ground truth: {ground_truth_path}")
    print(f"scenarios: {', '.join(scenario.scenario_id for scenario in scenarios)}")
    print("")

    results: list[ScenarioResult] = []
    for scenario in scenarios:
        result = run_scenario(
            scenario,
            entrypoint=entrypoint,
            repo_root=repo_root,
            results_dir=results_dir,
            ground_truth_path=ground_truth_path,
            truth=truth,
            timeout_s=args.timeout,
            dry_run=args.dry_run,
            scope_override=args.scope,
            public_key=args.public_key,
        )
        results.append(result)
        print(f"[{result.status}] {scenario.scenario_id}")
        print("  " + " ".join(result.command))
        if result.error:
            print(f"  note: {result.error}")
        if args.stop_on_failure and result.status != "completed" and not args.dry_run:
            print(f"stopping after {scenario.scenario_id} (--stop-on-failure)")
            break

    if args.dry_run:
        print("\ndry run: nothing was executed and no metrics were written")
        return 0

    written = write_results(results, truth, results_dir)
    for result in results:
        if not result.metrics:
            continue
        print("")
        print(render_table(result.metrics, title=f"{result.scenario_id} - {result.title}", targets=truth.raw.get("metric_targets") or {}))

    failed = [result.scenario_id for result in results if result.status != "completed"]
    print("")
    print(f"metrics written to {written.get('metrics.md')}")
    if failed:
        print(f"scenarios that did not complete: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
