"""Report rendering from recorded run state.

The report reads only what the run wrote to disk. That is the point: a report generated from
in-memory objects could describe a run that did not happen, whereas this one can be regenerated
from an archived directory months later and produce the same document.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from harness.artifacts import ArtifactStore
from harness.models import Finding, Observation
from harness.util import atomic_write_json, atomic_write_text, read_json, read_jsonl, sha256_json, utcnow

TEMPLATES = Path(__file__).parent / "templates"

#: Severity never comes from model prose (decision D6). The rubric maps a CVSS score to a fixed
#: band so that two runs matching the same CVE cannot disagree about how bad it is.
SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def severity_for(cvss: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if cvss >= threshold:
            return label
    return "info"


def build_report(*, run_dir: Path) -> tuple[str, dict[str, Any]]:
    run_dir = Path(run_dir)
    run = read_json(run_dir / "run.json")
    summary_events = read_jsonl(run_dir / "events.jsonl")
    observations = read_jsonl(run_dir / "observations.jsonl")
    findings_raw = read_json(run_dir / "findings.json") if (run_dir / "findings.json").exists() else []
    gaps = read_jsonl(run_dir / "gaps.jsonl")
    decisions = read_jsonl(run_dir / "provider-decisions.jsonl")
    ledger = read_jsonl(run_dir / "trace.jsonl")
    executions = read_jsonl(run_dir / "executions.jsonl")

    provenance = read_jsonl(run_dir / "provenance.jsonl")
    refusals = [
        triple["extra"]
        for triple in provenance
        if triple.get("relation") == "refused" and isinstance(triple.get("extra"), dict)
    ]

    ended = next((e for e in reversed(summary_events) if e.get("type") == "RUN_ENDED"), {})
    started = next((e for e in summary_events if e.get("type") == "RUN_STARTED"), {})
    retrieved_event = next((e for e in summary_events if e.get("type") == "MEMORY_RETRIEVED"), {})
    retrieved_ids = ((retrieved_event.get("data") or {}).get("entries") or [])
    retrieved_kinds = ((retrieved_event.get("data") or {}).get("kinds") or [])

    stats = {
        "steps": len(ledger),
        "provider_calls": len(executions),
        "findings": len(findings_raw),
        "gaps": len(gaps),
        "observations": len(observations),
        "prompt_tokens": sum(int(e.get("input_tokens", 0)) for e in ledger),
        "completion_tokens": sum(int(e.get("output_tokens", 0)) for e in ledger),
        "calls_skipped": sum(1 for e in summary_events if e.get("type") == "CALL_SKIPPED"),
        "expansions": sum(1 for e in summary_events if e.get("type") == "PROVIDER_EXPANSION"),
        "provider_rejections": sum(1 for e in summary_events if e.get("type") == "PROVIDER_REJECTED"),
    }

    integrity = _integrity(run_dir, run, observations, findings_raw, summary_events)

    findings_view = []
    for raw in findings_raw:
        finding = Finding.model_validate(raw)
        refs: list[Any] = []
        for observation_id in finding.observation_ids():
            match = next((o for o in observations if o.get("id") == observation_id), None)
            if match:
                refs.extend(Observation.model_validate(match).evidence)
        findings_view.append({"finding": finding, "evidence": refs})

    context = {
        "run": {
            **run,
            "status": (ended.get("data") or {}).get("status", "unknown"),
            "started_at": started.get("at", ""),
            "ended_at": ended.get("at", ""),
            "remote_egress": bool(run.get("enable_remote_egress")),
        },
        "stats": stats,
        "findings": [{"id": v["finding"].id, **v["finding"].model_dump(mode="json"), "evidence": v["evidence"]} for v in findings_view],
        "gaps": gaps,
        "decisions": decisions,
        "refusals": refusals,
        "retrieved": [
            {"id": entry_id, "kind": kind}
            for entry_id, kind in zip(retrieved_ids, retrieved_kinds + [""] * len(retrieved_ids))
        ],
        "integrity": integrity,
    }

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    markdown = env.get_template("report.md.j2").render(**context)

    machine = {
        "run_id": run.get("run_id"),
        "objective": run.get("objective"),
        "skill": run.get("skill"),
        "status": context["run"]["status"],
        "stats": stats,
        "findings": findings_raw,
        "gaps": gaps,
        "provider_decisions": decisions,
        "refusals": refusals,
        "integrity": integrity,
        "generated_at": utcnow().isoformat(),
    }
    return markdown, machine


def _integrity(
    run_dir: Path,
    run: dict[str, Any],
    observations: list[dict[str, Any]],
    findings_raw: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Re-derive the tamper-evident claims rather than restating them."""
    from harness.events import EventLog

    problems: list[str] = []
    run_id = str(run.get("run_id") or run_dir.name)
    try:
        EventLog(run_dir / "events.jsonl", run_id).verify_chain()
        chain_ok = True
    except Exception as exc:  # noqa: BLE001
        chain_ok = False
        problems.append(f"event chain did not verify: {exc}")

    store = ArtifactStore(run_dir, run_id)
    refs_checked = 0
    artifacts_dir = run_dir / "artifacts"
    if artifacts_dir.is_dir():
        for path in sorted(artifacts_dir.rglob("*")):
            if not path.is_file() or path.name.endswith(".meta.json"):
                continue
            if not store.verify_digest(f"sha256:{path.name}"):
                problems.append(f"artifact {path.name[:19]} does not hash to its address")
    for raw in observations:
        try:
            observation = Observation.model_validate(raw)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"observation {raw.get('id')} is unreadable: {exc}")
            continue
        for ref in observation.evidence:
            refs_checked += 1
            if not store.exists(ref.artifact):
                problems.append(f"observation {observation.id} cites a missing artifact")
            elif not store.verify_ref(ref):
                problems.append(f"observation {observation.id} has a span that does not recompute")

    digests = {
        str(raw.get("id")): sha256_json(raw)
        for raw in findings_raw
    }
    artifacts = len(list((run_dir / "artifacts").rglob("*.meta.json"))) if (run_dir / "artifacts").exists() else 0
    return {
        "chain_verified": chain_ok,
        "event_count": len(events),
        "artifact_count": artifacts,
        "evidence_refs": refs_checked,
        "finding_digests": digests,
        "problems": problems,
    }


def write_report(*, run_dir: Path) -> tuple[Path, Path]:
    markdown, machine = build_report(run_dir=run_dir)
    run_dir = Path(run_dir)
    md_path = run_dir / "report.md"
    json_path = run_dir / "report.json"
    atomic_write_json(json_path, machine)
    atomic_write_text(md_path, markdown)
    return md_path, json_path
