"""The report must be derivable from the run directory alone, and it must re-verify."""

from __future__ import annotations

from pathlib import Path

from harness.artifacts import ArtifactStore
from harness.events import EventLog
from harness.models import (
    Budget,
    Claim,
    EvidenceGap,
    Finding,
    MemoryDigests,
    ModelMetadata,
    Observation,
    ProviderDecision,
    RunConfig,
)
from harness.report.build import build_report, severity_for, write_report
from harness.util import append_jsonl, atomic_write_json, new_id, utcnow


def _build_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "runs" / "run-report"
    run_dir.mkdir(parents=True)
    run_id = "run-report"

    events = EventLog(run_dir / "events.jsonl", run_id)
    events.append("RUN_STARTED", {"objective": "scan lab-web-01", "skill": "port_scan"})
    events.append("MEMORY_RETRIEVED", {"entries": ["mem-1"], "kinds": ["tool_behavior"]})

    store = ArtifactStore(run_dir, run_id)
    meta = store.put_text(
        'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\n',
        media_type="application/nmap+xml",
        producer="native:synthetic",
    )
    ref = store.ref(meta.digest, byte_start=0, byte_end=meta.byte_length, locator="line 1")

    observation = Observation(
        id="o-1",
        run_id=run_id,
        kind="service",
        value={"target": "lab-web-01", "port": 22, "product": "OpenSSH", "version": "8.2p1"},
        parser="nmap_xml",
        parser_version="0.1.0",
        provider="native:synthetic",
        execution_id="x-1",
        trust_class="local_tool",
        taint="T3",
        evidence=[ref],
    )
    claim = Claim(
        id="c-1",
        statement="OpenSSH 8.2p1 is exposed on lab-web-01 port 22.",
        assertion="observed",
        supports=[observation.id],
        confidence="observed",
        confidence_basis="parser output from an immutable artifact",
    )
    finding = Finding(
        id="f-1",
        run_id=run_id,
        title="Exposed SSH service with a vulnerable OpenSSH version",
        status="possible",
        severity="critical",
        claims=[claim],
        cve=["CVE-2023-38408"],
        cpe=["cpe:/a:openbsd:openssh:8.2p1"],
        skill="port_scan",
    )
    gap = EvidenceGap(
        id="g-1",
        run_id=run_id,
        kind="partial_coverage",
        impact="http.probe was refused because no provider can serve it",
        capability="http.probe",
    )
    decision = ProviderDecision(
        id="d-1",
        capability="service.enumerate",
        verdict="single",
        selected=["native:synthetic"],
        considered=["native:synthetic", "native:nmap"],
        rejected={"native:nmap": "higher rank: available but not minimum-sufficient"},
        reason="one provider closes the need",
    )

    config = RunConfig(
        run_id=run_id,
        objective="scan lab-web-01",
        skill="port_scan",
        scope_id="lab-2026-09",
        scope_sha256="a" * 64,
        model=ModelMetadata(backend="scripted", model_id="scripted-planner"),
        budgets=Budget(),
        memory=MemoryDigests(baseline_sha256="b" * 64, active_sha256="c" * 64),
        harness_version="0.1.0",
        created_at=utcnow(),
    )

    atomic_write_json(run_dir / "run.json", {**config.model_dump(mode="json"), "status": "completed"})
    append_jsonl(run_dir / "observations.jsonl", observation.model_dump(mode="json"))
    atomic_write_json(run_dir / "findings.json", [finding.model_dump(mode="json")])
    append_jsonl(run_dir / "gaps.jsonl", gap.model_dump(mode="json"))
    append_jsonl(run_dir / "provider-decisions.jsonl", decision.model_dump(mode="json"))
    append_jsonl(
        run_dir / "trace.jsonl",
        {"step": 1, "model_id": "scripted-planner", "tokenizer_id": "heuristic", "input_tokens": 900, "output_tokens": 120},
    )
    append_jsonl(
        run_dir / "provenance.jsonl",
        {
            "subject": "p-1",
            "relation": "refused",
            "object": "http.probe",
            "extra": {"capability": "http.probe", "grant": "g-1", "reason": "no provider"},
        },
    )
    events.append("RUN_ENDED", {"status": "completed", "steps": 1, "findings": 1, "gaps": 1})
    atomic_write_json(run_dir / "claims.jsonl", [])
    return run_dir


def test_report_is_built_from_the_run_directory(tmp_path) -> None:
    run_dir = _build_run_dir(tmp_path)
    markdown, machine = build_report(run_dir=run_dir)
    assert "Investigation report" in markdown
    assert "CVE-2023-38408" in markdown
    assert machine["stats"]["findings"] == 1
    assert machine["stats"]["prompt_tokens"] == 900


def test_report_reruns_the_integrity_checks(tmp_path) -> None:
    run_dir = _build_run_dir(tmp_path)
    _, machine = build_report(run_dir=run_dir)
    integrity = machine["integrity"]
    assert integrity["chain_verified"] is True
    assert integrity["evidence_refs"] == 1
    assert integrity["artifact_count"] == 1
    assert not integrity["problems"]
    assert "f-1" in integrity["finding_digests"]


def test_report_detects_a_tampered_artifact(tmp_path) -> None:
    """If the bytes change, the quoted span no longer recomputes and the report must say so."""
    run_dir = _build_run_dir(tmp_path)
    target = [p for p in (run_dir / "artifacts").rglob("*") if p.is_file() and not p.name.endswith(".json")][0]
    target.write_bytes(b"tampered payload bytes that are a different length")
    _, machine = build_report(run_dir=run_dir)
    assert machine["integrity"]["problems"]


def test_write_report_creates_both_files(tmp_path) -> None:
    run_dir = _build_run_dir(tmp_path)
    md_path, json_path = write_report(run_dir=run_dir)
    assert md_path.exists() and json_path.exists()
    assert "Investigation report" in md_path.read_text(encoding="utf-8")


def test_severity_comes_from_a_fixed_rubric() -> None:
    assert severity_for(9.8) == "critical"
    assert severity_for(7.0) == "high"
    assert severity_for(4.1) == "medium"
    assert severity_for(0.2) == "low"
    assert severity_for(0.0) == "info"


def test_a_provider_conflict_is_surfaced_rather_than_hidden(tmp_path) -> None:
    """Success criterion: the report exposes agreement and conflict instead of choosing a side."""
    run_dir = _build_run_dir(tmp_path)
    append_jsonl(
        run_dir / "correlations.jsonl",
        {
            "id": "cor-1",
            "run_id": "run-report",
            "key": "service|lab-web-01|22|tcp",
            "observation_ids": ["o-1", "o-2"],
            "relation": "conflict",
            "detail": "providers disagree on version: 8.2p1 vs 9.3p2",
        },
    )
    markdown, machine = build_report(run_dir=run_dir)
    assert "Cross-provider reconciliation" in markdown
    assert "conflict" in markdown
    assert "8.2p1 vs 9.3p2" in markdown
    assert machine["correlations"][0]["relation"] == "conflict"


def test_a_run_with_no_correlations_says_so(tmp_path) -> None:
    run_dir = _build_run_dir(tmp_path)
    markdown, _ = build_report(run_dir=run_dir)
    assert "nothing to reconcile" in markdown
