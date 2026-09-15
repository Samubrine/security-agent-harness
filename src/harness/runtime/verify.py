"""Referential integrity for a recorded run: audit invariant 6.

``ProviderExecution.necessity_decision`` and ``.policy_decision`` are required fields, but a
required field is not a *checked* reference: a v1 run serialised an execution citing
``d-fabricated`` without complaint. The consequence is that the report's chain of "was this call
necessary, and what authorised it?" is a claim rather than a proof.

This module re-derives that reference graph from a run's own bytes, and is deliberately paranoid
about its input:

* a file that is present but corrupt is reported, never silently replaced by its fallback - if
  ``observations.json`` is truncated to garbage the audit must not quietly read a stale or
  partial ``observations.jsonl`` and then pronounce the run clean;
* a record that will not reconstruct as a pydantic model is still checked for the invariants
  whose whole point is to catch bytes that bypassed validation (an ``expand`` decision with no
  reason cannot be constructed through the model validator, so a hit is byte-level tampering);
* ``audit_run_dir`` never raises. A read or parse failure is a ``ProvenanceIssue``, because the
  caller is an auditor aimed at a directory it does not trust.

The v1 fact the policy check depends on: ``policy-decisions.jsonl`` does not exist in a v1 run
directory. Policy decision ids are only recoverable from ``provenance.jsonl`` triples with
``relation == "governed_by"`` (``subject`` is the policy decision id, ``object`` the necessity
decision id). When that file is absent the check still runs against the derived ids and records a
warning, so the weaker check is visible instead of being mistaken for a strong one.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from pathlib import Path
from typing import Any, NamedTuple

from harness.models import (
    EvidenceGap,
    Finding,
    Grant,
    Observation,
    PolicyDecision,
    ProviderDecision,
    ProviderExecution,
    ProvenanceAudit,
    ProvenanceIssue,
)
from harness.util import read_json, read_jsonl

__all__ = ["audit_provenance", "audit_run_dir"]

#: The live provenance gate (``harness.findings.validate``) refuses a claim that cites a memory
#: reference. The audit has to use exactly the same test: a narrower rule here would let a
#: finding through the audit that the live validator would have rejected.
MEMORY_REFERENCE_PREFIXES = ("mem-", "memory:")

#: ``provenance.jsonl`` relation naming the policy decision that governed a necessity decision.
GOVERNED_BY = "governed_by"


def _issue(code: str, subject: str, detail: str, severity: str = "error") -> ProvenanceIssue:
    return ProvenanceIssue(code=code, subject=subject, detail=detail, severity=severity)  # type: ignore[arg-type]


def _brief(value: Any, limit: int = 240) -> str:
    """One-line, length-bounded rendering of a caught exception or a bad value.

    Tampered bytes are untrusted: a parse error that embeds a whole file would turn the audit
    report into a second copy of the attacker's payload.
    """
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit] + "..."


def _attr(record: Any, name: str, default: Any) -> Any:
    """Read a field from a fully validated record or from a leniently built one.

    Records that failed validation are kept as raw field bags so the checks that only make sense
    *after* tampering can still run; they may be dicts, so attribute access alone is not enough.
    """
    value = record.get(name, default) if isinstance(record, dict) else getattr(record, name, default)
    return default if value is None else value


def _looks_like_memory(reference: Any) -> bool:
    """Memory is context and can never stand where evidence is required."""
    return isinstance(reference, str) and reference.startswith(MEMORY_REFERENCE_PREFIXES)


def _iter_claim_refs(finding: Any) -> Iterable[tuple[str, str]]:
    """Yield ``(claim_id, referenced_id)`` for every id a finding's claims cite.

    Both directions are checked: a claim that contradicts a non-existent observation is exactly as
    unfalsifiable as one that supports it.
    """
    claims = _attr(finding, "claims", [])
    if not isinstance(claims, list):
        return
    for index, claim in enumerate(claims):
        claim_id = _attr(claim, "id", f"claim#{index}")
        for field in ("supports", "contradicts"):
            refs = _attr(claim, field, [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                yield str(claim_id), ref


def _build_audit(
    *,
    run_id: str,
    executions: Sequence[ProviderExecution],
    decisions: Sequence[ProviderDecision],
    policy_decisions: Sequence[PolicyDecision],
    observations: Sequence[Observation],
    findings: Sequence[Finding],
    gaps: Sequence[EvidenceGap],
    grants: Sequence[Grant],
    known_policy_decision_ids: Collection[str],
    extra_issues: Sequence[ProvenanceIssue] = (),
    extra_checked: dict[str, int] | None = None,
) -> ProvenanceAudit:
    executions = list(executions)
    decisions = list(decisions)
    policy_decisions = list(policy_decisions)
    observations = list(observations)
    findings = list(findings)
    gaps = list(gaps)
    grants = list(grants)

    necessity_ids = {_attr(d, "id", "") for d in decisions}
    policy_ids = {_attr(p, "id", "") for p in policy_decisions} | set(known_policy_decision_ids)
    observation_ids = {_attr(o, "id", "") for o in observations}
    grant_ids = {_attr(g, "id", "") for g in grants}
    executions_by_id: dict[str, ProviderExecution] = {}
    for execution in executions:
        executions_by_id.setdefault(str(_attr(execution, "id", "")), execution)

    issues: list[ProvenanceIssue] = list(extra_issues)

    # Invariant 6 proper: every execution must name a necessity decision and a policy decision
    # that exist. A fabricated id is how an execution gets into a report without a reason.
    for execution in executions:
        execution_id = str(_attr(execution, "id", ""))
        if _attr(execution, "run_id", None) != run_id:
            issues.append(
                _issue(
                    "execution_run_id_mismatch",
                    execution_id,
                    f"execution run_id is {_attr(execution, 'run_id', None)!r}, expected {run_id!r}",
                )
            )
        if _attr(execution, "necessity_decision", None) not in necessity_ids:
            issues.append(
                _issue(
                    "execution_necessity_decision_missing",
                    execution_id,
                    f"necessity_decision {_attr(execution, 'necessity_decision', None)!r} is not the id "
                    "of any recorded provider decision",
                )
            )
        if _attr(execution, "policy_decision", None) not in policy_ids:
            issues.append(
                _issue(
                    "execution_policy_decision_missing",
                    execution_id,
                    f"policy_decision {_attr(execution, 'policy_decision', None)!r} is not a recorded "
                    "policy decision id",
                )
            )
        # Only meaningful when grants were supplied: an empty sequence means "scope was not read",
        # not "no grant exists", and accusing every execution of an unknown grant would be a lie.
        if grants and _attr(execution, "grant", None) not in grant_ids:
            issues.append(
                _issue(
                    "execution_grant_unknown",
                    execution_id,
                    f"grant {_attr(execution, 'grant', None)!r} is not among the supplied grants",
                )
            )

    for decision in decisions:
        decision_id = str(_attr(decision, "id", ""))
        if _attr(decision, "verdict", None) == "expand" and _attr(decision, "expansion_reason", None) is None:
            issues.append(
                _issue(
                    "decision_expand_without_reason",
                    decision_id,
                    "verdict is 'expand' with no expansion_reason; the model validator forbids this, "
                    "so the bytes were altered after they were written",
                )
            )
        satisfied_by = _attr(decision, "satisfied_by", [])
        if isinstance(satisfied_by, list):
            for observation_id in satisfied_by:
                if observation_id not in observation_ids:
                    issues.append(
                        _issue(
                            "decision_satisfied_by_unknown_observation",
                            decision_id,
                            f"satisfied_by cites {observation_id!r}, which is not a current-run "
                            "observation",
                        )
                    )

    for policy_decision in policy_decisions:
        execution_id = _attr(policy_decision, "execution_id", None)
        if execution_id is None:
            continue
        citing = executions_by_id.get(str(execution_id))
        if citing is None:
            reason = f"execution_id {execution_id!r} is not a recorded execution"
        elif _attr(citing, "policy_decision", None) != _attr(policy_decision, "id", None):
            reason = (
                f"execution {execution_id} cites policy_decision "
                f"{_attr(citing, 'policy_decision', None)!r} instead"
            )
        else:
            continue
        # A warning, not an error: the authorisation half of the pair is what invariant 6 pins
        # down. A one-way link is evidence of a wiring bug, not of an unbacked claim.
        issues.append(
            _issue(
                "policy_decision_execution_mismatch",
                str(_attr(policy_decision, "id", "")),
                reason,
                "warning",
            )
        )

    for observation in observations:
        if _attr(observation, "run_id", None) != run_id:
            issues.append(
                _issue(
                    "observation_run_id_mismatch",
                    str(_attr(observation, "id", "")),
                    f"observation run_id is {_attr(observation, 'run_id', None)!r}, expected {run_id!r}",
                )
            )

    for finding in findings:
        finding_id = str(_attr(finding, "id", ""))
        if _attr(finding, "run_id", None) != run_id:
            issues.append(
                _issue(
                    "finding_run_id_mismatch",
                    finding_id,
                    f"finding run_id is {_attr(finding, 'run_id', None)!r}, expected {run_id!r}",
                )
            )
        for claim_id, reference in _iter_claim_refs(finding):
            if reference in observation_ids or _looks_like_memory(reference):
                continue
            issues.append(
                _issue(
                    "finding_claim_observation_missing",
                    f"{finding_id}/{claim_id}",
                    f"claim cites {reference!r}, which is neither a current-run observation nor a "
                    "memory reference",
                )
            )

    # The same id twice is how one record impersonates another: lookups by id silently take the
    # first match, so a duplicate lets a green record shadow a red one.
    for kind, records in (
        ("execution", executions),
        ("provider decision", decisions),
        ("policy decision", policy_decisions),
        ("observation", observations),
        ("finding", findings),
        ("gap", gaps),
        ("grant", grants),
    ):
        counts = Counter(str(_attr(record, "id", "")) for record in records)
        for record_id, count in counts.items():
            if count > 1:
                issues.append(
                    _issue(
                        "duplicate_record_id",
                        record_id,
                        f"{count} {kind} records share the id {record_id!r}",
                    )
                )

    checked: dict[str, int] = {
        "executions": len(executions),
        "provider_decisions": len(decisions),
        "policy_decisions": len(policy_decisions),
        "known_policy_decision_ids": len(policy_ids),
        "observations": len(observations),
        "findings": len(findings),
        "gaps": len(gaps),
        "grants": len(grants),
    }
    if extra_checked:
        checked.update(extra_checked)

    # Dedupe then order: two identical findings about one broken reference are one problem, and a
    # stable order is what makes a stored audit comparable to a re-derived one.
    unique = {(i.code, i.subject, i.detail, i.severity): i for i in issues}
    ordered = sorted(unique.values(), key=lambda i: (i.code, i.subject, i.detail))
    checked["issues_error"] = sum(1 for i in ordered if i.severity == "error")
    checked["issues_warning"] = sum(1 for i in ordered if i.severity == "warning")
    return ProvenanceAudit(run_id=run_id, checked=checked, issues=ordered)


def audit_provenance(
    *,
    run_id: str,
    executions: Sequence[ProviderExecution],
    decisions: Sequence[ProviderDecision],
    policy_decisions: Sequence[PolicyDecision],
    observations: Sequence[Observation],
    findings: Sequence[Finding],
    gaps: Sequence[EvidenceGap] = (),
    grants: Sequence[Grant] = (),
    known_policy_decision_ids: Collection[str] = (),
) -> ProvenanceAudit:
    """Check that every reference an in-memory run graph makes resolves to a real record.

    ``known_policy_decision_ids`` exists because policy decision ids are not always available as
    records: v1 runs persist neither ``policy-decisions.jsonl`` nor the decision id on the
    ``POLICY_DECIDED`` event, so the ids have to be recovered out of band (see ``audit_run_dir``)
    and handed in here.
    """
    return _build_audit(
        run_id=run_id,
        executions=executions,
        decisions=decisions,
        policy_decisions=policy_decisions,
        observations=observations,
        findings=findings,
        gaps=gaps,
        grants=grants,
        known_policy_decision_ids=known_policy_decision_ids,
    )


class _RecordFile(NamedTuple):
    """One file of serialised records, plus the fields the checks need it to carry.

    ``needs`` is the gate for lenient reconstruction: a record whose bytes failed validation is
    only kept when every field a check reads is present, because a missing field would make the
    check invent an issue that the (already reported) parse failure is the real story for.
    """

    kind: str
    model: type[Any]
    needs: tuple[str, ...]
    canonical: str
    fallback: str | None = None
    #: False for a file a clean run is allowed not to write at all.
    required: bool = True


_RECORD_FILES: tuple[_RecordFile, ...] = (
    _RecordFile(
        "executions",
        ProviderExecution,
        ("id", "run_id", "necessity_decision", "policy_decision", "grant"),
        "executions.json",
        "executions.jsonl",
    ),
    _RecordFile(
        "provider_decisions",
        ProviderDecision,
        ("id", "verdict", "expansion_reason", "satisfied_by"),
        "provider-decisions.jsonl",
    ),
    _RecordFile("observations", Observation, ("id", "run_id"), "observations.json", "observations.jsonl"),
    _RecordFile("findings", Finding, ("id", "run_id", "claims"), "findings.json"),
    # ``gaps.jsonl`` is optional on purpose: a run that recorded no gap writes no file, which is
    # what ``eval/results/log_analysis/run`` looks like. Calling that run incomplete would be a
    # false accusation, and a false accusation is how an audit gets ignored.
    _RecordFile("gaps", EvidenceGap, ("id",), "gaps.jsonl", required=False),
)


def _read_json_value(path: Path, issues: list[ProvenanceIssue]) -> tuple[Any, bool]:
    """Parse one JSON/JSONL file, reporting - never raising - on unreadable bytes.

    The second element distinguishes "parsed to null/[]" from "could not be read", which the
    callers must not conflate: an unreadable scope is not an empty scope.
    """
    try:
        raw = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
    except Exception as exc:  # noqa: BLE001 - an auditor must survive arbitrary bytes
        issues.append(
            _issue(
                "run_dir_unreadable",
                path.name,
                f"file does not parse: {type(exc).__name__}: {_brief(exc)}",
            )
        )
        return None, False
    return raw, True


def _read_raw_records(path: Path, issues: list[ProvenanceIssue]) -> list[Any]:
    """Read a run file into a list of raw records, reporting on unreadable bytes."""
    raw, parsed = _read_json_value(path, issues)
    if not parsed:
        return []
    if not isinstance(raw, list):
        issues.append(
            _issue(
                "run_dir_unreadable",
                path.name,
                f"top-level JSON value is {type(raw).__name__}, expected a list of records",
            )
        )
        return []
    return raw


def _lenient_record(spec: _RecordFile, raw: dict[str, Any]) -> Any | None:
    """Rebuild a rejected record from raw fields so post-validation checks can still fire."""
    if any(name not in raw for name in spec.needs):
        return None
    return spec.model.model_construct(**{name: raw[name] for name in spec.needs})


def _load_records(path: Path, spec: _RecordFile, issues: list[ProvenanceIssue]) -> list[Any]:
    out: list[Any] = []
    for index, raw in enumerate(_read_raw_records(path, issues)):
        if not isinstance(raw, dict):
            issues.append(
                _issue("run_dir_unreadable", path.name, f"record {index} is {type(raw).__name__}, not an object")
            )
            continue
        try:
            out.append(spec.model.model_validate(raw))
            continue
        except Exception as exc:  # noqa: BLE001 - a malformed record is an issue, not a crash
            issues.append(
                _issue(
                    "run_dir_unreadable",
                    path.name,
                    f"record {index} does not reconstruct as {spec.model.__name__}: "
                    f"{type(exc).__name__}: {_brief(exc)}",
                )
            )
        lenient = _lenient_record(spec, raw)
        if lenient is not None:
            out.append(lenient)
    return out


def _locate(run_dir: Path, spec: _RecordFile) -> Path | None:
    """Prefer the canonical file; fall back only when the canonical name is *absent*.

    A present-but-corrupt canonical file is never shadowed by its fallback: an attacker who can
    truncate ``observations.json`` must not thereby choose which file the audit reads.
    """
    for name in (spec.canonical, spec.fallback):
        if name is None:
            continue
        candidate = run_dir / name
        if candidate.exists():
            return candidate
    return None


def _resolve_run_id(run_dir: Path, issues: list[ProvenanceIssue]) -> str:
    """Run identity comes from ``run.json``, then the directory name."""
    run_json = run_dir / "run.json"
    if run_json.exists():
        try:
            raw = read_json(run_json)
        except Exception as exc:  # noqa: BLE001
            issues.append(
                _issue("run_dir_unreadable", "run.json", f"file does not parse: {type(exc).__name__}: {_brief(exc)}")
            )
        else:
            if isinstance(raw, dict) and isinstance(raw.get("run_id"), str):
                return raw["run_id"]
            issues.append(
                _issue("run_dir_unreadable", "run.json", "no usable run_id field; using the directory name")
            )
    else:
        issues.append(_issue("run_dir_incomplete", "run.json", "run.json is absent; run_id taken from the directory name"))
    return run_dir.name


def _policy_ids_from_provenance(run_dir: Path, issues: list[ProvenanceIssue]) -> set[str]:
    """Recover policy decision ids from ``provenance.jsonl`` ``governed_by`` triples.

    This is the v1 fallback and the only reason the policy check can say anything at all today.
    The relation is directional: ``subject`` is the policy decision, ``object`` the necessity
    decision it governed. Reading it backwards would build a set of ids that nothing cites and
    silently pass every execution.
    """
    path = run_dir / "provenance.jsonl"
    if not path.exists():
        return set()
    found: set[str] = set()
    for index, triple in enumerate(_read_raw_records(path, issues)):
        if not isinstance(triple, dict):
            issues.append(
                _issue("run_dir_unreadable", path.name, f"triple {index} is {type(triple).__name__}, not an object")
            )
            continue
        if triple.get("relation") != GOVERNED_BY:
            continue
        subject = triple.get("subject")
        if isinstance(subject, str) and subject:
            found.add(subject)
        else:
            issues.append(
                _issue("run_dir_unreadable", path.name, f"governed_by triple {index} has no usable subject")
            )
    return found


def _policy_ids_from_events(run_dir: Path, issues: list[ProvenanceIssue]) -> set[str]:
    """Harvest ``policy_decision_id`` from ``POLICY_DECIDED`` events when v1.1 wrote it.

    v1 events do not carry the id, so its absence is normal and never an issue; when it is there
    it is one more id the policy check can accept.
    """
    path = run_dir / "events.jsonl"
    if not path.exists():
        return set()
    found: set[str] = set()
    for event in _read_raw_records(path, issues):
        if not isinstance(event, dict) or event.get("type") != "POLICY_DECIDED":
            continue
        data = event.get("data")
        if isinstance(data, dict) and isinstance(data.get("policy_decision_id"), str):
            found.add(data["policy_decision_id"])
    return found


def _load_grants(run_dir: Path, issues: list[ProvenanceIssue]) -> list[Grant]:
    """Grants live inside ``scope.json``; an unreadable scope is reported, not assumed empty."""
    path = run_dir / "scope.json"
    if not path.exists():
        issues.append(_issue("run_dir_incomplete", "scope.json", "scope.json is absent; grant references cannot be checked"))
        return []
    raw, parsed = _read_json_value(path, issues)
    if not parsed:
        return []
    if not isinstance(raw, dict):
        issues.append(_issue("run_dir_unreadable", "scope.json", f"scope is {type(raw).__name__}, not an object"))
        return []
    scope = raw
    grants_raw = scope.get("grants", [])
    if not isinstance(grants_raw, list):
        issues.append(_issue("run_dir_unreadable", "scope.json", "grants is not a list"))
        return []
    out: list[Grant] = []
    for index, entry in enumerate(grants_raw):
        if not isinstance(entry, dict):
            issues.append(_issue("run_dir_unreadable", "scope.json", f"grant {index} is not an object"))
            continue
        try:
            out.append(Grant.model_validate(entry))
        except Exception as exc:  # noqa: BLE001
            issues.append(
                _issue(
                    "run_dir_unreadable",
                    "scope.json",
                    f"grant {index} does not reconstruct as Grant: {type(exc).__name__}: {_brief(exc)}",
                )
            )
    return out


def audit_run_dir(run_dir: Path) -> ProvenanceAudit:
    """Re-derive a recorded run's reference graph from the run directory itself.

    Never raises: a nonexistent path, an empty directory, and a directory full of tampered bytes
    all produce a ``ProvenanceAudit`` whose issues say what could not be established.
    """
    run_dir = Path(run_dir)
    issues: list[ProvenanceIssue] = []
    checked_extra: dict[str, int] = {}

    run_id = _resolve_run_id(run_dir, issues)

    loaded: dict[str, list[Any]] = {}
    for spec in _RECORD_FILES:
        path = _locate(run_dir, spec)
        if path is None:
            loaded[spec.kind] = []
            if spec.required:
                issues.append(
                    _issue(
                        "run_dir_incomplete",
                        spec.canonical,
                        f"{spec.canonical} is absent"
                        + (f" and so is {spec.fallback}" if spec.fallback else ""),
                    )
                )
            continue
        loaded[spec.kind] = _load_records(path, spec, issues)

    # ``policy-decisions.jsonl`` is absent in v1, so its absence is not incompleteness. When it is
    # present it is authoritative and the derived ids are ignored, so a v1.1 run cannot have its
    # real policy records contradicted by a stray provenance triple.
    policy_path = run_dir / "policy-decisions.jsonl"
    if policy_path.exists():
        policy_decisions = _load_records(
            policy_path,
            _RecordFile("policy_decisions", PolicyDecision, ("id", "execution_id"), "policy-decisions.jsonl"),
            issues,
        )
        known_policy_ids: set[str] = set()
        checked_extra["policy_decision_ids_derived"] = 0
    else:
        policy_decisions = []
        known_policy_ids = _policy_ids_from_provenance(run_dir, issues)
        known_policy_ids |= _policy_ids_from_events(run_dir, issues)
        checked_extra["policy_decision_ids_derived"] = len(known_policy_ids)
        issues.append(
            _issue(
                "policy_decision_record_absent",
                "policy-decisions.jsonl",
                f"no policy-decisions.jsonl: {len(known_policy_ids)} policy decision ids recovered from "
                "provenance.jsonl governed_by triples; the check is weaker than a record-level one",
                "warning",
            )
        )

    return _build_audit(
        run_id=run_id,
        executions=loaded["executions"],
        decisions=loaded["provider_decisions"],
        policy_decisions=policy_decisions,
        observations=loaded["observations"],
        findings=loaded["findings"],
        gaps=loaded["gaps"],
        grants=_load_grants(run_dir, issues),
        known_policy_decision_ids=known_policy_ids,
        extra_issues=issues,
        extra_checked=checked_extra,
    )
