"""Assemble findings from claims, matcher candidates and correlations.

Two decisions are visible in this file and both are deliberate.

* **Status is not confidence.** A version match can be a certainty and still leave the finding at
  ``possible``: decision D9 reserves ``confirmed`` for evidence that satisfies a confirmation rule,
  which in this project means an observation of the thing itself (a payload that exists in an
  artifact) rather than an inference from a version. Nothing here promotes a finding because it
  looks convincing.
* **Severity is a rubric.** A finding's severity comes from the CVSS of the matched CVE or from a
  fixed per-class table stated below, never from a model's sense of how serious something sounds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from harness.analysers.cve_match import CveCandidate
from harness.models import Claim, Correlation, Finding, Observation
from harness.util import new_id, utcnow

#: Fixed severity per finding class, used when a CVSS score is not available. Stated as data so a
#: reviewer can disagree with the rubric in one place instead of hunting for judgement calls.
CLASS_SEVERITY: dict[str, str] = {
    "injection_attempt_observed": "medium",
    "auth_bruteforce": "high",
    "auth_success_after_burst": "high",
    "http_probe_campaign": "medium",
    "http_traversal_probe": "medium",
    "http_injection_probe": "high",
    "sensitive_path_probe": "low",
    "scanner_user_agent": "info",
    "entry_point_cross_source": "high",
}


@dataclass(frozen=True)
class _Class:
    """A finding class: a title, the rules that feed it, and the status they establish."""

    key: str
    title: str
    rules: tuple[str, ...]
    status: str
    narrative: str = ""


CLASSES: tuple[_Class, ...] = (
    _Class(
        key="injection_attempt_observed",
        title="Instruction-shaped content inside attacker-controlled data",
        rules=("injection_attempt_observed",),
        status="confirmed",
        narrative=(
            "A service or log payload contains text shaped like an instruction to the model. The "
            "payload is treated as an observation about its sender, never as a directive, and the "
            "harness's behaviour is unchanged by it. This is the one finding class whose status is "
            "confirmed without active verification, because the artefact is the payload itself."
        ),
    ),
    _Class(
        key="auth_bruteforce",
        title="Credential brute force against the authentication service",
        rules=("auth_bruteforce",),
        status="confirmed",
        narrative=(
            "Repeated authentication failures from one source are recorded directly in the log, so "
            "the burst is observed rather than inferred. Whether it succeeded is a separate finding."
        ),
    ),
    _Class(
        key="auth_success_after_burst",
        title="Successful authentication following a credential burst",
        rules=("auth_success_after_burst",),
        status="possible",
        narrative=(
            "A successful login follows a burst of failures from the same address. That ordering is "
            "consistent with a successful guess and equally consistent with a legitimate user behind "
            "the same address, so the finding stays possible and carries that caveat."
        ),
    ),
    _Class(
        key="http_probe_campaign",
        title="Automated reconnaissance against the web service",
        rules=(
            "http_probe_campaign",
            "http_traversal_probe",
            "http_injection_probe",
            "sensitive_path_probe",
            "scanner_user_agent",
        ),
        status="confirmed",
        narrative=(
            "The access log contains requests whose shape - traversal sequences, injection syntax, "
            "sensitive paths, self-declared scanners - shows deliberate probing. Response codes are "
            "recorded with each request, so a refusal is not reported as a compromise."
        ),
    ),
    _Class(
        key="entry_point_cross_source",
        title="Entry-point hypothesis supported by scan and log evidence",
        rules=("entry_point_cross_source",),
        status="possible",
        narrative=(
            "Two independent sources agree that an exposed service exists and that hostile activity "
            "reached the host. Co-occurrence is not exploitation: this is a hypothesis to test, and "
            "the harness deliberately did not test it."
        ),
    ),
)


def build_findings(
    *,
    run_id: str,
    observations: Sequence[Observation],
    claims: Sequence[Claim],
    candidates: Sequence[CveCandidate],
    correlations: Sequence[Correlation],
    skill: str,
) -> list[Finding]:
    by_rule: dict[str, list[Claim]] = {}
    for claim in claims:
        by_rule.setdefault(claim.rule_id or "", []).append(claim)

    conflict_note = _conflict_caveat(correlations)
    findings: list[Finding] = []
    consumed: set[str] = set()

    for klass in CLASSES:
        selected: list[Claim] = []
        for rule in klass.rules:
            for claim in by_rule.get(rule, []):
                selected.append(claim)
                consumed.add(claim.id)
        if not selected:
            continue
        if conflict_note:
            for claim in selected:
                claim.caveats.append(conflict_note)
        findings.append(
            Finding(
                id=new_id("f"),
                run_id=run_id,
                title=klass.title,
                status=klass.status,  # type: ignore[arg-type]
                severity=CLASS_SEVERITY.get(klass.key, "unknown"),  # type: ignore[arg-type]
                claims=selected,
                narrative=klass.narrative or None,
                skill=skill,
                created_at=utcnow(),
            )
        )

    findings.extend(_cve_findings(run_id, observations, by_rule, candidates, skill, consumed, conflict_note))
    return findings


def _cve_findings(
    run_id: str,
    observations: Sequence[Observation],
    by_rule: dict[str, list[Claim]],
    candidates: Sequence[CveCandidate],
    skill: str,
    consumed: set[str],
    conflict_note: str | None,
) -> list[Finding]:
    """One finding per version match, citing both the match and the service it was derived from.

    The match claim on its own says "this CVE applies to this version". Attaching the service claim
    as well is what makes the finding answer the next question a reader has: on which host, and on
    which port?

    The link between a candidate and its claims is made through observation ids, never through the
    text of a statement: a claim cites the observation it was built from, and the candidate names
    the observations it was built from, so the join is structural and cannot drift when wording
    changes.
    """
    claim_by_support: dict[str, Claim] = {}
    for rule in ("vulnerability_match_recorded", "service_exposed"):
        for claim in by_rule.get(rule, []):
            for observation_id in claim.supports:
                claim_by_support.setdefault(observation_id, claim)
    observation_by_id = {obs.id: obs for obs in observations}

    out: list[Finding] = []
    for candidate in candidates:
        ids = list(candidate.observation_ids)
        claim = claim_by_support.get(ids[0]) if ids else None
        if claim is None:
            # A candidate with no claim would be a finding with no rule behind it, which is exactly
            # the shape this design refuses to produce.
            continue
        attached = [claim]
        consumed.add(claim.id)
        for observation_id in ids[1:]:
            supporting = claim_by_support.get(observation_id)
            if supporting is not None and supporting.id not in {c.id for c in attached}:
                attached.append(supporting)
        if conflict_note:
            for item in attached:
                item.caveats.append(conflict_note)
        # The service observation is whichever cited observation is not the matcher's own record.
        observation = next(
            (
                observation_by_id[obs_id]
                for obs_id in ids
                if obs_id in observation_by_id and observation_by_id[obs_id].kind == "service"
            ),
            None,
        )
        location = ""
        if observation is not None:
            value = observation.value or {}
            location = f" on {value.get('target', 'unknown')} port {value.get('port', '?')}"
        out.append(
            Finding(
                id=new_id("f"),
                run_id=run_id,
                title=f"{candidate.product} {candidate.version} is inside the range of {candidate.cve}",
                status="possible",
                severity=candidate.severity,  # type: ignore[arg-type]
                cve=[candidate.cve],
                cpe=[candidate.cpe],
                claims=attached,
                narrative=(
                    f"The detected version{location} falls inside the recorded range for "
                    f"{candidate.cve} ({candidate.summary}). The match is a version comparison, not a "
                    "demonstration that the weakness is exploitable in this deployment, so the "
                    "finding stays possible until active verification runs."
                    if candidate.summary
                    else None
                ),
                skill=skill,
                created_at=utcnow(),
            )
        )
    return out


def _conflict_caveat(correlations: Sequence[Correlation]) -> str | None:
    conflicts = [c for c in correlations if c.relation == "conflict"]
    if not conflicts:
        return None
    keys = ", ".join(sorted({c.key for c in conflicts}))
    return (
        f"providers disagreed about {keys} in this run; the conflict is preserved in the run state "
        "rather than resolved by preference, so this finding may rest on the losing side of it"
    )


def unused_claims(claims: Sequence[Claim], findings: Sequence[Finding]) -> list[Claim]:
    """Claims that no finding cites. Useful for the evaluation harness and for spotting a rule that
    fires into the void."""
    used = {claim.id for finding in findings for claim in finding.claims}
    return [claim for claim in claims if claim.id not in used]
