"""The provenance gate every finding passes before it can be reported.

This module is the enforcement point for the invariants in design 02 section 14 and the headline
success criterion of the whole project: *zero unsupported findings*. A finding is not rejected
because it is wrong - nothing here can know that - but because it is not defensible, and the
difference between the two is the entire point.

Four checks carry most of the weight:

1. every claim cites a current-run observation that actually exists;
2. every cited observation's evidence span recomputes from its artifact bytes;
3. a memory entry can never occupy the place where evidence is required;
4. a reported CVE is backed by an observation the harness's own matcher produced, so it entered the
   run through the snapshot rather than through a model's recollection or a remote server's
   assertion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from harness.models import Finding, Observation

#: The parser whose observations may carry a CVE match. The harness selects a parser from the
#: response's media type, so a provider payload cannot claim it - which is what makes this an
#: identity check rather than a hint. `native:cve_matcher` is the only producer registered on this
#: parser (see `harness.runtime.analysers`).
MATCHER_PARSER = "vulnerability_json"

#: The trust class that producer runs under. A remote service's observations are `local_mcp` or
#: `external_provider`; only a local tool the harness started itself may assert a CVE.
MATCHER_TRUST_CLASS = "local_tool"


@dataclass
class ValidationResult:
    ok: bool
    violations: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


def validate_finding(
    finding: Finding,
    *,
    observations: Mapping[str, Observation],
    store: object,
) -> ValidationResult:
    """Check one finding against the current-run provenance graph.

    ``store`` is duck-typed to ``verify_ref`` and ``exists`` so this can be exercised without a real
    artifact tree, but every production call passes the run's ArtifactStore.
    """
    violations: list[str] = []

    if not finding.claims:
        violations.append("finding has no claim; a finding without a claim is an assertion")

    cited: list[str] = []
    for claim in finding.claims:
        if claim.assertion != "llm_hypothesis" and not claim.supports:
            violations.append(
                f"claim {claim.id} is {claim.assertion} but cites no supporting observation"
            )
        for observation_id in claim.supports:
            cited.append(observation_id)
            if _looks_like_memory(observation_id):
                violations.append(
                    f"claim {claim.id} cites {observation_id!r}, which is a memory reference; "
                    "memory is context and can never be finding evidence"
                )

    for observation_id in dict.fromkeys(cited):
        observation = observations.get(observation_id)
        if observation is None:
            violations.append(
                f"{observation_id!r} is not a current-run observation; a claim cannot cite "
                "evidence from another run or from nowhere"
            )
            continue
        if not observation.evidence:
            violations.append(f"observation {observation_id} carries no evidence span")
            continue
        for ref in observation.evidence:
            if not _verifies(store, ref):
                violations.append(
                    f"observation {observation_id} cites {ref.artifact} bytes "
                    f"{ref.byte_start}:{ref.byte_end}, which does not recompute from the artifact"
                )

    for cve in finding.cve:
        if not _cve_is_evidenced(cve, cited, observations):
            violations.append(
                f"{cve} is reported without a matcher-produced observation behind it; a CVE that "
                "did not come from the recorded snapshot must not be reported"
            )

    return ValidationResult(ok=not violations, violations=violations)


def validate_all(
    findings: Sequence[Finding],
    *,
    observations: Mapping[str, Observation],
    store: object,
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into ``(accepted, rejected)``.

    Rejections are returned rather than dropped so the caller can log ``VALIDATION_FAILED`` for
    each one. A silently discarded finding would make the harness look cleaner than it is, and the
    rejection rate is itself a signal about prompt and prompt-contract quality.
    """
    accepted: list[Finding] = []
    rejected: list[Finding] = []
    for finding in findings:
        result = validate_finding(finding, observations=observations, store=store)
        if result.ok:
            accepted.append(finding)
        else:
            rejected.append(finding)
    return accepted, rejected


# -- helpers ----------------------------------------------------------------------------


def _looks_like_memory(reference: str) -> bool:
    return reference.startswith("mem-") or reference.startswith("memory:")


def _verifies(store: object, ref: object) -> bool:
    if not hasattr(store, "verify_ref"):
        return False
    try:
        return bool(store.verify_ref(ref))
    except Exception:  # noqa: BLE001 - a store that cannot answer is a failed check, not a crash
        return False


def _cve_is_evidenced(
    cve: str, cited: Sequence[str], observations: Mapping[str, Observation]
) -> bool:
    """A CVE is admissible only if the *matcher itself* recorded that exact CVE id.

    This is what makes "the model cannot author a CVE" checkable rather than aspirational. It used
    to check the cited observation's ``kind``, which is a string the *producer* supplies: a remote
    MCP payload declaring ``kind: vulnerability_match`` satisfied a gate whose entire purpose is to
    prove the match came from the digest-stamped snapshot, and a fabricated critical finding passed
    with zero violations (R2-01). The parser and the trust class are decided by the *harness* - the
    first from the media type it routed to a parser, the second from the provider it started - so
    they are the part of an observation a remote server cannot write.
    """
    for observation_id in cited:
        observation = observations.get(observation_id)
        if observation is None:
            continue
        if observation.kind != "vulnerability_match":
            continue
        if observation.parser != MATCHER_PARSER:
            continue
        if str(observation.trust_class) != MATCHER_TRUST_CLASS:
            continue
        if str((observation.value or {}).get("cve") or "") == cve:
            return True
    return False
