"""Internal deterministic analysers exposed as ordinary providers.

``vulnerability.match`` is a capability the model may request, but it is not a network tool: it is
CPE normalisation plus offline version-range matching against a snapshot. Modelling it as a
provider anyway (rather than special-casing the loop) is what keeps the investigation loop free
of capability-specific branches, and it means the matching step is recorded, parsed and
evidenced exactly like any other call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

from harness.analysers.cve_match import VulnerabilitySnapshot, candidate_cves
from harness.models import (
    EvidenceGap,
    EvidenceRef,
    Observation,
    ProviderExecution,
    ProviderSpec,
)
from harness.providers.base import ProviderRequest, ProviderResult
from harness.util import canonical_json, new_id, utcnow

MEDIA_TYPE = "application/vnd.harness.vulnerability+json"
PARSER_NAME = "vulnerability_json"
PARSER_VERSION = "0.1.0"


@dataclass
class CveMatcherProvider:
    """Serves ``vulnerability.match`` from already-parsed observations.

    The observation source is injected as a callable instead of being passed through the request
    args, because request args are model-supplied and the model must never be able to choose
    which evidence the matcher reads.
    """

    snapshot: VulnerabilitySnapshot
    observations: Callable[[], Sequence[Observation]]
    min_cvss: float = 0.0

    @property
    def spec(self) -> ProviderSpec:
        return ProviderSpec(
            id="native:cve_matcher",
            kind="native",
            capabilities=["vulnerability.match"],
            input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            output_media_type=MEDIA_TYPE,
            parser=PARSER_NAME,
            risk="LOW",
            trust_class="local_tool",
            requires_network_egress=False,
            timeout_s=30,
            idempotent=True,
            description="Deterministic offline CPE/version matching against a snapshot-stamped database.",
        )

    def invoke(self, request: ProviderRequest) -> ProviderResult:
        observations = list(self.observations())
        candidates, gaps = candidate_cves(observations, self.snapshot, min_cvss=self.min_cvss)
        by_id = {obs.id: obs for obs in observations}
        payload = {
            "snapshot_id": getattr(self.snapshot, "snapshot_id", ""),
            "snapshot_digest": self.snapshot.digest,
            "candidates": [
                {
                    "cve": c.cve,
                    "cpe": c.cpe,
                    "product": c.product,
                    "version": c.version,
                    "cvss": c.cvss,
                    "severity": c.severity,
                    "summary": c.summary,
                    "matched_on": c.matched_on,
                    "observation_ids": list(c.observation_ids),
                    # A CVE match is a conclusion *about* a banner, so the proof travels with it:
                    # the parser attaches these spans verbatim rather than inventing new ones.
                    "source_refs": [
                        ref.model_dump(mode="json")
                        for obs_id in c.observation_ids
                        for ref in (by_id.get(obs_id).evidence if by_id.get(obs_id) else [])
                    ],
                }
                for c in candidates
            ],
        }
        return ProviderResult(
            provider=self.spec.id,
            capability=request.capability,
            exit_status="completed",
            stdout=canonical_json(payload).encode("utf-8"),
            media_type=MEDIA_TYPE,
            structured=payload,
            provider_version="snapshot:" + str(getattr(self.snapshot, "snapshot_id", "unknown")),
            gaps=list(gaps),
        )


def parse_vulnerability_json(
    data: bytes,
    *,
    execution: ProviderExecution,
    run_id: str,
    trust_class: str = "local_tool",
    artifact_digest: str | None = None,
    evidence_of: Callable[[int, int], list[EvidenceRef]] | None = None,
    **_: Any,
) -> Any:
    """Turn the matcher's structured output into evidence-backed observations.

    The evidence attached to a ``vulnerability_match`` is inherited from the service observation
    it was derived from. A CVE match is a conclusion *about* a banner, so its proof is the banner
    bytes, not a restatement of the conclusion.
    """
    import json

    from harness.parsers.registry import ParseResult

    try:
        payload = json.loads(data.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ParseResult(observations=[], gaps=[])

    observations: list[Observation] = []
    for candidate in payload.get("candidates") or []:
        value = {
            "cve": candidate.get("cve", ""),
            "cpe": candidate.get("cpe", ""),
            "product": candidate.get("product", ""),
            "version": candidate.get("version", ""),
            "cvss": candidate.get("cvss"),
            "severity": candidate.get("severity", ""),
            "summary": candidate.get("summary", ""),
            "matched_on": candidate.get("matched_on", ""),
            "snapshot_digest": payload.get("snapshot_digest", ""),
        }
        refs: list[EvidenceRef] = []
        for raw in candidate.get("source_refs") or []:
            try:
                refs.append(EvidenceRef.model_validate(raw))
            except Exception:  # noqa: BLE001 - a malformed ref must not become evidence
                continue
        observations.append(
            Observation(
                id=new_id("o"),
                run_id=run_id,
                kind="vulnerability_match",
                value=value,
                parser=PARSER_NAME,
                parser_version=PARSER_VERSION,
                provider=execution.provider,
                execution_id=execution.id,
                freshness=utcnow(),
                trust_class=trust_class,  # type: ignore[arg-type]
                taint="T2",
                evidence=refs,
            )
        )
    gaps: list[EvidenceGap] = []
    for gap in payload.get("gaps") or []:
        gaps.append(
            EvidenceGap(
                id=new_id("g"),
                run_id=run_id,
                kind=gap.get("kind", "no_cpe"),
                scope=dict(gap.get("scope") or {}),
                impact=gap.get("impact", ""),
                capability=execution.capability,
            )
        )
    return ParseResult(observations=observations, gaps=gaps)
