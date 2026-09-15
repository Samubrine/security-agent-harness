"""Reader for MCP tool responses (``application/vnd.harness.mcp+json``).

An MCP server is a remote service, so its reply is treated exactly like a banner: data, never
instruction, and never a way to widen what the run knows about itself. Two controls make that
concrete rather than aspirational:

* **Observation kinds are an allowlist.** A server that invents a kind is not enriching the evidence
  graph, it is writing into a schema it does not own; unknown kinds are dropped and reported.
* **Every observation is T3.** The trust level is set here from the transport and is never read
  from the payload, so a server cannot declare its own output trustworthy.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from harness.models import EvidenceGap, EvidenceRef, ProviderExecution, TrustClass
from harness.parsers.registry import ParseContext, ParseResult
from harness.util import new_id

MCP_MEDIA_TYPE = "application/vnd.harness.mcp+json"
PARSER_NAME = "mcp_json"
PARSER_VERSION = "0.1.0"

#: The kinds a provider-supplied payload is allowed to contribute. Mirrors the frozen table in
#: docs/dev/INTERFACES.md section 4; anything outside it is not silently accepted.
ALLOWED_KINDS = frozenset(
    {
        "service",
        "host_state",
        "scan_meta",
        "auth_event",
        "auth_summary",
        "http_event",
        "http_summary",
        "banner",
        "injection_attempt",
        "vulnerability_match",
    }
)


def parse_mcp_json(
    data: bytes,
    *,
    execution: ProviderExecution,
    run_id: str,
    trust_class: TrustClass = "local_mcp",
    artifact_digest: str | None = None,
    evidence_of: Callable[[int, int], list[EvidenceRef]] | None = None,
    target: str | None = None,
) -> ParseResult:
    ctx = ParseContext(
        data=bytes(data),
        media_type=MCP_MEDIA_TYPE,
        run_id=run_id,
        execution=execution,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        trust_class=trust_class,
        evidence_of=evidence_of,
        artifact_digest=artifact_digest,
        target=target,
    )
    try:
        envelope: Any = json.loads(ctx.data.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ParseResult(
            observations=[],
            gaps=[
                EvidenceGap(
                    id=new_id("g"),
                    run_id=run_id,
                    kind="provider_failure",
                    scope={"provider": execution.provider, "artifact": ctx.artifact_digest},
                    impact="the MCP response was not readable JSON, so it produced no observations",
                    capability=execution.capability,
                )
            ],
        )

    result: Any = {}
    if isinstance(envelope, dict):
        result = envelope.get("result")
    entries: Any = []
    if isinstance(result, dict):
        entries = result.get("observations")
    if not isinstance(entries, list):
        return ParseResult(observations=[], gaps=[])

    observations = []
    gaps: list[EvidenceGap] = []
    total = len(ctx.data)
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind") or "")
        value = entry.get("value")
        if kind not in ALLOWED_KINDS or not isinstance(value, dict):
            gaps.append(
                EvidenceGap(
                    id=new_id("g"),
                    run_id=run_id,
                    kind="partial_coverage",
                    scope={"provider": execution.provider, "index": index, "kind": kind or None},
                    impact=(
                        "the MCP response contained an observation this harness does not accept "
                        "(unknown kind or non-object value); it was dropped rather than trusted"
                    ),
                    capability=execution.capability,
                )
            )
            continue
        observations.append(
            ctx.observe(
                kind,
                dict(value),
                byte_start=0,
                byte_end=total,
                taint="T3",
                locator="mcp-result[" + str(index) + "]",
            )
        )

    raw_gaps: Any = []
    if isinstance(result, dict):
        raw_gaps = result.get("gaps")
    if isinstance(raw_gaps, list):
        for entry in raw_gaps:
            if not isinstance(entry, dict):
                continue
            gaps.append(
                EvidenceGap(
                    id=new_id("g"),
                    run_id=run_id,
                    kind=str(entry.get("kind") or "partial_coverage"),
                    scope=dict(entry.get("scope") or {}),
                    impact=str(entry.get("impact") or "the MCP server reported incomplete coverage"),
                    capability=execution.capability,
                )
            )
    return ParseResult(observations=observations, gaps=gaps)
