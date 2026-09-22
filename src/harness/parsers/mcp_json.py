"""Reader for MCP tool responses (``application/vnd.harness.mcp+json``).

An MCP server is a remote service, so its reply is treated exactly like a banner: data, never
instruction, and never a way to widen what the run knows about itself. Four controls make that
concrete rather than aspirational:

* **Observation kinds are an allowlist.** A server that invents a kind is not enriching the evidence
  graph, it is writing into a schema it does not own; unknown kinds are dropped and reported.
* **A CVE match is not on that allowlist.** ``vulnerability_match`` is the one kind a finding may
  cite as proof of a CVE, and the finding validator keys its CVE gate on exactly that. A server able
  to declare the kind could therefore author a critical finding that passed a gate whose purpose is
  to prove the match came from the digest-stamped snapshot, so the kind is refused here and named in
  the gap (R2-01).
* **Values are checked where the harness consumes them as types.** A payload saying ``cvss: "high"``
  or ``severity: "SEVERE"`` used to raise from a downstream `float()` or a pydantic validator - not a
  `HarnessError`, so it escaped every handler and ended the run mid-investigation. The observation is
  dropped with a gap that names the field instead (R2-19).
* **The target comes from the runtime, never from the payload.** A server that names a host in its
  own output would otherwise put that host into a claim, and the scope's aliases are the only names
  the model is allowed to see (R2-20).

* **Every observation is T3.** The trust level is set here from the transport and is never read
  from the payload, so a server cannot declare its own output trustworthy.

A payload the harness cannot read at all - not JSON, a gap whose kind is outside the vocabulary - is
a recorded outcome rather than an exception: see the catch sites below, each of which produces a gap
that says what was wrong.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from harness.models import GAP_KINDS, EvidenceGap, EvidenceRef, GapKind, ProviderExecution, TrustClass
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
    }
)

#: Kinds that exist in the vocabulary but that only the harness's own offline matcher may produce.
#: Named separately from "unknown kind" so the recorded gap says *why* the observation was refused;
#: a server that sends one is either confused about the protocol or trying to satisfy the CVE gate
#: from the outside, and those are worth telling apart in an audit.
MATCHER_ONLY_KINDS = frozenset({"vulnerability_match"})

#: Severity is a fixed rubric over CVSS (decision D6) and a `Finding` accepts exactly these. A server
#: choosing its own words would otherwise fail pydantic validation several layers later, outside
#: every handler that knows how to report it.
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})

#: The values the harness itself treats as typed: `findings/builder.py` does `float(cvss)`, puts
#: `severity` into a `Finding` and compares `cpe`/`product`/`version` against the snapshot. Anything
#: else in a payload stays free-form data, because the harness does not interpret it.
_STRING_FIELDS = ("cpe", "product", "version", "cve", "matched_on", "summary", "target")


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
                _gap(
                    execution,
                    run_id,
                    impact="the MCP response was not readable JSON, so it produced no observations",
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
        # A completed call that admits nothing is not the same as a call that returned nothing to
        # say. The native parsers report `empty_result` for this, and a reader comparing runs should
        # not have to know which parser produced which silence (R2-21).
        return ParseResult(
            observations=[],
            gaps=[
                _gap(
                    execution,
                    run_id,
                    impact=(
                        "the MCP result carried no observations list, so the call produced no "
                        "evidence and nothing to say about why"
                    ),
                    kind="empty_result",
                )
            ],
        )

    observations = []
    gaps: list[EvidenceGap] = []
    total = len(ctx.data)
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind") or "")
        value = entry.get("value")
        if kind in MATCHER_ONLY_KINDS:
            gaps.append(
                _gap(
                    execution,
                    run_id,
                    index=index,
                    kind_name=kind,
                    impact=(
                        "the MCP response reported a vulnerability match; only the harness's own "
                        "offline matcher may produce one, so it was dropped rather than trusted"
                    ),
                )
            )
            continue
        if kind not in ALLOWED_KINDS or not isinstance(value, dict):
            gaps.append(
                _gap(
                    execution,
                    run_id,
                    index=index,
                    kind_name=kind,
                    impact=(
                        "the MCP response contained an observation this harness does not accept "
                        "(unknown kind or non-object value); it was dropped rather than trusted"
                    ),
                )
            )
            continue
        problem = _value_problem(value)
        if problem is not None:
            gaps.append(
                _gap(
                    execution,
                    run_id,
                    index=index,
                    kind_name=kind,
                    impact=f"the MCP response carried a value this harness will not accept: {problem}",
                )
            )
            continue
        payload = dict(value)
        if target:
            # The runtime's alias wins over anything the payload said. A server naming its own host
            # would otherwise put a name into a claim that no grant in this run authorises (R2-20).
            payload["target"] = target
        observations.append(
            ctx.observe(
                kind,
                payload,
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
        for index, entry in enumerate(raw_gaps):
            if not isinstance(entry, dict):
                continue
            # A gap kind outside the vocabulary used to raise a pydantic ValidationError, which the
            # parser registry turns into a ParserError and the run aborts mid-investigation: a remote
            # server could end a run by naming a gap badly (R2-18).
            requested = str(entry.get("kind") or "")
            kind_name = requested if requested in GAP_KINDS else "partial_coverage"
            scope = entry.get("scope")
            gaps.append(
                EvidenceGap(
                    id=new_id("g"),
                    run_id=run_id,
                    kind=kind_name,
                    scope=dict(scope) if isinstance(scope, dict) else {},
                    impact=str(entry.get("impact") or "the MCP server reported incomplete coverage"),
                    capability=execution.capability,
                )
            )
            if kind_name != requested:
                gaps[-1].scope = {
                    **gaps[-1].scope,
                    "provider": execution.provider,
                    "reported_kind": requested,
                }
                gaps[-1].impact = (
                    f"the MCP server reported a gap of unknown kind {requested!r}; recorded as "
                    f"{kind_name} with the original kind kept here. {gaps[-1].impact}"
                )

    if not observations and not gaps:
        # A completed call that admits nothing is a gap in the evidence, not a silent success: the
        # native parsers report `empty_result` for the same shape of nothing, and a reader comparing
        # runs should not have to know which parser produced which silence (R2-21). The server's own
        # gaps count as something said, so this only fires when the payload said nothing at all.
        gaps.append(
            _gap(
                execution,
                run_id,
                kind="empty_result",
                impact="the MCP result carried no observations, so the call produced no evidence",
            )
        )

    return ParseResult(observations=observations, gaps=gaps)


def _gap(
    execution: ProviderExecution,
    run_id: str,
    *,
    impact: str,
    kind: GapKind = "partial_coverage",
    index: int | None = None,
    kind_name: str | None = None,
) -> EvidenceGap:
    scope: dict[str, Any] = {"provider": execution.provider}
    if index is not None:
        scope["index"] = index
    if kind_name is not None:
        scope["kind"] = kind_name or None
    return EvidenceGap(
        id=new_id("g"),
        run_id=run_id,
        kind=kind,
        scope=scope,
        impact=impact,
        capability=execution.capability,
    )


def _value_problem(value: dict[str, Any]) -> str | None:
    """Why this payload's typed values cannot be accepted, or ``None`` when they can.

    Only the fields the harness interprets are checked. Everything else stays what it is - a remote
    server's data, carried verbatim into an observation nobody parses as a number or a rubric.
    """
    cvss = value.get("cvss")
    if cvss is not None:
        if isinstance(cvss, bool) or not isinstance(cvss, (int, float)):
            return f"cvss is {type(cvss).__name__} ({cvss!r}), and the harness reads it as a score"
        if not 0.0 <= float(cvss) <= 10.0:
            return f"cvss is {cvss!r}, outside the 0-10 range"
    severity = value.get("severity")
    if severity is not None and str(severity) not in SEVERITIES:
        return (
            f"severity is {severity!r}, and this harness knows {sorted(SEVERITIES)}; a server does "
            "not get to invent a severity band"
        )
    for name in _STRING_FIELDS:
        if name in value and not isinstance(value[name], str):
            return f"{name} is {type(value[name]).__name__} ({value[name]!r}), and it must be a string"
    return None

