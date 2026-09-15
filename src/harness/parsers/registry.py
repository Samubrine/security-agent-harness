"""Deterministic parser dispatch: immutable artifact bytes in, evidence-bound observations out.

Why a registry instead of a chain of format checks: a provider advertises a media type and a
parser name in its ``ProviderSpec``, so the investigation loop never learns a file format. A new
format becomes a registration rather than a branch inside the runtime (design 01, section 11).

Two properties are enforced here rather than documented, because both are load-bearing for every
finding built on top:

* an observation cannot exist without an evidence span that hashes against real artifact bytes.
  A parser that cannot locate what it read fails loudly instead of emitting a plausible record
  with invented offsets -- fabricated offsets are worse than no observation, because they make an
  unverifiable claim look verified;
* a parser cannot attribute artifact bytes to a run other than the execution that produced them,
  so evidence cannot be laundered from one investigation into another.

``injection_observations`` lives here on purpose. The patterns themselves are frozen in
``harness.util`` (one definition of "this payload is instruction-shaped"); this module owns the
single translation from a match into an observation plus the scope-widening gap, so the nmap and
log parsers cannot drift into two different renderings of the same attack.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable

from harness.errors import ParserError
from harness.models import (
    EvidenceGap,
    EvidenceRef,
    Observation,
    ProviderExecution,
    TaintLevel,
    TrustClass,
)
from harness.util import (
    clamp_text,
    detect_injection,
    new_id,
    out_of_scope_ips,
    strip_control_chars,
)

#: How much of an injected instruction is quoted into a finding. The excerpt is for a human
#: reading the report; the evidence span still points at the full payload in the artifact.
EXCERPT_LIMIT = 400


@dataclass
class ParseResult:
    """What a parser hands back: typed observations, plus the gaps it has to admit.

    A gap is not an error. "I read the artifact and there was nothing to match" is a fact the
    report must carry (design 02, section 4); folding it into an empty list would quietly turn
    "no evidence" into "not affected".
    """

    observations: list[Observation]
    gaps: list[EvidenceGap] = field(default_factory=list)


ParserFn = Callable[..., ParseResult]


@dataclass(slots=True)
class ParseContext:
    """Everything a parser needs to build an evidence-bound observation.

    The context is where the provenance rules are applied once, so every parser inherits the same
    guarantees: offsets must be inside the artifact, a span is hashed from the bytes it names, and
    an observation is stamped with the execution that produced the artifact rather than with
    anything the parsed content claims about itself.
    """

    data: bytes
    media_type: str
    run_id: str
    execution: ProviderExecution
    parser_name: str
    parser_version: str
    trust_class: TrustClass = "local_tool"
    artifact_digest: str | None = None
    evidence_of: Callable[[int, int], list[EvidenceRef]] | None = None
    #: Some formats carry no host name of their own (a combined-format access log does not). The
    #: runtime may name the granted host here; when it does not, the parser records "unknown"
    #: rather than inventing a plausible target.
    target: str | None = None

    def __post_init__(self) -> None:
        if not self.media_type:
            raise ParserError("a parser must declare the media type it is registered for")
        if self.artifact_digest is None and self.evidence_of is None:
            raise ParserError(
                f"{self.parser_name} was asked to parse without provenance: pass artifact_digest "
                "or evidence_of, otherwise every observation it emits would be unciteable"
            )
        if self.run_id and self.execution.run_id and self.execution.run_id != self.run_id:
            raise ParserError(
                f"execution {self.execution.id} belongs to run {self.execution.run_id!r}; its "
                f"output cannot become evidence in run {self.run_id!r}"
            )

    # -- positions ---------------------------------------------------------------------

    def line_number(self, byte_offset: int) -> int:
        """1-based line number, counted from the artifact bytes themselves rather than from a
        parser's idea of how the file was laid out."""
        return self.data.count(b"\n", 0, max(0, byte_offset)) + 1

    def refs(
        self,
        byte_start: int,
        byte_end: int,
        *,
        locator: str | None = None,
        taint: TaintLevel = "T3",
    ) -> list[EvidenceRef]:
        """Build the evidence refs for a span, refusing offsets that are not inside the artifact.

        Out-of-range offsets fail here, while the author still knows which element they meant,
        instead of surviving into a report that cites bytes nobody can find.
        """
        self._check_span(byte_start, byte_end)
        if self.evidence_of is not None:
            found = list(self.evidence_of(byte_start, byte_end))
            if not found:
                raise ParserError(
                    f"{self.parser_name} got no evidence ref for bytes {byte_start}:{byte_end}; "
                    "an observation without evidence must not be emitted"
                )
            return [self._with_span_hash(ref) for ref in found]
        digest = self.artifact_digest
        if digest is None:  # pragma: no cover - __post_init__ already refuses this combination
            raise ParserError("no artifact digest available to anchor the evidence span")
        ref = EvidenceRef(
            artifact=digest,
            media_type=self.media_type,
            byte_start=byte_start,
            byte_end=byte_end,
            line_start=self.line_number(byte_start),
            line_end=self.line_number(max(byte_start, byte_end - 1)),
            locator=locator,
            taint=taint,
        )
        ref.span_sha256 = ref.compute_span_sha256(self.data)
        return [ref]

    def observe(
        self,
        kind: str,
        value: dict[str, Any],
        *,
        byte_start: int,
        byte_end: int,
        taint: TaintLevel = "T2",
        locator: str | None = None,
        freshness: Any = None,
    ) -> Observation:
        """Assemble one observation. ``kind`` and ``value`` come from the frozen table in
        ``docs/dev/INTERFACES.md`` section 4; this method adds identity and evidence, nothing else."""
        return Observation(
            id=new_id("o"),
            run_id=self.run_id,
            kind=kind,
            value=value,
            parser=self.parser_name,
            parser_version=self.parser_version,
            provider=self.execution.provider,
            execution_id=self.execution.id,
            freshness=freshness,
            trust_class=self.trust_class,
            taint=taint,
            evidence=self.refs(byte_start, byte_end, locator=locator, taint=taint),
        )

    # -- internals ---------------------------------------------------------------------

    def _check_span(self, byte_start: int, byte_end: int) -> None:
        if byte_start < 0 or byte_end < byte_start or byte_end > len(self.data):
            raise ParserError(
                f"{self.parser_name} asked for evidence span {byte_start}:{byte_end} outside the "
                f"{len(self.data)}-byte artifact"
            )

    def _with_span_hash(self, ref: EvidenceRef) -> EvidenceRef:
        """Fill in a span hash a builder left empty, but only from bytes we actually hold.

        Verification is the validator's job, so this never invents a hash for a span it cannot
        recompute: a ref pointing at another artifact keeps whatever hash its builder gave it.
        """
        if ref.span_sha256:
            return ref
        if self.artifact_digest is not None and ref.artifact == self.artifact_digest:
            if 0 <= ref.byte_start <= ref.byte_end <= len(self.data):
                ref = ref.model_copy(update={"span_sha256": ref.compute_span_sha256(self.data)})
        return ref


class ParserRegistry:
    """Media type to parser selection, plus the integrity gate every result passes through."""

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, _ParserEntry]] = {}

    def register(
        self,
        media_type: str,
        name: str,
        fn: ParserFn,
        *,
        version: str = "0.1.0",
    ) -> None:
        if not media_type or not name:
            raise ValueError("a parser needs both a media type and a name: that is how it is chosen")
        if not callable(fn):
            raise ValueError(f"parser {name!r} is not callable")
        bucket = self._entries.setdefault(media_type, {})
        if name in bucket:
            raise ValueError(f"parser {name!r} is already registered for media type {media_type!r}")
        bucket[name] = _ParserEntry(name=name, version=version, fn=fn)

    def media_types(self) -> list[str]:
        return sorted(self._entries)

    def names(self, media_type: str) -> list[str]:
        return sorted(self._entries.get(media_type, {}))

    def parse(
        self,
        data: bytes,
        media_type: str,
        *,
        execution: ProviderExecution,
        run_id: str,
        trust_class: TrustClass = "local_tool",
        artifact_digest: str | None = None,
        evidence_of: Callable[[int, int], list[EvidenceRef]] | None = None,
        target: str | None = None,
    ) -> ParseResult:
        entry = self._select(media_type)
        kwargs: dict[str, Any] = {
            "execution": execution,
            "run_id": run_id,
            "trust_class": trust_class,
            "artifact_digest": artifact_digest,
            "evidence_of": evidence_of,
        }
        # ``target`` is additive (see ParseContext): a parser that does not know the parameter is
        # never handed it, so registering a third-party parser cannot start failing on upgrade.
        if target is not None and _accepts_keyword(entry.fn, "target"):
            kwargs["target"] = target
        try:
            result = entry.fn(bytes(data), **kwargs)
        except ParserError:
            raise
        except Exception as exc:  # noqa: BLE001 - a format failure is a ParserError at the boundary
            raise ParserError(f"{entry.name} could not parse {media_type!r}: {exc}") from exc
        return _check_result(result, entry, run_id)

    def _select(self, media_type: str) -> _ParserEntry:
        bucket = self._entries.get(media_type)
        if not bucket:
            raise ParserError(
                f"no parser is registered for media type {media_type!r} "
                f"(registered: {sorted(self._entries)})"
            )
        # Lowest name wins, not last-registered: selection must not depend on import order.
        return bucket[sorted(bucket)[0]]


@dataclass(frozen=True, slots=True)
class _ParserEntry:
    name: str
    version: str
    fn: ParserFn


def _accepts_keyword(fn: ParserFn, keyword: str) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins and C callables
        return False
    if keyword in params:
        return True
    return any(param.kind is inspect.Parameter.VAR_KEYWORD for param in params.values())


def _check_result(result: Any, entry: _ParserEntry, run_id: str) -> ParseResult:
    """Refuse a result that would put an unevidenced or misfiled observation in the graph."""
    if not isinstance(result, ParseResult):
        raise ParserError(f"{entry.name} returned {type(result).__name__}, expected ParseResult")
    for observation in result.observations:
        if not observation.evidence:
            raise ParserError(
                f"{entry.name} produced a {observation.kind!r} observation with no evidence; "
                "an unciteable observation is worse than a gap"
            )
        if any(not ref.span_sha256 for ref in observation.evidence):
            raise ParserError(
                f"{entry.name} produced a {observation.kind!r} observation with an unhashed "
                "evidence span, so the span could not be verified against its artifact"
            )
        if run_id and observation.run_id != run_id:
            raise ParserError(
                f"{entry.name} stamped an observation with run {observation.run_id!r} while "
                f"parsing for run {run_id!r}"
            )
    return result


def injection_observations(
    ctx: ParseContext,
    *,
    text: str,
    source: str,
    byte_start: int,
    byte_end: int,
    target: str,
    authorised: set[str],
) -> tuple[list[Observation], EvidenceGap | None]:
    """Turn instruction-shaped attacker text into evidence, never into instructions.

    A banner or a log line that says "ignore all previous instructions" is a fact about the world:
    it becomes an ``injection_attempt`` observation, and the hosts it tries to add to the scope are
    recorded as an out-of-scope list in a ``prompt_injection_attempt`` gap. Nothing here acts on the
    text, and the text never leaves the artifact -- only a bounded, control-character-stripped
    excerpt does.

    ``authorised`` is the set of hosts the producing execution was allowed to touch (for a scan,
    the addresses present in the document itself). Any other literal address inside the payload is,
    by construction, a scope-widening attempt.
    """
    patterns = detect_injection(text)
    if not patterns:
        return [], None
    out_of_scope = out_of_scope_ips(text, authorised)
    excerpt, span_start, span_end = _payload_span(ctx, text, byte_start, byte_end)
    observations = [
        ctx.observe(
            "injection_attempt",
            {
                "target": target,
                "source": source,
                "pattern": pattern,
                "payload_excerpt": excerpt,
                # Additive key: the payload's scope-widening attempt is the point of this record,
                # so it travels with the observation and not only inside the gap.
                "out_of_scope_ips": out_of_scope,
            },
            byte_start=span_start,
            byte_end=span_end,
            taint="T3",
            locator=f"{source} payload on {target}",
        )
        for pattern in patterns
    ]
    gap = EvidenceGap(
        id=new_id("g"),
        run_id=ctx.run_id,
        kind="prompt_injection_attempt",
        scope={
            "target": target,
            "source": source,
            "patterns": patterns,
            "out_of_scope_ips": out_of_scope,
            "artifact": ctx.artifact_digest,
        },
        impact=(
            "attacker-controlled text contains instruction-shaped content"
            + (
                f" and names {', '.join(out_of_scope)} which is not in the authorised set"
                if out_of_scope
                else ""
            )
            + "; it is recorded as evidence and was not acted on"
        ),
        capability=ctx.execution.capability,
    )
    return observations, gap


def _payload_span(
    ctx: ParseContext, text: str, byte_start: int, byte_end: int
) -> tuple[str, int, int]:
    """Quote the line carrying the instruction and tighten the span onto its real bytes.

    The excerpt is bounded and control characters are stripped before it can reach a prompt; the
    span is only narrowed when the raw bytes can actually be found inside the region we parsed, so
    a tightened span is always a byte-exact subset of the artifact.
    """
    excerpt_text = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and detect_injection(stripped):
            excerpt_text = strip_control_chars(stripped)
            break
    if not excerpt_text:
        excerpt_text = strip_control_chars(text).strip()
    start, end = byte_start, byte_end
    try:
        anchor = excerpt_text.encode("utf-8")
    except UnicodeEncodeError:  # pragma: no cover - lxml does not produce lone surrogates
        anchor = b""
    if anchor:
        found = ctx.data.find(anchor, byte_start, byte_end)
        if found >= 0:
            start, end = found, found + len(anchor)
    return clamp_text(excerpt_text, EXCERPT_LIMIT), start, end
