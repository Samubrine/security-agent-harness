"""The provider boundary: one capability request in, bytes or a typed gap out.

This is the only place where an abstract capability becomes a concrete action, so the two
structural guarantees of the design are enforced here instead of being trusted to each adapter:

* a request carries a Grant and never a model-supplied target, so a provider that wants to act
  has to read the authorised resource out of the grant -- there is no other field in which a
  target could arrive;
* a provider never raises for an ordinary failure. A missing binary, an unreachable host or a
  refused path become exit_status="failed" plus an EvidenceGap, because "this tool could not
  answer" is itself evidence about coverage. Raising would let that fact disappear from the
  report.

The args mapping is untrusted model input. Providers treat it as a hint at most; anything that
reaches an argv array has to be derivable from the grant or from a validated field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from harness.models import EvidenceGap, ExitStatus, GapKind, Grant, ProviderSpec
from harness.util import new_id


@dataclass(frozen=True)
class ProviderRequest:
    """One concrete invocation of one capability against one grant.

    Frozen because the runner records the request next to the execution; mutating it afterwards
    would break the correspondence between what was authorised and what actually ran.
    """

    run_id: str
    execution_id: str
    capability: str
    args: dict[str, Any]
    grant: Grant
    target_alias: str
    timeout_s: int

    @classmethod
    def build(
        cls,
        *,
        grant: Grant,
        capability: str,
        run_id: str = "",
        execution_id: str | None = None,
        args: dict[str, Any] | None = None,
        target_alias: str | None = None,
        timeout_s: int = 60,
    ) -> ProviderRequest:
        """Convenience factory.

        target_alias defaults to the grant alias so a caller cannot accidentally place the real
        resource where an alias is expected: the alias is the only target name that may ever be
        rendered back into a prompt.
        """
        return cls(
            run_id=run_id or "run-unset",
            execution_id=execution_id or new_id("x"),
            capability=capability,
            args=dict(args or {}),
            grant=grant,
            target_alias=target_alias or grant.alias,
            timeout_s=timeout_s,
        )


@dataclass
class ProviderResult:
    """The normalised envelope every provider returns, native or MCP.

    stdout holds the raw bytes that the run content-addresses before parsing: providers never
    pre-digest their own evidence, because that would let a provider choose what the parsers
    are allowed to see.
    """

    provider: str
    capability: str
    exit_status: ExitStatus
    stdout: bytes | None = None
    media_type: str = "application/octet-stream"
    structured: dict[str, Any] | None = None
    argv: list[str] | None = None
    provider_version: str | None = None
    error: str | None = None
    gaps: list[EvidenceGap] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exit_status == "completed"


@runtime_checkable
class Provider(Protocol):
    """What the registry and the router need from anything able to serve a capability."""

    spec: ProviderSpec

    def invoke(self, request: ProviderRequest) -> ProviderResult: ...


def make_gap(
    *,
    request: ProviderRequest,
    kind: GapKind,
    impact: str,
    scope: dict[str, Any] | None = None,
) -> EvidenceGap:
    """Build a gap traceable back to the capability that came up short."""
    return EvidenceGap(
        id=new_id("g"),
        run_id=request.run_id,
        kind=kind,
        scope=dict(scope or {}),
        impact=impact,
        capability=request.capability,
    )


def failed_result(
    *,
    request: ProviderRequest,
    provider: str,
    error: str,
    impact: str,
    kind: GapKind = "provider_failure",
    exit_status: ExitStatus = "failed",
    media_type: str = "text/plain",
    scope: dict[str, Any] | None = None,
    stdout: bytes | None = None,
    structured: dict[str, Any] | None = None,
    argv: list[str] | None = None,
    provider_version: str | None = None,
) -> ProviderResult:
    """The single failure shape for every provider.

    Keeping one shape means every failure carries a gap whose kind the report and the necessity
    gate can reason about, rather than a bare exception string only a human can read.
    """
    return ProviderResult(
        provider=provider,
        capability=request.capability,
        exit_status=exit_status,
        stdout=stdout,
        media_type=media_type,
        structured=structured,
        argv=argv,
        provider_version=provider_version,
        error=error,
        gaps=[make_gap(request=request, kind=kind, impact=impact, scope=scope)],
    )
