"""Filesystem reading inside a granted scope.

The filesystem capability exists so that log analysis is possible without giving the agent a way to
read arbitrary files. Two guarantees make that true here:

* **The path is resolved, never concatenated.** ``safe_relpath`` refuses anything that escapes the
  root, and a refusal is a hard failure rather than a best-effort read of something nearby;
* **The root comes from the grant.** The provider defaults to the grant's own filesystem resource
  and only accepts an override at construction time, which is a configuration act and not a model
  one.

Log content is local data about remote actors, so it is T2: it describes hostile traffic without
being attacker-authored text in the way a banner is.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from harness.models import ProviderSpec
from harness.providers.base import ProviderRequest, ProviderResult, failed_result, make_gap
from harness.util import safe_relpath

DEFAULT_MEDIA_TYPE = "text/x-authlog"
PARSER_NAME = "auth_log"

#: How much of one file is read in a single call. Bounding this keeps a huge access log from
#: becoming a huge prompt problem later, and the truncation is reported as a gap rather than
#: silently applied.
MAX_BYTES = 8 * 1024 * 1024

_INPUT_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
    "required": ["path"],
    "additionalProperties": False,
}

#: Control characters, including NUL. A name containing one is not a path, and letting the filesystem
#: try to interpret it risks a truncated read of something else entirely.
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class LogFileProvider:
    """Reads one named file from a granted log directory."""

    root: Path | None = None
    max_bytes: int = MAX_BYTES

    @property
    def spec(self) -> ProviderSpec:
        return ProviderSpec(
            id="native:logfile",
            kind="native",
            capabilities=["log.read"],
            input_schema=_INPUT_SCHEMA,
            output_media_type=DEFAULT_MEDIA_TYPE,
            parser=PARSER_NAME,
            risk="LOW",
            trust_class="local_tool",
            requires_network_egress=False,
            timeout_s=30,
            idempotent=True,
            description="Reads a bounded log file from a filesystem grant using a validated basename.",
        )

    def invoke(self, request: ProviderRequest) -> ProviderResult:
        if request.grant.kind != "fs":
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=(
                    f"grant {request.grant.id} is a {request.grant.kind} grant, "
                    "not a filesystem grant"
                ),
                impact="this grant does not authorise reading files",
                kind="permission_denied",
                exit_status="denied",
            )
        raw_name = request.args.get("path") or request.args.get("file")
        if not isinstance(raw_name, str) or not raw_name.strip():
            return failed_result(
                request=request,
                provider=self.spec.id,
                error="log.read needs a file name",
                impact="no file was named, so no log evidence could be produced",
                kind="permission_denied",
                exit_status="denied",
            )
        name = raw_name.strip()
        if _CONTROL.search(name):
            return failed_result(
                request=request,
                provider=self.spec.id,
                error="the requested file name contains control characters",
                impact="the request was refused before any file was opened",
                kind="permission_denied",
                exit_status="denied",
            )

        root = Path(self.root) if self.root is not None else _root_from_grant(request.grant.resource)
        if root is None:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error="no log directory is configured for this grant",
                impact="no log evidence could be produced because no directory is authorised",
                kind="permission_denied",
                exit_status="denied",
            )
        try:
            path = safe_relpath(root, name)
        except ValueError as exc:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"refusing path {name!r}: {exc}",
                impact="the requested path escapes the granted directory, so nothing was read",
                kind="permission_denied",
                exit_status="denied",
                scope={"requested": name},
            )

        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"{name!r} does not exist under the granted directory",
                impact="the named log file is absent, so no log evidence exists for it",
                kind="unreachable",
                exit_status="failed",
            )
        except OSError as exc:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"{name!r} could not be read: {exc}",
                impact="the log file could not be read, so no log evidence exists for it",
                kind="provider_failure",
            )

        truncated = len(data) > self.max_bytes
        payload = data[: self.max_bytes] if truncated else data
        result = ProviderResult(
            provider=self.spec.id,
            capability=request.capability,
            exit_status="completed",
            stdout=payload,
            media_type=media_type_for(name),
            argv=[],
            provider_version="logfile-1",
        )
        if truncated:
            result.gaps.append(
                make_gap(
                    request=request,
                    kind="partial_coverage",
                    impact=(
                        f"{name!r} is larger than the {self.max_bytes}-byte read limit and was "
                        "truncated; activity after the cut-off is not in this run's evidence"
                    ),
                    scope={"file": name, "bytes_read": self.max_bytes, "bytes_total": len(data)},
                )
            )
        if not payload.strip():
            result.gaps.append(
                make_gap(
                    request=request,
                    kind="empty_result",
                    impact=f"{name!r} is empty, so it provides no evidence either way",
                    scope={"file": name},
                )
            )
        return result


def _root_from_grant(resource: str) -> Path | None:
    if not isinstance(resource, str) or not resource.startswith("fs:"):
        return None
    value = resource[len("fs:") :].strip()
    return Path(value) if value else None


def media_type_for(name: str) -> str:
    """Pick the parser by the shape of the file name.

    Filename-based selection is a deliberate simplification: this provider serves a lab corpus whose
    files are named for what they are. Stating it in one function makes exactly which names route
    where visible, and an unknown name falls back to the authentication format rather than to a
    guess about file content.
    """
    lowered = Path(name).name.lower()
    if "access" in lowered or "nginx" in lowered or "http" in lowered:
        return "text/x-nginx-access"
    return DEFAULT_MEDIA_TYPE


def parser_for(media_type: str) -> str:
    return "nginx_access" if media_type == "text/x-nginx-access" else PARSER_NAME
