"""The nmap adapter: the one place in this project that opens a socket by running a scanner.

Three properties are enforced here rather than promised in a prompt.

* **The target comes from the grant.** ``request.grant.resource`` is the authoritative host; the
  model supplies no host, and there is no field in a proposal in which it could. Even a fully
  injected model cannot get a host name into ``argv``.
* **The argv is a list.** There is no shell, no string interpolation and no ``shell=True`` anywhere
  in the harness, so a hostile value cannot become a second command.
* **A missing scanner is a gap, not an exception.** nmap is not installed on every machine that runs
  this project, and "the tool was unavailable" is a fact the report has to carry. Raising would let
  that coverage loss disappear.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from harness.models import ProviderSpec
from harness.providers.base import ProviderRequest, ProviderResult, failed_result

MEDIA_TYPE = "application/nmap+xml"
PARSER_NAME = "nmap_xml"

#: A port specification is a comma-separated list of ports or ranges and nothing else. Validating it
#: is cheap, and it is the only argument of this provider that reaches argv.
_PORTS = re.compile(r"^[0-9]{1,5}(?:-[0-9]{1,5})?(?:,[0-9]{1,5}(?:-[0-9]{1,5})?)*$")
_INPUT_SCHEMA = {
    "type": "object",
    "properties": {"profile": {"type": "string"}, "ports": {"type": "string"}},
    "additionalProperties": False,
}


@dataclass
class NmapProvider:
    binary: str = "nmap"

    @property
    def spec(self) -> ProviderSpec:
        return ProviderSpec(
            id="native:nmap",
            kind="native",
            capabilities=["service.enumerate", "http.probe"],
            # http.probe is advertised so the provider model records that the capability exists, and
            # excluded so this adapter is never chosen for it: nmap does not probe HTTP semantics,
            # and a capability claim that outruns the implementation is how a planner ends up asking
            # for something nobody can deliver.
            excludes=["http.probe"],
            input_schema=_INPUT_SCHEMA,
            output_media_type=MEDIA_TYPE,
            parser=PARSER_NAME,
            risk="LOW",
            trust_class="local_tool",
            requires_network_egress=True,
            timeout_s=300,
            idempotent=True,
            # A live service-detection scan of a host costs seconds, not milliseconds, and the gate
            # ranks by that estimate rather than by which provider was registered first.
            estimated_cost={"latency_ms": 30_000, "token_payload_hint": 2000},
            description="Service and version detection against an authorised target.",
        )

    def invoke(self, request: ProviderRequest) -> ProviderResult:
        host = _host_from_grant(request.grant.resource)
        if host is None:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"grant {request.grant.id} does not name a network resource",
                impact="a non-network grant cannot be scanned",
                kind="permission_denied",
                exit_status="denied",
            )
        ports = request.args.get("ports")
        if ports is not None and not _PORTS.match(str(ports)):
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"refusing port specification {ports!r}",
                impact="the port argument was not a port specification, so nothing was scanned",
                kind="permission_denied",
                exit_status="denied",
            )

        if shutil.which(self.binary) is None:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"the {self.binary!r} binary is not installed on this machine",
                impact=(
                    "nmap could not run, so this provider produced no evidence; another provider "
                    "that advertises the same capability would be needed to cover this need"
                ),
                kind="provider_failure",
            )

        argv = [self.binary, "-sV", "-T4", "-oX", "-"]
        if ports:
            argv += ["-p", str(ports)]
        argv.append(host)

        try:
            completed = subprocess.run(
                argv, capture_output=True, timeout=request.timeout_s, check=False, shell=False
            )
        except subprocess.TimeoutExpired:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"nmap exceeded the {request.timeout_s}s timeout",
                impact="the scan did not finish, so no service evidence was produced for this host",
                kind="tool_timeout",
                exit_status="timeout",
                argv=argv,
            )
        except OSError as exc:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"nmap could not be executed: {exc}",
                impact="the scanner could not be started, so no evidence exists for this host",
                kind="provider_failure",
                argv=argv,
            )

        if completed.returncode != 0 or not completed.stdout:
            stderr = completed.stderr.decode("utf-8", "replace")[:400]
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"nmap exited {completed.returncode}: {stderr}",
                impact="the scan produced no usable XML, so no service evidence exists for this host",
                kind="provider_failure",
                argv=argv,
                stdout=completed.stdout or None,
                provider_version=_version(completed.stderr),
            )

        return ProviderResult(
            provider=self.spec.id,
            capability=request.capability,
            exit_status="completed",
            stdout=completed.stdout,
            media_type=MEDIA_TYPE,
            argv=argv,
            provider_version=_version(completed.stderr),
        )


def _host_from_grant(resource: str) -> str | None:
    """Extract the host from ``net:<addr>``. Any other scheme is refused, not guessed at."""
    if not isinstance(resource, str) or not resource.startswith("net:"):
        return None
    host = resource[len("net:") :].strip()
    return host or None


def _version(stderr: bytes) -> str | None:
    text = stderr.decode("utf-8", "replace") if stderr else ""
    match = re.search(r"Nmap version (\S+)", text)
    return match.group(1) if match else None
