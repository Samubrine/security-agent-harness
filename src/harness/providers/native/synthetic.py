"""A deterministic, fixture-backed provider for ``service.enumerate``.

This is not a mock. It is the provider that makes three things possible on a machine with no scanner
installed and no lab running:

* the integration tests and the evaluation harness, which must produce identical results on every
  machine or the metrics mean nothing;
* the replay demo, where a recorded run has to be re-derivable without touching a target;
* a second opinion for the multi-provider path, since it advertises the same capability as the real
  nmap adapter while being local, fast and risk-free.

It reads only from the fixture directory it is constructed with, resolves the target through the
**grant**, and reports a failure rather than inventing output for an alias it has no data for.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from harness.models import ProviderSpec
from harness.providers.base import ProviderRequest, ProviderResult, failed_result

MEDIA_TYPE = "application/nmap+xml"
PARSER_NAME = "nmap_xml"


@dataclass
class SyntheticProvider:
    """Serves stored scan output for known aliases.

    ``fixture_root`` is injectable so tests can point it at a temporary copy and prove the provider
    reads nothing outside the directory it was given.
    """

    fixture_root: Path

    @property
    def spec(self) -> ProviderSpec:
        return ProviderSpec(
            id="native:synthetic",
            kind="native",
            capabilities=["service.enumerate"],
            input_schema={
                "type": "object",
                "properties": {"profile": {"type": "string"}},
                "additionalProperties": False,
            },
            output_media_type=MEDIA_TYPE,
            parser=PARSER_NAME,
            risk="LOW",
            trust_class="local_tool",
            requires_network_egress=False,
            timeout_s=10,
            idempotent=True,
            # Declared cheap on purpose. The necessity gate orders equivalent providers by estimated
            # cost, and a fixture-backed read really is cheaper than a live scan -- so an offline run
            # selects this one and leaves the real scanner as the second source it can expand to.
            estimated_cost={"latency_ms": 5, "token_payload_hint": 2000},
            description=(
                "Deterministic replay of a recorded scan; used for tests, evaluation and as a "
                "risk-free corroborating provider."
            ),
        )

    def invoke(self, request: ProviderRequest) -> ProviderResult:
        # The alias is the model-facing name; the file is chosen by the *grant* the runtime minted,
        # so a proposal cannot select scan output for a host it was not authorised to touch.
        alias = request.target_alias or request.grant.alias
        filename = _FILENAMES.get(alias)
        if filename is None:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"no recorded scan exists for alias {alias!r}",
                impact=(
                    f"no service evidence exists for {alias}: the synthetic provider has no "
                    "recorded output for this target"
                ),
                kind="provider_failure",
            )
        path = Path(self.fixture_root) / filename
        try:
            data = path.read_bytes()
        except OSError as exc:
            return failed_result(
                request=request,
                provider=self.spec.id,
                error=f"recorded scan {filename} could not be read: {exc}",
                impact=f"the fixture for {alias} is missing, so no service evidence could be produced",
                kind="provider_failure",
            )
        return ProviderResult(
            provider=self.spec.id,
            capability=request.capability,
            exit_status="completed",
            stdout=data,
            media_type=MEDIA_TYPE,
            argv=[],
            provider_version="synthetic-1",
        )


#: The only aliases this provider knows. Anything else is a failure with a gap, which is how a
#: missing fixture becomes visible coverage loss instead of a plausible-looking empty scan.
_FILENAMES: dict[str, str] = {
    "lab-web-01": "lab_web_01.xml",
    "lab-web-02": "lab_web_02.xml",
}
