"""An MCP server presented as an ordinary capability provider.

Two asymmetries are deliberate and are what keep MCP from becoming a second orchestrator:

* **Capabilities come from the server's tool list, not from the model.** A server can only be
  selected for something it actually advertises, and the mapping from capability to tool name is
  configuration fixed before the run starts.
* **Its output is untrusted by default.** A remote service's reply is T3 data: it enters the run as
  an artifact and an observation, never as instructions. Design D17 makes that the default rather
  than an opt-in, because the default is what actually protects a run nobody is watching.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from harness.models import ProviderSpec
from harness.providers.base import ProviderRequest, ProviderResult, failed_result
from harness.providers.mcp.client import McpStdioClient
from harness.util import canonical_json

MEDIA_TYPE = "application/vnd.harness.mcp+json"
PARSER_NAME = "mcp_json"


@dataclass
class McpProvider:
    """Wraps a connected MCP client, exposing one tool per mapped capability."""

    provider_id: str
    client: McpStdioClient
    tool_for: dict[str, str]
    risk: str = "LOW"
    trust_class: str = "local_mcp"
    timeout_s: int = 60
    requires_network_egress: bool = False
    description: str = ""
    parser: str = PARSER_NAME
    _spec: ProviderSpec | None = field(default=None, init=False, repr=False)

    @property
    def spec(self) -> ProviderSpec:
        if self._spec is None:
            self._spec = ProviderSpec(
                id=self.provider_id,
                kind="mcp",
                capabilities=sorted(self.tool_for),
                input_schema={"type": "object", "additionalProperties": True},
                output_media_type=MEDIA_TYPE,
                parser=self.parser,
                risk=self.risk,  # type: ignore[arg-type]
                trust_class=self.trust_class,  # type: ignore[arg-type]
                requires_network_egress=self.requires_network_egress,
                timeout_s=self.timeout_s,
                idempotent=True,
                description=self.description or ("MCP provider " + self.provider_id),
            )
        return self._spec

    @classmethod
    def from_advertised_tools(
        cls,
        *,
        provider_id: str,
        client: McpStdioClient,
        capability_map: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> McpProvider:
        """Discover capabilities by asking the server, and refuse a server that advertises none.

        Registration is not usage, but an MCP server that cannot serve anything has no place in the
        registry: it would appear in every routing decision as a candidate to reject.
        """
        client.initialize()
        tools = {str(tool.get("name")) for tool in client.list_tools()}
        mapping = dict(capability_map or {})
        if not mapping:
            mapping = {name: name for name in sorted(tools)}
        missing = sorted({tool for tool in mapping.values() if tool not in tools})
        if missing:
            raise ValueError(
                "MCP server " + provider_id + " does not advertise tool(s) " + repr(missing)
            )
        if not mapping:
            raise ValueError("MCP server " + provider_id + " advertises no usable capability")
        return cls(provider_id=provider_id, client=client, tool_for=mapping, **kwargs)

    def invoke(self, request: ProviderRequest) -> ProviderResult:
        tool = self.tool_for.get(request.capability)
        if tool is None:
            return failed_result(
                request=request,
                provider=self.provider_id,
                error="this MCP provider has no tool mapped for " + request.capability,
                impact="the MCP server cannot serve this capability, so it produced no evidence",
                kind="partial_coverage",
                exit_status="denied",
            )
        # Only the grant alias and the validated args cross the boundary. The real resource never
        # does, which is what keeps an MCP server from learning more about the target than the model
        # is allowed to know.
        arguments = {**request.args, "target": request.target_alias}
        try:
            raw = self.client.call_tool(tool, arguments, timeout_s=float(request.timeout_s))
        except Exception as exc:  # noqa: BLE001 - every transport failure is one reportable outcome
            return failed_result(
                request=request,
                provider=self.provider_id,
                error="MCP call failed: " + str(exc),
                impact="the MCP server did not answer, so it produced no evidence",
                kind="provider_failure",
            )

        payload = self._structured(raw)
        if raw.get("isError"):
            return failed_result(
                request=request,
                provider=self.provider_id,
                error="the MCP tool reported an error: " + canonical_json(payload)[:400],
                impact="the MCP server returned an error result, so it produced no evidence",
                kind="provider_failure",
                stdout=canonical_json(payload).encode("utf-8"),
                structured=payload if isinstance(payload, dict) else None,
            )

        envelope = {
            "provider": self.provider_id,
            "capability": request.capability,
            "tool": tool,
            "target_alias": request.target_alias,
            "result": payload,
        }
        return ProviderResult(
            provider=self.provider_id,
            capability=request.capability,
            exit_status="completed",
            stdout=canonical_json(envelope).encode("utf-8"),
            media_type=MEDIA_TYPE,
            structured=envelope,
            argv=[],
            provider_version=str(self.client.server_info.get("version") or "mcp"),
        )

    @staticmethod
    def _structured(raw: dict[str, Any]) -> Any:
        """Prefer structured content, fall back to the first text block parsed as JSON."""
        if isinstance(raw.get("structuredContent"), dict | list):
            return raw["structuredContent"]
        content = raw.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = str(block.get("text") or "")
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return {"text": text}
        return {}
