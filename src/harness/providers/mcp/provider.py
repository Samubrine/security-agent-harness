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
    #: The argument names each tool declared, from the server's own `tools/list`. Used twice: to
    #: build the spec's schema so the policy refuses an undeclared key before the call, and to refuse
    #: one per tool at the boundary. A model-chosen key that a tool happens to honour reaches a
    #: resource the grant never authorised, which is R2-23 and R2-07 at the remote boundary.
    tool_arguments: dict[str, frozenset[str]] = field(default_factory=dict)
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
            declared = sorted({name for names in self.tool_arguments.values() for name in names})
            self._spec = ProviderSpec(
                id=self.provider_id,
                kind="mcp",
                capabilities=sorted(self.tool_for),
                # What the server said its tools take, and nothing else - unless it said nothing at
                # all, in which case there is no declaration to hold the model to and the schema stays
                # permissive rather than denying every call for a server that is merely terse.
                input_schema=(
                    {"type": "object", "properties": {name: {} for name in declared},
                     "additionalProperties": False}
                    if declared
                    else {"type": "object", "additionalProperties": True}
                ),
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
        advertised = client.list_tools()
        tools = {str(tool.get("name")) for tool in advertised}
        declared: dict[str, frozenset[str]] = {}
        for tool in advertised:
            name = str(tool.get("name"))
            schema = tool.get("inputSchema")
            properties = schema.get("properties") if isinstance(schema, dict) else None
            declared[name] = frozenset(properties) if isinstance(properties, dict) else frozenset()
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
        return cls(
            provider_id=provider_id,
            client=client,
            tool_for=mapping,
            tool_arguments={tool: declared.get(tool, frozenset()) for tool in mapping.values()},
            **kwargs,
        )

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
        accepted = self.tool_arguments.get(tool)
        if accepted:
            undeclared = sorted(name for name in request.args if name not in accepted)
            if undeclared:
                # Recorded as a gap rather than raised: this is the model proposing something the
                # server's own declaration does not accept, which is a routing outcome, not a harness
                # failure. `target` is not in `request.args` - the harness adds it below - so a tool
                # that only takes a target is still callable.
                return failed_result(
                    request=request,
                    provider=self.provider_id,
                    error=(
                        f"tool {tool!r} does not declare argument(s) {undeclared}; it accepts "
                        f"{sorted(accepted)}"
                    ),
                    impact=(
                        "the call was refused at the boundary, so no argument the server did not "
                        "declare reached it"
                    ),
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
