"""MCP is a provider boundary, so it is tested as an unreliable remote peer.

Every test here assumes the server may misbehave: answering the wrong request, sending a line that is
not JSON, or reporting an error. A protocol client that only works against a correct server is a
client that turns a broker's bug into a fabricated finding.
"""

from __future__ import annotations

import sys
from collections import deque
from pathlib import Path
from typing import Any, Callable

import pytest

from harness.errors import ProviderError, ProviderTimeout
from harness.models import Grant
from harness.providers.base import ProviderRequest
from harness.providers.mcp.client import McpStdioClient, StdioTransport
from harness.providers.mcp.provider import MEDIA_TYPE, McpProvider

HELPER_SERVER = Path(__file__).parent / "helpers" / "mcp_server.py"


class ScriptedTransport:
    """In-process transport whose replies are computed from the request that was sent.

    Building replies from the request rather than replaying a fixed list keeps a test's intent
    visible: the fake answers the question it was asked, so a client that mis-frames a request fails
    instead of passing against a script that happened to match.
    """

    def __init__(self, handler: Callable[[dict[str, Any]], dict[str, Any] | None]) -> None:
        self.handler = handler
        self.sent: list[dict[str, Any]] = []
        self._queue: deque[dict[str, Any]] = deque()
        self.closed = False

    def send(self, message: dict[str, Any]) -> None:
        self.sent.append(message)
        if message.get("id") is None:
            return
        response = self.handler(message)
        if response is not None:
            self._queue.append(response)

    def receive(self, timeout_s: float) -> dict[str, Any]:
        if not self._queue:
            raise ProviderTimeout("the scripted transport has nothing left to say")
        return self._queue.popleft()

    def close(self) -> None:
        self.closed = True


def ok(message: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def happy_server(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    if method == "initialize":
        return ok(message, {"protocolVersion": "2024-11-05", "serverInfo": {"name": "fake", "version": "1.0"}})
    if method == "tools/list":
        if message.get("params", {}).get("cursor"):
            return ok(message, {"tools": [{"name": "log.read"}]})
        return ok(message, {"tools": [{"name": "service.enumerate"}], "nextCursor": "1"})
    if method == "tools/call":
        return ok(message, {"structuredContent": {"observations": []}, "isError": False})
    return None


def client(handler: Callable[[dict[str, Any]], dict[str, Any] | None] = happy_server) -> tuple[McpStdioClient, ScriptedTransport]:
    transport = ScriptedTransport(handler)
    return McpStdioClient(transport), transport


def test_handshake_reports_server_info() -> None:
    subject, _ = client()
    result = subject.initialize()
    assert result["serverInfo"]["name"] == "fake"
    assert subject.server_info["version"] == "1.0"


def test_requests_before_initialise_are_refused() -> None:
    """Skipping the handshake would let a server be used before it declared what it supports."""
    subject, _ = client()
    with pytest.raises(ProviderError, match="initialise"):
        subject.list_tools()
    with pytest.raises(ProviderError, match="initialise"):
        subject.call_tool("service.enumerate", {})


def test_tools_are_collected_across_pages() -> None:
    subject, transport = client()
    subject.initialize()
    tools = subject.list_tools()
    assert [tool["name"] for tool in tools] == ["service.enumerate", "log.read"]
    # The second page was requested with the cursor the first page returned.
    assert any(message.get("params", {}).get("cursor") == "1" for message in transport.sent)


def test_a_response_for_another_request_is_refused() -> None:
    """Mis-associating a result with a method is how output lands on the wrong capability."""
    def confused(message: dict[str, Any]) -> dict[str, Any] | None:
        if message.get("method") == "initialize":
            return {"jsonrpc": "2.0", "id": 9999, "result": {"serverInfo": {}}}
        return happy_server(message)

    subject, _ = client(confused)
    with pytest.raises(ProviderError, match="answered id"):
        subject.initialize()


def test_a_jsonrpc_error_response_is_raised() -> None:
    def erroring(message: dict[str, Any]) -> dict[str, Any] | None:
        if message.get("method") == "initialize":
            return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32603, "message": "boom"}}
        return happy_server(message)

    subject, _ = client(erroring)
    with pytest.raises(ProviderError, match="boom"):
        subject.initialize()


def test_notifications_are_sent_without_an_id() -> None:
    subject, transport = client()
    subject.initialize()
    notifications = [m for m in transport.sent if m.get("id") is None]
    assert notifications and notifications[0]["method"] == "notifications/initialized"


# -- the provider wrapper ---------------------------------------------------------------------


def grant() -> Grant:
    from datetime import timedelta

    from harness.util import utcnow

    return Grant(
        id="g-mcp",
        resource="net:10.77.0.11",
        alias="lab-web-01",
        capabilities=["service.enumerate"],
        expires_at=utcnow() + timedelta(hours=1),
        origin="scope:test",
        kind="net",
    )


def test_provider_discovers_capabilities_from_the_servers_tool_list() -> None:
    subject, _ = client()
    provider = McpProvider.from_advertised_tools(
        provider_id="mcp:scanner-a", client=subject, capability_map={"service.enumerate": "service.enumerate"}
    )
    assert provider.spec.kind == "mcp"
    assert provider.spec.capabilities == ["service.enumerate"]
    # MCP output is remote by default; the spec must say so rather than being trusted.
    assert provider.spec.trust_class == "local_mcp"


def test_provider_refuses_a_capability_the_server_never_advertised() -> None:
    subject, _ = client()
    with pytest.raises(ValueError, match="does not advertise"):
        McpProvider.from_advertised_tools(
            provider_id="mcp:scanner-a", client=subject, capability_map={"http.probe": "http.probe"}
        )


def test_provider_wraps_a_tool_result_in_an_evidence_envelope() -> None:
    subject, _ = client()
    provider = McpProvider.from_advertised_tools(
        provider_id="mcp:scanner-a", client=subject, capability_map={"service.enumerate": "service.enumerate"}
    )
    result = provider.invoke(
        ProviderRequest.build(grant=grant(), capability="service.enumerate", run_id="run-mcp", args={})
    )
    assert result.exit_status == "completed"
    assert result.media_type == MEDIA_TYPE
    assert result.structured is not None
    import json

    envelope = json.loads(result.stdout.decode("utf-8"))
    assert envelope["capability"] == "service.enumerate"
    assert envelope["tool"] == "service.enumerate"
    # Only the alias crosses the boundary; the real resource never does.
    assert envelope["target_alias"] == "lab-web-01"
    assert "10.77.0.11" not in result.stdout.decode("utf-8")


def test_provider_turns_a_tool_error_into_a_gap() -> None:
    def failing(message: dict[str, Any]) -> dict[str, Any] | None:
        if message.get("method") == "tools/call":
            return ok(message, {"isError": True, "content": [{"type": "text", "text": "nope"}]})
        return happy_server(message)

    subject, _ = client(failing)
    provider = McpProvider.from_advertised_tools(
        provider_id="mcp:scanner-a", client=subject, capability_map={"service.enumerate": "service.enumerate"}
    )
    result = provider.invoke(
        ProviderRequest.build(grant=grant(), capability="service.enumerate", run_id="run-mcp", args={})
    )
    assert result.exit_status == "failed"
    assert result.gaps and result.gaps[0].kind == "provider_failure"


# -- a real process ---------------------------------------------------------------------------


def test_client_completes_a_handshake_with_a_real_subprocess() -> None:
    """The one test that proves the framing works over a pipe rather than in a fake."""
    transport = StdioTransport([sys.executable, str(HELPER_SERVER)])
    subject = McpStdioClient(transport, default_timeout_s=20.0)
    try:
        subject.initialize()
        assert subject.server_info["name"] == "fake-scanner"
        tools = subject.list_tools()
        assert {tool["name"] for tool in tools} == {"service.enumerate", "log.read"}
        result = subject.call_tool("service.enumerate", {"target": "lab-web-01"})
        observations = result["structuredContent"]["observations"]
        assert observations[0]["kind"] == "service"
        assert observations[0]["value"]["product"] == "OpenSSH"
    finally:
        subject.close()
