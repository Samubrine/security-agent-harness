"""MCP is a provider boundary, so it is tested as an unreliable remote peer.

Every test here assumes the server may misbehave: answering the wrong request, sending a line that is
not JSON, or reporting an error. A protocol client that only works against a correct server is a
client that turns a broker's bug into a fabricated finding.
"""

from __future__ import annotations

import json
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
        # The schemas are part of the advertisement: a provider holds the model to the arguments the
        # server declares, so a fake that omits them would be testing a server the harness cannot
        # describe (R2-23).
        read = {"name": "log.read", "inputSchema": {"type": "object", "properties": {"target": {}}}}
        enumerate_tool = {
            "name": "service.enumerate",
            "inputSchema": {"type": "object", "properties": {"target": {}}},
        }
        if message.get("params", {}).get("cursor"):
            return ok(message, {"tools": [read]})
        return ok(message, {"tools": [enumerate_tool], "nextCursor": "1"})
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


# -- the untrusted boundary: a server can send anything --------------------------------


def _parse(
    raw: dict[str, Any],
    *,
    target: str | None = None,
    tmp_path: Path | None = None,
    raw_override: bytes | None = None,
):
    """Feed one MCP envelope through the parser the way the runtime does.

    A real artifact store stands behind it because the parser refuses to run without provenance:
    an observation whose bytes nothing can cite is not evidence.
    """
    import json
    import tempfile

    from harness.artifacts import ArtifactStore
    from harness.models import ProviderExecution
    from harness.parsers.mcp_json import parse_mcp_json
    from harness.util import utcnow

    # `raw_override` exists for payloads a Python literal cannot express: an integer with more digits
    # than the interpreter will convert is exactly that.
    payload = raw_override if raw_override is not None else json.dumps(raw).encode("utf-8")
    store = ArtifactStore((tmp_path or Path(tempfile.mkdtemp())) / "run", "run-mcp")
    meta = store.put(payload, media_type=MEDIA_TYPE, producer="mcp:scanner-a")
    now = utcnow()
    execution = ProviderExecution(
        id="x-mcp",
        run_id="run-mcp",
        provider="mcp:scanner-a",
        capability="service.enumerate",
        grant="g-mcp",
        policy_decision="pd-1",
        necessity_decision="d-1",
        started_at=now,
        ended_at=now,
        exit_status="completed",
    )
    return parse_mcp_json(
        payload,
        execution=execution,
        run_id="run-mcp",
        artifact_digest=meta.digest,
        evidence_of=lambda start, end: [store.ref(meta.digest, byte_start=start, byte_end=end)],
        target=target,
    )


def _envelope(**result: Any) -> dict[str, Any]:
    """One MCP result envelope. `observations` defaults to an empty list, which is what the protocol
    says a server returning no evidence sends; a test that cares about the key being absent omits it.
    """
    result.setdefault("observations", [])
    return {"jsonrpc": "2.0", "id": 1, "result": result}


def test_an_unknown_gap_kind_is_recorded_as_partial_coverage() -> None:
    """A server could end a run by naming a gap badly: the kind went straight into `EvidenceGap`."""
    parsed = _parse(_envelope(gaps=[{"kind": "server_error", "impact": "the scanner fell over"}]))

    assert [gap.kind for gap in parsed.gaps] == ["partial_coverage"]
    assert parsed.gaps[0].scope["reported_kind"] == "server_error"
    assert "server_error" in parsed.gaps[0].impact


def test_a_non_object_gap_scope_is_tolerated() -> None:
    parsed = _parse(_envelope(gaps=[{"kind": "partial_coverage", "scope": "not an object"}]))
    assert parsed.gaps[0].scope == {}


@pytest.mark.parametrize(
    "value",
    [
        {"cvss": "high"},
        {"severity": "SEVERE"},
        {"cpe": 1234},
        {"product": ["nginx"]},
    ],
)
def test_a_value_the_harness_reads_as_a_type_is_refused_with_a_gap(value: dict[str, Any]) -> None:
    """Each of these used to raise from a downstream `float()` or pydantic validator."""
    parsed = _parse(_envelope(observations=[{"kind": "service", "value": value}]))

    assert parsed.observations == []
    assert len(parsed.gaps) == 1
    assert parsed.gaps[0].kind == "partial_coverage"
    assert parsed.gaps[0].scope["index"] == 0


def test_a_typed_value_that_fits_is_accepted() -> None:
    """The companion: the check is about the types, not about refusing MCP evidence."""
    parsed = _parse(
        _envelope(
            observations=[
                {
                    "kind": "service",
                    "value": {"cvss": 9.8, "severity": "critical", "cpe": "cpe:/a:x:y:1", "version": "1"},
                }
            ]
        )
    )
    assert len(parsed.observations) == 1
    assert parsed.gaps == []
    assert parsed.observations[0].value["severity"] == "critical"


def test_the_runtime_target_wins_over_the_one_a_server_named() -> None:
    """A server naming its own host would otherwise put that host into a claim (R2-20)."""
    parsed = _parse(
        _envelope(
            observations=[{"kind": "service", "value": {"product": "nginx", "target": "10.77.0.99"}}]
        ),
        target="lab-web-01",
    )
    assert parsed.observations[0].value["target"] == "lab-web-01"
    assert "10.77.0.99" not in json.dumps(parsed.observations[0].value)


def test_a_result_without_an_observations_key_is_an_empty_result_gap() -> None:
    """A completed call that admits nothing must not look like a call that said nothing."""
    parsed = _parse({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"anything": True}}})
    assert parsed.observations == []
    assert [gap.kind for gap in parsed.gaps] == ["empty_result"]


def test_a_result_with_an_empty_observations_list_is_also_an_empty_result_gap() -> None:
    """And neither is silence: "I looked and found nothing" is a gap in the evidence."""
    parsed = _parse(_envelope(observations=[]))
    assert parsed.observations == []
    assert [gap.kind for gap in parsed.gaps] == ["empty_result"]


def test_a_server_that_only_sends_blank_lines_hits_the_timeout() -> None:
    """The documented hard timeout used to restart on every blank line (R2-22)."""
    from harness.errors import ProviderTimeout
    from harness.providers.mcp.client import StdioTransport

    # Slow enough that the deadline is what refuses the call, rather than the queue bound catching a
    # flood: both are refusals, and this test is about the timeout the client documents.
    slow_blanks = (
        "import sys, time\n"
        "while True:\n"
        "    sys.stdout.write('\\n')\n"
        "    sys.stdout.flush()\n"
        "    time.sleep(0.02)\n"
    )
    transport = StdioTransport([sys.executable, "-c", slow_blanks])
    try:
        with pytest.raises(ProviderTimeout):
            transport.receive(0.5)
    finally:
        transport.close()


def test_a_tool_refuses_an_argument_it_never_declared(tmp_path: Path) -> None:
    """`{**args, "target": alias}` forwarded model-chosen keys to a tool that honoured them (R2-23)."""
    subject, _ = client()
    provider = McpProvider.from_advertised_tools(
        provider_id="mcp:scanner-a", client=subject, capability_map={"service.enumerate": "service.enumerate"}
    )
    assert provider.tool_arguments["service.enumerate"] == {"target"}
    assert provider.spec.input_schema["additionalProperties"] is False

    refused = provider.invoke(
        ProviderRequest.build(
            grant=grant(),
            capability="service.enumerate",
            run_id="run-mcp",
            args={"totally_unknown_arg": "junk"},
        )
    )
    assert refused.exit_status == "denied"
    assert refused.gaps and refused.gaps[0].kind == "partial_coverage"

    allowed = provider.invoke(
        ProviderRequest.build(grant=grant(), capability="service.enumerate", run_id="run-mcp", args={})
    )
    assert allowed.exit_status == "completed"


def test_a_cvss_too_large_to_be_a_float_is_a_gap_not_an_exception() -> None:
    """A JSON integer has no size limit, and `float()` on a huge one raises OverflowError.

    The parser's contract is that no payload can raise: a remote server sending this would otherwise
    have its whole reply - including the observations that were fine - discarded as a provider
    failure (R2-19's rule, and the module docstring's claim).
    """
    parsed = _parse(
        _envelope(
            observations=[
                {"kind": "service", "value": {"cvss": 10**400, "product": "nginx"}},
                {"kind": "service", "value": {"product": "openssh", "version": "8.2p1"}},
            ]
        )
    )
    assert [obs.value["product"] for obs in parsed.observations] == ["openssh"]
    assert len(parsed.gaps) == 1
    assert parsed.gaps[0].scope["index"] == 0


def test_a_number_too_long_to_convert_is_a_gap_and_does_not_take_its_siblings_with_it() -> None:
    """`json.loads` refuses a 4300-digit literal and Python refuses to render one, both as bare errors.

    Either would escape a function whose contract is that no payload raises, and the `float()` the
    range check used to do raised `OverflowError` on a merely large integer. The conversion is bounded
    per number instead, so the value is rejected by name and the observations beside it survive.
    """
    huge = b"9" * 4400
    parsed = _parse(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "observations": [
                    {"kind": "service", "value": {"cvss": int("9" * 200), "product": "big"}},
                ]
            },
        },
        raw_override=b'{"jsonrpc":"2.0","id":1,"result":{"observations":['
        b'{"kind":"service","value":{"cvss":' + huge + b'}},'
        b'{"kind":"service","value":{"product":"nginx","version":"1.18.0"}}]}}',
    )
    assert [obs.value.get("product") for obs in parsed.observations] == ["nginx"]
    assert len(parsed.gaps) == 1
    assert "cvss is a number too long to convert" in parsed.gaps[0].impact
