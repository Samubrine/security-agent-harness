"""A minimal, hand-written MCP client over stdio.

Hand-written rather than delegated to an SDK because the point of this boundary is that the harness
controls what leaves and what is accepted back: one request at a time, a hard timeout per request, a
refusal to skip protocol initialisation, and a transport protocol narrow enough that unit tests can
drive it with an in-process fake instead of spawning a process.

Frame format is newline-delimited JSON, per the stdio transport: one JSON-RPC 2.0 object per line.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from harness.errors import ProviderError, ProviderTimeout

JSONRPC_VERSION = "2.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"

#: The longest single frame this client will assemble. A server that streams a gigabyte without a
#: newline would otherwise be read into memory line by line before anyone could refuse it, and a
#: frame that long is a protocol error rather than a message (R2-22).
MAX_FRAME_BYTES = 4 * 1024 * 1024

#: How many complete frames may wait to be consumed. A server that answers faster than the client
#: asks is a protocol error too: the queue exists to decouple the reader thread from the request
#: loop, not to buffer an unbounded stream (R2-22).
MAX_QUEUED_FRAMES = 1024


@runtime_checkable
class McpTransport(Protocol):
    def send(self, message: dict[str, Any]) -> None: ...

    def receive(self, timeout_s: float) -> dict[str, Any]: ...

    def close(self) -> None: ...


class StdioTransport:
    """Spawns the server as an argv list and pumps its stdout on a reader thread.

    The reader thread is required because ``subprocess`` pipes are blocking: without it a request
    timeout could not be enforced, and a hung server would hold the run open -- exactly what the
    runner's timeout exists to prevent.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        if not command:
            raise ProviderError("an MCP stdio transport needs a command to run")
        self._command = list(command)
        self._queue: queue.Queue[bytes | None] = queue.Queue(maxsize=MAX_QUEUED_FRAMES)
        #: Why the reader thread stopped trusting the stream. Set from that thread and read by the
        #: request loop, so a server that floods or overruns the client fails the call instead of
        #: holding the run open.
        self._failure: str | None = None
        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            shell=False,
        )
        self._reader = threading.Thread(target=self._pump, name="mcp-stdout", daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        stream = self._process.stdout
        try:
            if stream is not None:
                while True:
                    frame = stream.readline(MAX_FRAME_BYTES)
                    if not frame:
                        break
                    if len(frame) >= MAX_FRAME_BYTES and not frame.endswith(b"\n"):
                        # Refusing here bounds what this client will hold: reading the rest of an
                        # over-long frame to report it would be the denial of service it avoids.
                        self._failure = (
                            f"the MCP server sent a frame longer than {MAX_FRAME_BYTES} bytes without "
                            "a newline; refusing to keep reading it"
                        )
                        break
                    self._offer(frame)
        finally:
            self._offer(None)

    def _offer(self, item: bytes | None) -> None:
        """Hand a frame to the request loop, or record why it cannot be queued."""
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            self._failure = (
                f"the MCP server produced more than {MAX_QUEUED_FRAMES} unanswered frames; refusing "
                "to buffer an unbounded stream"
            )

    def send(self, message: dict[str, Any]) -> None:
        stdin = self._process.stdin
        if stdin is None or self._process.poll() is not None:
            raise ProviderError("the MCP server is no longer running")
        payload = json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            stdin.write(payload.encode("utf-8"))
            stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ProviderError("the MCP server closed its input") from exc

    def receive(self, timeout_s: float) -> dict[str, Any]:
        # One deadline for this call, not one per frame: the loop below skips blank lines, and asking
        # the queue for a fresh timeout each time let a server hold the client open indefinitely by
        # sending nothing but newlines - the documented hard timeout never fired (R2-22).
        deadline = time.monotonic() + max(0.001, timeout_s)
        while True:
            if self._failure is not None:
                raise ProviderError(self._failure)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderTimeout(
                    "the MCP server did not answer within " + str(timeout_s) + "s"
                )
            try:
                item = self._queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise ProviderTimeout(
                    "the MCP server did not answer within " + str(timeout_s) + "s"
                ) from exc
            if item is None:
                raise ProviderError("the MCP server closed the connection")
            text = item.decode("utf-8", errors="replace").strip()
            if not text:
                # Blank lines are framing noise, not messages. Skipping them is not the same as
                # tolerating a malformed one -- and it is not a reason to extend the deadline.
                continue
            try:
                message = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ProviderError(
                    "the MCP server sent a line that is not JSON: " + repr(text[:120])
                ) from exc
            if not isinstance(message, dict):
                raise ProviderError("the MCP server sent a JSON value that is not an object")
            return message

    def close(self) -> None:
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except OSError:
            pass
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
        finally:
            self._reader.join(timeout=2)


class McpStdioClient:
    """One JSON-RPC request at a time, with initialisation treated as a precondition."""

    def __init__(
        self,
        transport: McpTransport,
        *,
        name: str = "security-agent-harness",
        version: str = "0.1.0",
        default_timeout_s: float = 30.0,
        max_tool_pages: int = 10,
    ) -> None:
        self._transport = transport
        self._name = name
        self._version = version
        self._timeout = default_timeout_s
        self._max_tool_pages = max_tool_pages
        self._next_id = 0
        self._initialized = False
        self._server_info: dict[str, Any] = {}

    @property
    def server_info(self) -> dict[str, Any]:
        return dict(self._server_info)

    def initialize(self) -> dict[str, Any]:
        if self._initialized:
            return dict(self._server_info)
        result = self._request(
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": self._name, "version": self._version},
            },
        )
        self._server_info = dict(result.get("serverInfo") or {})
        self._notify("notifications/initialized")
        self._initialized = True
        return dict(result)

    def list_tools(self) -> list[dict[str, Any]]:
        self._require_initialised()
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(self._max_tool_pages):
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params)
            page = result.get("tools")
            if not isinstance(page, list):
                raise ProviderError("the MCP server returned a tools/list result without a tools list")
            for entry in page:
                if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                    raise ProviderError("the MCP server returned a tool entry without a name")
                tools.append(entry)
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(
        self, name: str, arguments: dict[str, Any], *, timeout_s: float | None = None
    ) -> dict[str, Any]:
        self._require_initialised()
        result = self._request(
            "tools/call", {"name": name, "arguments": dict(arguments)}, timeout_s=timeout_s
        )
        if not isinstance(result, dict):
            raise ProviderError("the MCP server returned a non-object tool result")
        return result

    def close(self) -> None:
        self._transport.close()

    # -- internals ----------------------------------------------------------------------

    def _require_initialised(self) -> None:
        if not self._initialized:
            raise ProviderError(
                "the MCP client must complete the initialise handshake before any other request"
            )

    def _request(
        self, method: str, params: dict[str, Any], *, timeout_s: float | None = None
    ) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self._transport.send(
            {"jsonrpc": JSONRPC_VERSION, "id": request_id, "method": method, "params": params}
        )
        # One deadline for the whole request, computed once. Passing the full timeout on every loop
        # turn restarted the clock each time a frame arrived, so a server that answered slowly - or
        # sent blank lines forever - held the run open past the timeout it documents (R2-22).
        limit = timeout_s if timeout_s is not None else self._timeout
        deadline = time.monotonic() + limit
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderTimeout(
                    "the MCP server did not answer request " + str(request_id)
                    + " within " + str(limit) + "s"
                )
            message = self._transport.receive(remaining)
            if message.get("id") != request_id:
                # A response to a different request would silently mis-associate output with a
                # method, which is how a scanner's result ends up attached to the wrong capability.
                raise ProviderError(
                    "the MCP server answered id "
                    + repr(message.get("id"))
                    + " while "
                    + str(request_id)
                    + " was pending"
                )
            if "error" in message:
                raise ProviderError("MCP error from " + method + ": " + str(message["error"]))
            result = message.get("result")
            if not isinstance(result, dict):
                raise ProviderError("MCP " + method + " returned a non-object result")
            return result

    def _notify(self, method: str) -> None:
        self._transport.send({"jsonrpc": JSONRPC_VERSION, "method": method})
