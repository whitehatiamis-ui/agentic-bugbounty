"""Minimal MCP client for the Burp Suite MCP Server extension.

Burp's extension speaks *streamable HTTP*, not the older `/sse` transport. Against
burp-suite 1.1.2 the working endpoint is `http://127.0.0.1:9876/mcp`; `/sse` answers
404 and the root path is the legacy SSE handshake. If you point this at `/sse` you get
`SSE error: Non-200 status code (404)` and no tools, which is the single most common
way this integration is misconfigured.

The client is deliberately small: no dependency beyond the standard library, one
session, one call at a time. An agent needs `tools/list` and `tools/call`; everything
else is Burp's problem.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_URL = "http://127.0.0.1:9876/mcp"
PROTOCOL_VERSION = "2025-06-18"


class MCPError(RuntimeError):
    """Transport or protocol failure talking to the MCP server."""


@dataclass
class ToolResult:
    ok: bool
    text: str
    raw: dict[str, Any]

    def __str__(self) -> str:
        return self.text


class BurpMCP:
    """One MCP session against the Burp extension, over streamable HTTP."""

    def __init__(self, url: str = DEFAULT_URL, *, timeout: float = 60.0, client_name: str = "agentic-bugbounty"):
        self.url = url
        self.timeout = timeout
        self.client_name = client_name
        self.session_id: str | None = None
        self.server_info: dict[str, Any] = {}
        self.protocol_version: str | None = None
        self._next_id = 0

    # ---------------------------------------------------------------- plumbing

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            headers["mcp-session-id"] = self.session_id

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
                content_type = response.headers.get("content-type", "")
                session_id = response.headers.get("mcp-session-id")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise MCPError(f"{self.url} returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise MCPError(
                f"cannot reach {self.url} ({exc.reason}) — is Burp running with the "
                "MCP Server extension enabled?"
            ) from exc

        if session_id:
            self.session_id = session_id

        # Notifications are answered with 202 and an empty body.
        if not body.strip():
            return {}

        if "text/event-stream" in content_type:
            return _last_event_json(body)
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise MCPError(f"server sent non-JSON body: {body[:200]!r}") from exc

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": self._id(), "method": method}
        if params is not None:
            payload["params"] = params
        reply = self._post(payload)
        if "error" in reply:
            error = reply["error"]
            raise MCPError(f"{method} failed: {error.get('message', error)}")
        return reply.get("result", {})

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._post(payload)

    # ------------------------------------------------------------------- API

    def initialize(self) -> dict[str, Any]:
        result = self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": self.client_name, "version": "1.0"},
            },
        )
        self.server_info = result.get("serverInfo", {})
        self.protocol_version = result.get("protocolVersion")
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, Any]]:
        result = self._request("tools/list")
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        result = self._request(
            "tools/call",
            {"name": name, "arguments": arguments or {}},
        )
        blocks = result.get("content") or []
        text = "\n".join(
            block.get("text", "") for block in blocks if isinstance(block, dict)
        ).strip()
        return ToolResult(ok=not result.get("isError", False), text=text, raw=result)

    def tool_names(self) -> list[str]:
        return [tool.get("name", "") for tool in self.list_tools()]

    # --------------------------------------------------------- context manager

    def __enter__(self) -> "BurpMCP":
        self.initialize()
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _last_event_json(body: str) -> dict[str, Any]:
    """Return the last JSON-RPC message in an SSE-framed response body."""
    message: dict[str, Any] | None = None
    for event in body.replace("\r\n", "\n").split("\n\n"):
        data = [
            line[len("data:"):].lstrip()
            for line in event.split("\n")
            if line.startswith("data:")
        ]
        if not data:
            continue
        try:
            candidate = json.loads("\n".join(data))
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and "jsonrpc" in candidate:
            message = candidate
    if message is None:
        raise MCPError(f"no JSON-RPC message in SSE body: {body[:200]!r}")
    return message
