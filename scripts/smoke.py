#!/usr/bin/env python3
"""Prove the Burp connection works before you spend tokens hunting.

Checks, in order: the MCP endpoint answers, the session negotiates, tools are listed,
and one read-only tool call returns. Prints a one-line verdict per step so a failure
names itself instead of showing up later as a mystery refusal inside the agent loop.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from burp_mcp.client import BurpMCP, MCPError  # noqa: E402


def main() -> int:
    try:
        with BurpMCP() as burp:
            print(f"server: {burp.server_info} protocol: {burp.protocol_version}")
            names = burp.tool_names()
            print(f"tools: {len(names)}")
            if not names:
                print("FAIL: connected but the extension exposes no tools")
                return 1

            history = burp.call_tool("get_proxy_http_history", {"offset": 0, "count": 1})
            print(f"history call ok: {history.ok} | reply: {history.text[:80]}")

            encoded = burp.call_tool("url_encode", {"content": "a b&c"})
            print(f"url_encode ok: {encoded.ok} | {encoded.text}")
            return 0 if history.ok and encoded.ok else 1
    except MCPError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        print(
            "hint: the extension serves streamable HTTP at /mcp; /sse returns 404 on "
            "burp-suite 1.1.x",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
