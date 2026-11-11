#!/usr/bin/env python3
"""The agent loop.

objective -> model -> tool_use -> scope gate -> policy gate -> MCP -> observation
          -> transcript -> model -> ...

Everything the model can do is a tool in this file. Everything it is allowed to do is
decided by code it cannot edit at runtime. That separation is the whole design: the
model supplies judgement, the harness supplies limits.

Run:

    export AGENT_MODEL=<a model id your provider serves>
    python -m agent.loop --scope scope/scope.yaml \
        --objective "map the unauthenticated surface of the widget bootstrap endpoint"

Add --allow-writes only when the program brief covers state-changing tests, and
--dry-run to print the tool set and scope without calling a model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from agent.policy import Policy, Verdict
from evidence.capture import EvidenceBundle, scrub
from burp_mcp.client import BurpMCP, MCPError
from scope.guard import ScopeGuard, ScopeViolation

STATE_DIR = Path("state")

SYSTEM_PROMPT = """You are the reasoning layer of an authorised bug-bounty harness.

You are operating inside a program's scope. The scope rules below are enforced in code:
a request outside them is refused before it is sent, and you will see the refusal as a
tool error. Do not try to route around a refusal. Read the reason, correct your model of
the target, and continue inside the boundary.

{scope}

Working rules:

1. One hypothesis at a time. State it, then send the single request that would prove or
   kill it. A scattershot burst of requests teaches you nothing and looks like an attack.
2. Observed beats inferred. Never report a finding you have not seen in a response.
   If a test was blocked by the harness or failed for an environmental reason, say so
   and mark it unverified rather than assuming it worked.
3. The interesting bugs are in what the server trusts, not in what the client sends.
   When you see a parameter accepted without a gate, ask what downstream system trusts
   it, and whether that trust is the bug.
4. Before you call a finding, name the invariant that is broken and the request that
   proves it is unenforced. If you cannot name both, it is a lead, not a finding.
5. When you believe something is confirmed, call record_finding with the exact request
   and response. Do not paraphrase evidence.
6. Stop and report when the objective is met, when you have tested the objective's
   surface, or when the next step would need authorisation you do not have.

Be concise in your narration. The operator reads the transcript; they do not need a
preamble before each request."""


# --------------------------------------------------------------------- tools

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "scope_check",
        "description": (
            "Ask whether a request would be permitted, without sending it. Use this "
            "before working out an approach when you are unsure of the boundary."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP method"},
                "url": {"type": "string", "description": "Absolute URL"},
                "technique": {
                    "type": "string",
                    "description": "Optional test class, e.g. sqli, xss, race",
                },
            },
            "required": ["method", "url"],
        },
    },
    {
        "name": "http_request",
        "description": (
            "Send one raw HTTP/1.1 request through Burp and return the raw response. "
            "Every byte lands in the proxy history. The request must be in scope."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "request": {
                    "type": "string",
                    "description": (
                        "Complete raw request including the request line and headers, "
                        "e.g. 'GET /path HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n'"
                    ),
                },
                "host": {"type": "string", "description": "Target hostname"},
                "port": {"type": "integer", "description": "Target port, default 443"},
                "tls": {"type": "boolean", "description": "Use HTTPS, default true"},
            },
            "required": ["request", "host"],
        },
    },
    {
        "name": "proxy_history",
        "description": "Read recent Burp proxy history entries (offset, count).",
        "input_schema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "description": "Start index"},
                "count": {"type": "integer", "description": "How many entries"},
            },
            "required": ["offset"],
        },
    },
    {
        "name": "transform",
        "description": "URL- or base64-encode/decode a string.",
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {"type": "string"},
                "operation": {
                    "type": "string",
                    "enum": ["url_encode", "url_decode", "base64_encode", "base64_decode"],
                },
            },
            "required": ["value", "operation"],
        },
    },
    {
        "name": "record_finding",
        "description": (
            "Write a finding bundle to state/findings with the exact request and "
            "response you observed. Only call this for something you have seen."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "request": {"type": "string"},
                "response": {"type": "string"},
                "note": {"type": "string", "description": "Why this is a bug, in one paragraph"},
            },
            "required": ["title", "severity", "request", "response"],
        },
    },
]


class Harness:
    """Owns the gates, the MCP session, and the transcript."""

    def __init__(self, guard: ScopeGuard, policy: Policy, burp: BurpMCP, state_dir: Path):
        self.guard = guard
        self.policy = policy
        self.burp = burp
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        (self.state_dir / "findings").mkdir(exist_ok=True)
        self.transcript = (self.state_dir / "transcript.jsonl").open("a", encoding="utf-8")

    # -- transcript ------------------------------------------------------
    def log(self, kind: str, payload: dict[str, Any]) -> None:
        self.transcript.write(
            json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind, **payload})
            + "\n"
        )
        self.transcript.flush()

    # -- gates -----------------------------------------------------------
    def _gate(self, method: str, url: str, tool: str, arguments: dict[str, Any], technique: str | None = None) -> None:
        decision = self.guard.check(method, url, technique)
        self.log("scope", {"tool": tool, "method": method, "url": url, "allowed": decision.allowed, "reason": decision.reason, "rule": decision.rule})
        if not decision:
            raise ScopeViolation(decision)

        verdict = self.policy.review(tool, arguments, method=method)
        self.log("policy", {"tool": tool, "allowed": verdict.allowed, "reason": verdict.reason})
        if not verdict:
            raise PermissionError(f"policy refused: {verdict.reason}")

    # -- tools -----------------------------------------------------------
    def scope_check(self, arguments: dict[str, Any]) -> str:
        decision = self.guard.check(
            arguments.get("method", "GET"),
            arguments.get("url", ""),
            arguments.get("technique"),
        )
        return f"{'ALLOW' if decision.allowed else 'DENY'} [{decision.rule}] {decision.reason}"

    def http_request(self, arguments: dict[str, Any]) -> str:
        raw = arguments.get("request", "")
        host = arguments.get("host", "")
        port = int(arguments.get("port", 443))
        tls = bool(arguments.get("tls", True))

        method, path = _parse_request_line(raw)
        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}{path}"
        self._gate(method, url, "http_request", arguments)

        if "\r\n" not in raw and "\n" in raw:
            raw = raw.replace("\n", "\r\n")
        result = self.burp.call_tool(
            "send_http1_request",
            {
                "content": raw,
                "targetHostname": host,
                "targetPort": port,
                "usesHttps": tls,
            },
        )
        self.log("http", {"url": url, "ok": result.ok, "response": scrub(result.text)[:4000]})
        return result.text if result.ok else f"tool error: {result.text}"

    def proxy_history(self, arguments: dict[str, Any]) -> str:
        self._gate("GET", "https://burp.local/proxy-history", "proxy_history", arguments)
        result = self.burp.call_tool(
            "get_proxy_http_history",
            {"offset": int(arguments.get("offset", 0)), "count": int(arguments.get("count", 20))},
        )
        return result.text

    def transform(self, arguments: dict[str, Any]) -> str:
        operation = arguments.get("operation", "url_encode")
        result = self.burp.call_tool(operation, {"content": arguments.get("value", "")})
        return result.text

    def record_finding(self, arguments: dict[str, Any]) -> str:
        bundle = EvidenceBundle(
            title=arguments.get("title", "untitled"),
            severity=arguments.get("severity", "unrated"),
            scope_decision="recorded by agent after a permitted request",
            request=arguments.get("request", ""),
            response=arguments.get("response", ""),
        )
        if arguments.get("note"):
            bundle.add_note(arguments["note"])
        path = bundle.write(self.state_dir / "findings")
        self.log("finding", {"title": bundle.title, "severity": bundle.severity, "path": str(path)})
        return f"written: {path}"

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        table: dict[str, Callable[[dict[str, Any]], str]] = {
            "scope_check": self.scope_check,
            "http_request": self.http_request,
            "proxy_history": self.proxy_history,
            "transform": self.transform,
            "record_finding": self.record_finding,
        }
        handler = table.get(name)
        if handler is None:
            return f"unknown tool: {name}"
        return handler(arguments)


# ------------------------------------------------------------------- helpers


def _parse_request_line(raw: str) -> tuple[str, str]:
    first = (raw.splitlines() or [""])[0].strip()
    parts = first.split()
    if len(parts) >= 2:
        return parts[0].upper(), parts[1]
    return "GET", "/"


def _blocks_to_dicts(blocks: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for block in blocks:
        if block.type == "text":
            out.append({"type": "text", "text": block.text})
        elif block.type == "tool_use":
            out.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
    return out


# ---------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scope-locked agent loop over Burp MCP")
    parser.add_argument("--scope", default="scope/scope.yaml")
    parser.add_argument("--objective", required=False, default="")
    parser.add_argument("--model", default=os.environ.get("AGENT_MODEL", ""))
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--burp", default="http://127.0.0.1:9876/mcp")
    parser.add_argument("--allow-writes", action="store_true")
    parser.add_argument("--allow-risky", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    guard = ScopeGuard(args.scope)
    policy = Policy(allow_writes=args.allow_writes, allow_risky=args.allow_risky)

    if args.dry_run:
        print(guard.describe())
        print(f"\nwrites: {policy.allow_writes}, risky: {policy.allow_risky}")
        print("tools: " + ", ".join(t["name"] for t in TOOL_SPECS))
        return 0

    if not args.objective:
        parser.error("--objective is required unless --dry-run is set")
    if not args.model:
        parser.error("set AGENT_MODEL or pass --model (a model id your provider serves)")

    try:
        import anthropic
    except ImportError:
        print("pip install anthropic", file=sys.stderr)
        return 2

    burp = BurpMCP(args.burp)
    try:
        burp.initialize()
    except MCPError as exc:
        print(f"burp MCP unavailable: {exc}", file=sys.stderr)
        return 2

    harness = Harness(guard, policy, burp, STATE_DIR)
    client = anthropic.Anthropic()
    messages: list[dict[str, Any]] = [{"role": "user", "content": args.objective}]
    system = SYSTEM_PROMPT.format(scope=guard.describe())

    for step in range(1, args.max_steps + 1):
        response = client.messages.create(
            model=args.model,
            max_tokens=4096,
            system=system,
            tools=TOOL_SPECS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": _blocks_to_dicts(response.content)})

        for block in response.content:
            if block.type == "text" and block.text.strip():
                print(block.text.strip())

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            harness.log("stop", {"step": step, "reason": response.stop_reason})
            break

        results: list[dict[str, Any]] = []
        for block in tool_uses:
            try:
                output = harness.dispatch(block.name, dict(block.input or {}))
                is_error = False
            except (ScopeViolation, PermissionError) as exc:
                output = f"REFUSED: {exc}"
                is_error = True
            except MCPError as exc:
                output = f"MCP error: {exc}"
                is_error = True
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output,
                    "is_error": is_error,
                }
            )
            print(f"  → {block.name}: {'error' if is_error else 'ok'}")
        messages.append({"role": "user", "content": results})

    print(f"\nscope counts: {json.dumps(guard.counts())}")
    print(f"transcript: {STATE_DIR / 'transcript.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
