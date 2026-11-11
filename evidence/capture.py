"""Evidence capture: turn a tool result into something a triager will accept.

A finding dies when the evidence is a screenshot of a terminal. The bundle this module
writes keeps the raw request and response byte-for-byte, hashes them so tampering is
visible, records the scope decision that permitted the request, and redacts secrets
without destroying the structure that proves the bug.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SECRET_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token")

_TOKEN_PATTERNS = (
    re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


def redact(value: str, keep: int = 4) -> str:
    """Keep a prefix/suffix so the reader can tell two values apart, hide the middle.

    A token redacted to `ghp_…GlWv` is still linkable across two requests — which is
    the whole evidential point — while no longer being a working credential.
    """
    if value is None:
        return ""
    text = str(value)
    if len(text) <= keep * 2:
        return "*" * len(text)
    return f"{text[:keep]}{'*' * (len(text) - keep * 2)}{text[-keep:]}"


def scrub(text: str) -> str:
    """Remove credentials that leaked into a body, message, or header line."""
    if not text:
        return ""
    cleaned = text
    for pattern in _TOKEN_PATTERNS:
        cleaned = pattern.sub(lambda m: redact(m.group(0)), cleaned)
    for header in SECRET_HEADERS:
        cleaned = re.sub(
            rf"(?im)^({re.escape(header)}\s*:\s*)(.+)$",
            lambda m: m.group(1) + redact(m.group(2).strip()),
            cleaned,
        )
    return cleaned


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


@dataclass
class EvidenceBundle:
    """One finding's worth of proof."""

    title: str
    severity: str = "unrated"
    scope_decision: str = ""
    request: str = ""
    response: str = ""
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def write(self, directory: str | Path) -> Path:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", self.title.lower()).strip("-")[:60] or "finding"

        (out / f"{slug}-request.http").write_text(self.request)
        (out / f"{slug}-response.http").write_text(self.response)

        meta = {
            "title": self.title,
            "severity": self.severity,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "scope_decision": self.scope_decision,
            "sha256": {
                "request": sha256(self.request),
                "response": sha256(self.response),
            },
            "notes": self.notes,
            **self.meta,
        }
        (out / f"{slug}-meta.json").write_text(json.dumps(meta, indent=2) + "\n")

        (out / f"{slug}.md").write_text(self._markdown(meta, slug))
        return out / f"{slug}.md"

    def _markdown(self, meta: dict[str, Any], slug: str) -> str:
        notes = "\n".join(f"- {n}" for n in self.notes) or "- (none)"
        return (
            f"# {self.title}\n\n"
            f"- Severity: {self.severity}\n"
            f"- Captured: {meta['captured_at']}\n"
            f"- Scope decision: {self.scope_decision or 'n/a'}\n"
            f"- Request sha256: `{meta['sha256']['request']}`\n"
            f"- Response sha256: `{meta['sha256']['response']}`\n\n"
            f"## Notes\n\n{notes}\n\n"
            f"## Request\n\n```http\n{scrub(self.request)}\n```\n\n"
            f"## Response\n\n```http\n{scrub(self.response)}\n```\n\n"
            f"Raw files: `{slug}-request.http`, `{slug}-response.http`, `{slug}-meta.json`.\n"
        )
