"""Hard limits applied before any tool call leaves the process.

The scope guard answers "may I touch this host". This module answers a different
question: "even if I may, is this action safe to do at all".

It blocks irreversible operations and DoS-shaped traffic. It deliberately does *not*
block attack payloads — a SQL injection probe with `xp_cmdshell` in it is the job.
What it blocks is the class of action that cannot be undone or that would take a
target down: shutting services off, dropping tables, unbounded destructive deletes,
mailing every address in a list. Those are not findings; they are incidents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Matched against the flattened string form of every tool argument.
DENY: tuple[tuple[str, str], ...] = (
    (r"(?i)\b(shutdown|poweroff|reboot|halt)\b", "service disruption"),
    (r"(?i)\b(drop|truncate)\s+(table|database|schema)\b", "destructive SQL"),
    (r"(?i)\bdelete\s+from\b(?![\s\S]*\bwhere\b)", "DELETE without WHERE"),
    (r"(?i)\brm\s+-rf\s+/(?!/)", "destructive filesystem operation"),
    (r"(?i)\b(mass|bulk)[-_ ]?(mail|sms|message)\b", "bulk messaging a real user base"),
    (r"(?i)\bfor\s+i\s+in\s+range\(\s*10{5,}", "unbounded loop"),
)

# Allowed, but only with --allow-risky: slow, noisy, or load-shaped.
REVIEW: tuple[tuple[str, str], ...] = (
    (r"(?i)\bsleep\s*\(\s*(?:[2-9]\d|[1-9]\d{2,})\s*\)", "long blocking call"),
    (r"(?i)\bpg_sleep\s*\(\s*(?:[2-9]\d|[1-9]\d{2,})\s*\)", "long blocking call"),
    (r"(?i)\bbenchmark\s*\(\s*\d{5,}", "load-shaped benchmark"),
    (r"(?i)\b(?:intruder|ffuf|gobuster|nuclei)\b", "high-volume scanning"),
)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    needs_review: bool = False

    def __bool__(self) -> bool:
        return self.allowed


class Policy:
    """Operator policy for one run."""

    def __init__(
        self,
        *,
        allow_writes: bool = False,
        allow_risky: bool = False,
        extra_deny: Iterable[tuple[str, str]] = (),
    ):
        self.allow_writes = allow_writes
        self.allow_risky = allow_risky
        self._deny = tuple(DENY) + tuple(extra_deny)
        self._review = tuple(REVIEW)

    def review(self, tool: str, arguments: dict[str, Any], *, method: str | None = None) -> Verdict:
        blob = _flatten(arguments)

        for pattern, label in self._deny:
            if re.search(pattern, blob):
                return Verdict(False, f"blocked: {label} (matched {pattern!r})")

        verb = (method or _guess_method(arguments) or "").upper()
        if verb in WRITE_METHODS and not self.allow_writes:
            return Verdict(
                False,
                f"{verb} is state-changing; rerun with --allow-writes once the program "
                "brief permits it",
                needs_review=True,
            )

        for pattern, label in self._review:
            if re.search(pattern, blob):
                if self.allow_risky:
                    return Verdict(True, f"allowed with --allow-risky: {label}")
                return Verdict(
                    False,
                    f"{label} needs --allow-risky ({pattern!r})",
                    needs_review=True,
                )

        return Verdict(True, "allowed")


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return "\n".join(_flatten(item) for item in value)
    return "" if value is None else str(value)


def _guess_method(arguments: dict[str, Any]) -> str | None:
    """Best-effort verb detection for tools that do not declare one."""
    for key in ("method", "http_method", "verb"):
        if key in arguments:
            return str(arguments[key])
    content = arguments.get("content") or arguments.get("request") or ""
    if isinstance(content, str) and content:
        first = content.splitlines()[0].strip()
        if first:
            return first.split(" ")[0]
    return None
