"""Fail-closed scope enforcement.

Every outbound request an agent makes passes through `ScopeGuard.check()` before it
reaches a tool. There is no "probably in scope" outcome: a request is either matched by
an explicit allow rule or it is denied, with the reason handed back to the model so it
can correct course instead of retrying blind.

Design notes that matter:

* The hostname comes from `urlsplit(...).hostname`, never `netloc`. That is what makes
  `https://api.example.com@evil.com/` resolve to `evil.com` and get denied, instead of
  the naive string check handing it a pass.
* `fnmatch` is used deliberately: `*.example.com` matches `a.example.com` and
  `a.b.example.com`, but never the apex `example.com`. Apex access needs its own entry.
  Wildcards that silently cover too much are how researchers lose programs.
* Technique is a first-class part of the check. A host can be in scope while a class of
  test is explicitly excluded, and the guard has to know the difference.
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence
from urllib.parse import urlsplit

import yaml


class ScopeConfigError(RuntimeError):
    """Scope file missing, malformed, or permissive in a way we refuse to run with."""


@dataclass(frozen=True)
class Decision:
    """The outcome of one scope check, carrying enough detail to log and to teach."""

    allowed: bool
    reason: str
    rule: str = ""

    def __bool__(self) -> bool:  # `if guard.check(...)` reads naturally
        return self.allowed


@dataclass
class _Bucket:
    """Token bucket, one per host, so a single target cannot be hammered."""

    rate: float
    capacity: float
    tokens: float = 0.0
    last: float = field(default=0.0)

    def take(self, now: float) -> bool:
        if self.last == 0.0:
            self.last = now
            self.tokens = self.capacity
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens < 1.0:
            return False
        self.tokens -= 1.0
        return True


class ScopeGuard:
    """Loads a scope file and answers one question: may this request be sent?"""

    def __init__(self, scope_path: str | Path, *, clock: Callable[[], float] = time.monotonic):
        self.path = Path(scope_path)
        self._clock = clock
        if not self.path.is_file():
            raise ScopeConfigError(f"scope file not found: {self.path}")

        try:
            raw = yaml.safe_load(self.path.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ScopeConfigError(f"scope file is not valid YAML: {exc}") from exc
        if not isinstance(raw, dict):
            raise ScopeConfigError("scope file must be a mapping at the top level")

        self.program: str = str(raw.get("program") or "unnamed")
        allowed = raw.get("allowed") or {}
        excluded = raw.get("excluded") or {}

        self.allowed_hosts: list[str] = [str(h).lower() for h in allowed.get("hosts", [])]
        if not self.allowed_hosts:
            # An empty allowlist means everything, which is the one thing we never run.
            raise ScopeConfigError(
                "scope file declares no allowed.hosts — refusing to start with an "
                "open scope; write the wildcard you were authorised for"
            )

        self.excluded_hosts: list[str] = [str(h).lower() for h in excluded.get("hosts", [])]
        self.excluded_paths: list[str] = [str(p) for p in excluded.get("paths", [])]
        self.allowed_schemes: set[str] = {
            str(s).lower() for s in allowed.get("schemes", ["https"])
        }
        self.allowed_methods: set[str] = {
            str(m).upper()
            for m in allowed.get("methods", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        }

        defaults = {"https": {443}, "http": {80}}
        self.allowed_ports: dict[str, set[int]] = {
            scheme: set(defaults.get(scheme, {443}))
            for scheme in self.allowed_schemes
        }
        for scheme, ports in (allowed.get("ports") or {}).items():
            self.allowed_ports[str(scheme).lower()] = {int(p) for p in ports}

        self.forbidden_techniques: set[str] = {
            str(t).lower() for t in raw.get("forbidden_techniques", [])
        }

        limits = raw.get("limits") or {}
        self.rps: float = float(limits.get("rps", 5))
        self.max_requests_per_host: int = int(limits.get("max_requests_per_host", 10_000))

        self._buckets: dict[str, _Bucket] = {}
        self._counts: dict[str, int] = {}

    # ---------------------------------------------------------------- checking

    def check(self, method: str, url: str, technique: str | None = None) -> Decision:
        """Return an allow/deny decision. Deny by default, always."""
        parts = urlsplit(url or "")
        scheme = (parts.scheme or "").lower()

        if not scheme:
            return Decision(False, "URL has no scheme; expected an absolute URL", "no-scheme")
        if scheme not in self.allowed_schemes:
            return Decision(
                False,
                f"scheme {scheme!r} not allowed (allowed: {sorted(self.allowed_schemes)})",
                "scheme",
            )

        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return Decision(False, "URL has no host", "no-host")

        if technique and technique.lower() in self.forbidden_techniques:
            return Decision(
                False,
                f"technique {technique!r} is excluded for this program",
                "technique",
            )

        denied_by = _first_match(host, self.excluded_hosts)
        if denied_by:
            return Decision(False, f"host {host} matches exclusion {denied_by}", "excluded-host")

        allowed_by = _first_match(host, self.allowed_hosts)
        if not allowed_by:
            return Decision(
                False,
                f"host {host} is not covered by any allowed.hosts entry",
                "not-in-scope",
            )

        try:
            port = parts.port
        except ValueError:
            return Decision(False, f"URL carries an unparsable port: {url}", "bad-port")
        scheme_ports = self.allowed_ports.get(scheme, set())
        effective_port = port or (443 if scheme == "https" else 80)
        if effective_port not in scheme_ports:
            return Decision(
                False,
                f"port {effective_port} not allowed for {scheme} "
                f"(allowed: {sorted(scheme_ports)})",
                "port",
            )

        path = parts.path or "/"
        blocked_path = _first_match(path, self.excluded_paths)
        if blocked_path:
            return Decision(False, f"path {path} matches exclusion {blocked_path}", "excluded-path")

        verb = (method or "").upper()
        if verb not in self.allowed_methods:
            return Decision(
                False,
                f"method {verb!r} not allowed (allowed: {sorted(self.allowed_methods)})",
                "method",
            )

        used = self._counts.get(host, 0)
        if used >= self.max_requests_per_host:
            return Decision(
                False,
                f"per-host request cap reached ({self.max_requests_per_host}) for {host}",
                "budget",
            )

        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _Bucket(rate=self.rps, capacity=max(1.0, self.rps))
            self._buckets[host] = bucket
        if not bucket.take(self._clock()):
            return Decision(
                False,
                f"rate limit hit for {host} ({self.rps:g} req/s); back off and retry later",
                "rate-limit",
            )

        self._counts[host] = used + 1
        return Decision(True, f"in scope via {allowed_by}", "allowed")

    def check_or_raise(self, method: str, url: str, technique: str | None = None) -> Decision:
        decision = self.check(method, url, technique)
        if not decision:
            raise ScopeViolation(decision)
        return decision

    # -------------------------------------------------------------- reporting

    def describe(self) -> str:
        """A compact scope summary, injected into the agent's system prompt."""
        lines = [
            f"program: {self.program}",
            f"allowed hosts: {', '.join(self.allowed_hosts)}",
            f"excluded hosts: {', '.join(self.excluded_hosts) or '(none)'}",
            f"excluded paths: {', '.join(self.excluded_paths) or '(none)'}",
            f"schemes: {', '.join(sorted(self.allowed_schemes))}",
            f"methods: {', '.join(sorted(self.allowed_methods))}",
            f"forbidden techniques: {', '.join(sorted(self.forbidden_techniques)) or '(none)'}",
            f"rate limit: {self.rps:g} req/s per host, cap {self.max_requests_per_host}/host",
        ]
        return "\n".join(lines)

    def counts(self) -> dict[str, int]:
        return dict(self._counts)


class ScopeViolation(PermissionError):
    """Raised when a caller insists on a request the guard refused."""

    def __init__(self, decision: Decision):
        super().__init__(f"{decision.reason} [{decision.rule}]")
        self.decision = decision


def _first_match(value: str, patterns: Sequence[str] | Iterable[str]) -> str | None:
    lowered = value.lower()
    for pattern in patterns:
        if fnmatch.fnmatchcase(lowered, str(pattern).lower()):
            return str(pattern)
    return None
