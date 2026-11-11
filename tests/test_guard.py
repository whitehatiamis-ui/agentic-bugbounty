"""Scope guard has to fail closed. These tests are the proof that it does."""

from __future__ import annotations

import textwrap

import pytest

from scope.guard import ScopeConfigError, ScopeGuard, ScopeViolation

SCOPE = textwrap.dedent(
    """
    program: test-program
    allowed:
      hosts:
        - "*.topperpay.com"
        - topperpay.com
      schemes: [https]
      methods: [GET, POST]
      ports:
        https: [443]
    excluded:
      hosts:
        - "payments.topperpay.com"
      paths:
        - "/admin/*"
    forbidden_techniques:
      - dos
      - social-engineering
    limits:
      rps: 100
      max_requests_per_host: 50
    """
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def scope(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(SCOPE)
    return path


@pytest.fixture
def guard(scope):
    return ScopeGuard(scope, clock=Clock())


def test_subdomain_allowed(guard):
    assert guard.check("GET", "https://api.topperpay.com/v1/widgets")


def test_apex_allowed_when_listed(guard):
    assert guard.check("GET", "https://topperpay.com/")


def test_wildcard_does_not_cover_apex(tmp_path):
    path = tmp_path / "s.yaml"
    path.write_text("allowed:\n  hosts: ['*.example.com']\n")
    g = ScopeGuard(path)
    assert not g.check("GET", "https://example.com/")
    assert g.check("GET", "https://a.example.com/")
    assert g.check("GET", "https://a.b.example.com/")


def test_unrelated_host_denied(guard):
    decision = guard.check("GET", "https://evil.com/")
    assert not decision
    assert decision.rule == "not-in-scope"


def test_suffix_confusion_denied(guard):
    assert not guard.check("GET", "https://api.topperpay.com.evil.com/")


def test_userinfo_does_not_hide_host(guard):
    # urlsplit().hostname is what saves us here; netloc would read as allowed.
    assert not guard.check("GET", "https://api.topperpay.com@evil.com/")


def test_excluded_host_beats_allowlist(guard):
    decision = guard.check("GET", "https://payments.topperpay.com/")
    assert not decision
    assert decision.rule == "excluded-host"


def test_excluded_path(guard):
    assert not guard.check("GET", "https://api.topperpay.com/admin/shutdown")
    assert guard.check("GET", "https://api.topperpay.com/public")


def test_plain_http_denied(guard):
    decision = guard.check("GET", "http://api.topperpay.com/")
    assert not decision
    assert decision.rule == "scheme"


def test_non_default_port_denied(guard):
    assert not guard.check("GET", "https://api.topperpay.com:8443/")


def test_method_outside_allowlist(guard):
    decision = guard.check("DELETE", "https://api.topperpay.com/x")
    assert not decision
    assert decision.rule == "method"


def test_forbidden_technique(guard):
    decision = guard.check("GET", "https://api.topperpay.com/", technique="dos")
    assert not decision
    assert decision.rule == "technique"


def test_relative_url_denied(guard):
    assert not guard.check("GET", "/just/a/path")


def test_rate_limit_engages(scope):
    clock = Clock()
    g = ScopeGuard(scope, clock=clock)
    g.rps = 2.0
    assert g.check("GET", "https://api.topperpay.com/")
    assert g.check("GET", "https://api.topperpay.com/")
    third = g.check("GET", "https://api.topperpay.com/")
    assert not third and third.rule == "rate-limit"
    clock.now += 1.0
    assert g.check("GET", "https://api.topperpay.com/")


def test_per_host_cap(scope):
    g = ScopeGuard(scope, clock=Clock())
    g.max_requests_per_host = 2
    assert g.check("GET", "https://api.topperpay.com/")
    assert g.check("GET", "https://api.topperpay.com/")
    capped = g.check("GET", "https://api.topperpay.com/")
    assert not capped and capped.rule == "budget"


def test_empty_allowlist_refuses_to_start(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("program: x\nallowed:\n  hosts: []\n")
    with pytest.raises(ScopeConfigError):
        ScopeGuard(path)


def test_missing_file_refuses_to_start(tmp_path):
    with pytest.raises(ScopeConfigError):
        ScopeGuard(tmp_path / "nope.yaml")


def test_check_or_raise(guard):
    with pytest.raises(ScopeViolation):
        guard.check_or_raise("GET", "https://evil.com/")
