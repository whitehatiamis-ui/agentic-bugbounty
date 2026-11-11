"""Policy blocks irreversible actions, not attack payloads."""

from __future__ import annotations

from agent.policy import Policy


def test_get_allowed_by_default():
    assert Policy().review("http_request", {}, method="GET")


def test_write_blocked_without_flag():
    verdict = Policy().review("http_request", {"request": "POST /x HTTP/1.1"}, method="POST")
    assert not verdict and verdict.needs_review


def test_write_allowed_with_flag():
    assert Policy(allow_writes=True).review("http_request", {}, method="POST")


def test_method_guessed_from_raw_request():
    verdict = Policy().review("http_request", {"content": "DELETE /widgets/1 HTTP/1.1\r\n\r\n"})
    assert not verdict


def test_shutdown_blocked():
    assert not Policy(allow_writes=True).review("http_request", {"request": "POST /admin/shutdown"})


def test_drop_table_blocked():
    assert not Policy(allow_writes=True).review(
        "http_request", {"content": "id=1; DROP TABLE users--"}
    )


def test_delete_without_where_blocked():
    assert not Policy(allow_writes=True).review(
        "http_request", {"content": "q=DELETE FROM users"}
    )


def test_delete_with_where_allowed():
    # A scoped destructive statement inside a lab is ordinary testing.
    assert Policy(allow_writes=True).review(
        "http_request", {"content": "q=DELETE FROM sessions WHERE id=1"}
    )


def test_sqli_payload_is_not_censored():
    # xp_cmdshell is a valid probe, not an incident.
    assert Policy(allow_writes=True).review(
        "http_request", {"content": "id=1';EXEC xp_cmdshell('whoami')--"}
    )


def test_long_sleep_needs_risky_flag():
    payload = {"content": "id=1' AND SLEEP(30)--"}
    assert not Policy(allow_writes=True).review("http_request", payload)
    assert Policy(allow_writes=True, allow_risky=True).review("http_request", payload)


def test_short_sleep_allowed():
    assert Policy(allow_writes=True).review("http_request", {"content": "id=1 AND SLEEP(1)"})


def test_bulk_messaging_blocked():
    assert not Policy(allow_writes=True).review(
        "http_request", {"content": "POST /api/bulk-mail"}
    )


def test_scope_check_tool_untouched():
    assert Policy().review("scope_check", {"method": "GET", "url": "https://x/"})
