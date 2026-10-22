"""Opus delta review of D13 round 2 (l2-c3, hub#29 5779c79). Strict xfail = an open finding; drop the marker when fixed."""

from __future__ import annotations

import pytest
from test_webapi_core import sign_in_body
from webapi_helpers import Web

from orch_hub.webapi import api as A


@pytest.fixture
def w(tmp_path):
    web = Web(tmp_path)
    yield web
    web.close()


def _try(w, user, peer, totp="000000", password="x" * 12):
    body = {"user_id": user, "password": password, "totp": totp, "client": "app"}
    return w.call("POST", "/session", body, origin=None, peer=peer)


@pytest.mark.xfail(
    strict=True, reason="D13r2-1: the global bucket is a hub-wide sign-in lockout a few sources can hold"
)
def test_r2_a_few_strangers_cannot_hold_the_global_sign_in_bucket(w, monkeypatch):
    monkeypatch.setattr(A, "SIGNIN_GLOBAL_LIMIT", (40, 60_000))  # the shape of 300/min with 15 sources, scaled down
    for i in range(2):
        for _ in range(20):
            _try(w, "0" * 32, f"203.0.113.{i + 1}")
    s, o, _ = w.call("POST", "/session", sign_in_body(w, w.admin, client="app"), origin=None, peer="198.51.100.7")
    assert s == 200, o


@pytest.mark.xfail(strict=True, reason="D13r2-2: an IPv6 source is one address, not its /64")
def test_r2_one_ipv6_host_is_one_source(w):
    codes = [_try(w, "0" * 32, f"2001:db8::{i:x}")[1].get("error") for i in range(1, 25)]
    assert "rate_limited" in codes


@pytest.mark.xfail(strict=True, reason="D13r2-3: with the password known, TOTP guesses are bounded per source only")
def test_r2_totp_guessing_with_a_known_password_is_bounded_per_user(w):
    codes = []
    for i in range(8):  # 8 sources x 4 guesses = 32 TOTP guesses; before round 2 it was 5 per user per 15 min
        for _ in range(4):
            codes.append(_try(w, w.ann, f"203.0.113.{i + 1}", password="correct horse battery")[1].get("error"))
    assert "rate_limited" in codes


@pytest.mark.xfail(strict=True, reason="D13r2-4: behind two trusted proxies the last XFF entry is the first proxy")
def test_r2_chained_trusted_proxies_yield_the_client(w):
    w.api.d.trusted_peers = frozenset({"10.0.0.1", "10.0.0.2"})
    src = w.api._source({"x-forwarded-for": "198.51.100.7, 10.0.0.2"}, "10.0.0.1")
    assert src == "198.51.100.7"


def test_r2_xff_from_an_untrusted_peer_or_spoofed_first_entry_is_ignored(w):
    """Holds: a direct peer is its own source; through the edge only the entry the edge appended counts."""
    w.api.d.trusted_peers = frozenset({"10.0.0.1"})
    assert w.api._source({"x-forwarded-for": "1.2.3.4"}, "203.0.113.5") == "203.0.113.5"
    assert w.api._source({"x-forwarded-for": "1.2.3.4, 198.51.100.7"}, "10.0.0.1") == "198.51.100.7"
    assert w.api._source({"x-forwarded-for": "not-an-ip"}, "10.0.0.1") == "10.0.0.1"


def test_r2_get_prepared_is_the_owners_only(w):
    """Holds: another user's id and an unknown id give the same answer; the read does not consume it."""
    s, o, _ = w.call("GET", "/sign/prepared/" + "a" * 32, token=w.login(w.ann))
    assert (s, o) == (404, {"error": "unknown_prepared"})
    s, o, _ = w.call("GET", "/sign/prepared/" + "a" * 32, token=w.login(w.admin))
    assert (s, o) == (404, {"error": "unknown_prepared"})
