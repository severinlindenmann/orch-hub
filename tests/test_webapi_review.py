"""Adversarial tests from the Opus security review of D13 (l2-d13, hub#29). ``xfail(strict=True)`` marks a finding that
is still open: the test states the wanted behaviour and flips to a pass (strict = fails the run) once it is fixed, so the
fixer removes the marker."""

from __future__ import annotations

import os

import pytest
from test_webapi_core import sign_in_body
from webapi_helpers import ORIGIN, Web

from orch_hub.channels import service as CS
from orch_hub.webapi import api as A


@pytest.fixture
def w(tmp_path):
    web = Web(tmp_path)
    yield web
    web.close()


def _bad(w, user):
    return w.call(
        "POST", "/session", {"user_id": user, "password": "x" * 12, "totp": "000000", "client": "app"}, origin=None
    )


@pytest.mark.xfail(strict=True, reason="P1-1: anyone who knows a user id locks that user (hub-admins too) out")
def test_review_unauthenticated_peer_cannot_lock_out_a_hub_admin(w):
    # user ids are not secret: they are in every custodial event's actor ("u_<id>") that agents read in the workspace
    for _ in range(5):
        assert _bad(w, w.admin)[0] == 401
    s, o, _ = w.call("POST", "/session", sign_in_body(w, w.admin, client="app"), origin=None)
    assert s == 200, o


@pytest.mark.xfail(strict=True, reason="P1-1: no per-source or global cap before the scrypt work of a sign-in")
def test_review_sign_in_work_is_capped_across_user_ids(w, monkeypatch):
    calls = []
    real = CS._pw_hash
    monkeypatch.setattr(CS, "_pw_hash", lambda p, s: calls.append(1) or real(p, s))
    codes = [_bad(w, os.urandom(16).hex())[1]["error"] for _ in range(40)]  # 40 fresh ids, one source
    assert "rate_limited" in codes and len(calls) < 40


@pytest.mark.xfail(strict=True, reason="P2-1: cookie without the __Host- prefix and Path=/ can be tossed by a sibling")
def test_review_cookie_uses_host_prefix(w):
    s, _, h = w.call("POST", "/session", sign_in_body(w, w.ann), origin=ORIGIN)
    assert s == 200
    assert h["Set-Cookie"].startswith("__Host-") and "Path=/;" in h["Set-Cookie"] + ";"


@pytest.mark.xfail(
    strict=True, reason="P2-2: a session is not bound to its client kind; an app token works as a cookie"
)
def test_review_app_token_is_not_accepted_as_a_cookie(w):
    tok = w.login(w.ann)  # client: app
    s, _, _ = w.call("GET", "/session", token=tok, cookie=True)
    assert s == 401


@pytest.mark.xfail(strict=True, reason="P2-3: a refused user name leaves an orphan UK signing key behind")
def test_review_bad_user_name_creates_no_signing_key(w):
    admin = w.login(w.admin)
    ukdir = w.env.keys.state / "uk"
    before = set(os.listdir(ukdir)) if ukdir.exists() else set()
    s, o, _ = w.call("POST", "/admin/users", {"name": "bad\nname"}, token=admin)
    assert (s, o) == (400, {"error": "malformed"})
    assert set(os.listdir(ukdir)) == before


@pytest.mark.xfail(strict=True, reason="P2-4: _render escapes values but not object keys")
def test_review_render_escapes_keys_too():
    out = A._render({"a" + chr(0x202E) + "b": "x"})
    assert all(chr(0x202E) not in k for k in out)


def test_review_held_invariants(w):
    """What the review checked and found holding: no-Origin/null-Origin cookie writes refused, Origin on a bearer
    request still checked, revoke of an unknown id is forbidden_role, admin route needs the role, a removed admin's
    session dies."""
    ann = w.login(w.ann)
    for origin in (None, "null", "http://127.0.0.1:9000.evil"):
        assert w.call("DELETE", "/session", token=ann, cookie=True, origin=origin)[:2] == (
            403,
            {"error": "not_allowed"},
        )
    assert w.call("DELETE", "/session", token=ann, origin="null")[:2] == (403, {"error": "not_allowed"})
    assert w.call("POST", "/channels/" + "ab" * 16 + "/revoke", token=ann)[:2] == (403, {"error": "forbidden_role"})
    assert w.call("GET", "/admin/audit", token=ann)[:2] == (403, {"error": "forbidden_role"})
    admin = w.login(w.admin)
    w.env.acc.remove_member("hub-admin", w.admin)
    assert w.call("GET", "/admin/users", token=admin)[:2] == (403, {"error": "forbidden_role"})
