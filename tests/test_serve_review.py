"""Security review of orch-hub#37 (serve wiring + HubConfig, l2-serve). Each test pins one finding; ``xfail(strict)``
marks a gap that is still open (it turns red once fixed, so the marker is dropped with the fix)."""

from __future__ import annotations

import ast
import urllib.parse
from pathlib import Path

import pytest

import orch_hub
from orch_hub.config import HubConfig
from orch_hub.reconcile import reconcile_full_only

SRC = Path(orch_hub.__file__).parent
NAMES = {"dev", "dev_mode"}


def _dataclass_dev_defaults(tree: ast.AST) -> list[str]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for st in node.body:
                if (
                    isinstance(st, ast.AnnAssign)
                    and isinstance(st.target, ast.Name)
                    and st.target.id in NAMES
                    and st.value is not None
                ):
                    out.append(f"{node.name}.{st.target.id}")
    return out


def _literal_dev_kwargs(tree: ast.AST) -> list[int]:
    return [
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.keyword) and n.arg in NAMES and isinstance(n.value, ast.Constant)
    ]


# --- 1. the guard ----------------------------------------------------------------------------------------------------


def test_guard_gap_dataclass_field_default_is_not_seen_by_the_pr_guard():
    """P2-1: the PR's guard walks FunctionDef/Lambda only; a dataclass field (OpContext.dev_mode is one) with a default
    synthesises an __init__ default the ast walk never sees."""
    from test_hubconfig_guard import _defaulted

    tree = ast.parse("@dataclass\nclass C:\n    dev_mode: bool = True\n")
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.Lambda)]
    assert funcs == [] or all(_defaulted(f) == [] for f in funcs)  # the PR guard reports nothing
    assert _dataclass_dev_defaults(tree) == ["C.dev_mode"]  # the extension below does


def test_no_dataclass_dev_field_has_a_default():
    bad = []
    for path in sorted(SRC.rglob("*.py")):
        bad += [f"{path.relative_to(SRC)} {n}" for n in _dataclass_dev_defaults(ast.parse(path.read_text()))]
    assert not bad, bad


def test_no_literal_dev_keyword_outside_vector_generators():
    """A call site ``X(dev_mode=True)`` is the same accident as a default; only the vector generators may write one."""
    bad = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name.startswith("vectorgen"):
            continue
        bad += [f"{path.relative_to(SRC)}:{ln}" for ln in _literal_dev_kwargs(ast.parse(path.read_text()))]
    assert not bad, bad


def test_card_dev_marker_must_be_a_real_bool():
    for v in (None, 1, "true", 0):
        with pytest.raises(ValueError):
            HubConfig.from_card({"o": {"dev": v}}, listen="127.0.0.1:0")
    assert HubConfig.from_card({"o": {"dev": False}}, listen="127.0.0.1:0").dev is False


# --- 2. web listener ---------------------------------------------------------------------------------------------------


@pytest.mark.xfail(strict=True, reason="P2-2: trusted peers are not validated as IP addresses")
def test_trusted_peer_must_be_an_ip_address():
    """``_source`` compares the socket peer (an IP string) with the configured peers. A hostname never matches, so
    every request behind the edge gets the edge as its source: one shared sign-in rate bucket (lock-out DoS)."""
    with pytest.raises(ValueError):
        HubConfig(
            dev=True,
            listen="127.0.0.1:0",
            web_listen="127.0.0.1:0",
            trusted_peers=frozenset({"edge.internal"}),
            behind_edge=True,
            allowed_origins=frozenset({"https://hub.example"}),
        )


@pytest.mark.xfail(strict=True, reason="P2-3: allow_origin builds http://::1:PORT for an IPv6 loopback web listener")
def test_ipv6_loopback_dev_origin_matches_the_browser_host_header():
    """serve: ``api.allow_origin(f"http://{addr}:{port}")`` with addr ``::1``. Fails closed (every request is
    ``not_allowed``), so this is availability only, not a widening."""
    origin = f"http://{'::1'}:{8080}"
    assert urllib.parse.urlsplit(origin).netloc == "[::1]:8080"


# --- 3. reconcile ------------------------------------------------------------------------------------------------------


class _Reg:
    def __init__(self, modes, boom=False):
        import threading

        self.lock, self.modes, self.boom = threading.RLock(), modes, boom

    def mode(self, ws):
        if self.boom:
            raise RuntimeError("registry read failed")
        return self.modes.get(ws)


class _Seals:
    def __init__(self, live):
        self.live, self.retired = set(live), []

    def live_workspaces(self):
        return sorted(self.live)

    def retire(self, ws):
        self.retired.append(ws)


class _Views:
    def __init__(self, ws):
        self.ws, self.dropped = set(ws), []

    def workspaces(self):
        return sorted(self.ws)

    def drop(self, ws):
        self.dropped.append(ws)


def test_reconcile_never_touches_a_bound_full_workspace():
    reg = _Reg({"a" * 32: "full", "b" * 32: "selective"})
    seals, views = _Seals({"a" * 32, "b" * 32, "c" * 32}), _Views({"a" * 32, "c" * 32})
    reconcile_full_only(reg, seals, views)
    assert "a" * 32 not in seals.retired and "a" * 32 not in views.dropped
    assert seals.retired == ["b" * 32, "c" * 32] and views.dropped == ["b" * 32, "c" * 32]


@pytest.mark.xfail(strict=True, reason="P2-4: a registry error escapes reconcile and ends the 30 s retry thread")
def test_reconcile_survives_a_registry_error():
    """``registry.mode`` sits outside the per-step try; in serve's ``_retry`` loop (no try either) one raise ends the
    thread for the rest of the process: no more share-purge retries and no more wrap retire / view drop."""
    reconcile_full_only(_Reg({}, boom=True), _Seals({"a" * 32}), _Views(set()))
