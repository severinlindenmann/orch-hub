"""L2 (phase-4 contract pass, V3-D23) adversarial tests: orch-hub PR #22 at 5c04a8e. Each test asserts the behaviour the
review asks for and is marked ``xfail(strict=True)`` while the finding is open (state/l2-review-p4.md, L2P4-n); a fix
flips it to a pass and the marker must then go. A fix may change a call signature; keep the attack and the refusal."""

from __future__ import annotations

import pytest

from orch_hub.contract import hub as H
from orch_hub.contract import phase4 as P4
from orch_hub.contract import suite as S
from orch_hub.contract import vectorgen as G
from orch_hub.contract import vectorgen_p4 as GP

TICKET = G.TICKET


def _created(title: str) -> dict:
    return {"type": "ticket.created", "ticket_type": "feature", "title": title}


# --- L2P4-3: the text rule lets through private-use, unassigned and default-ignorable "blank" code points -------------


@pytest.mark.xfail(
    strict=True, reason="L2P4-3: Co (private use) passes the text rule; U+F8FF renders as a glyph on iOS"
)
def test_l2p4_3_text_rule_refuses_private_use():
    with pytest.raises(H.Refused) as r:
        P4.check_action(_created("Approve  payroll"), role="edit")
    assert r.value.code == "malformed"


@pytest.mark.xfail(strict=True, reason="L2P4-3: Cn (unassigned) passes; a newer Unicode may make it Cf (interop)")
def test_l2p4_3_text_rule_refuses_unassigned():
    with pytest.raises(H.Refused) as r:
        P4.check_action(_created("Fix ͸ login"), role="edit")
    assert r.value.code == "malformed"


@pytest.mark.xfail(strict=True, reason="L2P4-3: U+3164 HANGUL FILLER (Lo, Default_Ignorable) makes a blank title")
def test_l2p4_3_text_rule_refuses_blank_default_ignorable_title():
    for blank in ("ㅤ", "ᅟ", "ﾠ", "a͏", "x️"):
        with pytest.raises(H.Refused):
            P4.check_action(_created(blank), role="edit")


@pytest.mark.xfail(strict=True, reason="L2P4-3: a lone surrogate raises UnicodeEncodeError, not Refused('malformed')")
def test_l2p4_3_text_rule_lone_surrogate_is_a_refusal_not_a_crash():
    with pytest.raises(H.Refused) as r:
        P4.check_action(_created("a\ud800b"), role="edit")
    assert r.value.code == "malformed"


# --- L2P4-6: channel registration does not see the permanent channel revocation list ------------------------------------


@pytest.mark.xfail(strict=True, reason="L2P4-6: verify_channel_register takes no revoked_channels; §6.2 says permanent")
def test_l2p4_6_revoked_channel_key_cannot_register_again():
    reg = GP.register()
    revoked = [H.channel_id(S.public_bytes(S.key_from_seed(S.fake_seed("channel_alice_phone"))))]
    with pytest.raises(H.Refused) as r:
        P4.verify_channel_register(
            reg, hub_id=G.HUB_ID, challenge=GP.CHALLENGE, now_ms=G.NOW, dev_mode=True, revoked_channels=revoked
        )
    assert r.value.code == "channel_revoked"


# --- L2P4-9: a workspace-log reset leaves ticket lines that run ahead of the new workspace view -------------------------


@pytest.mark.xfail(strict=True, reason="L2P4-9: reset of the workspace log does not re-check held ticket ws_seq")
def test_l2p4_9_workspace_reset_does_not_keep_ticket_lines_ahead_of_it():
    wk = {1: GP.WK[1]}
    kw = {"workspace_id": G.WS_A, "wsk_pub": S.public_bytes(G.K.priv["wsk_a"]), "wk_epochs": wk}
    views: dict = {}
    for body in (GP.page("workspace", GP.WS_LINES), GP.page(TICKET, GP.TK_LINES)):
        views = P4.apply_view_page(views, body, **kw)
    assert len(views[TICKET]) == 2  # ticket seq 2 has ws_seq 2
    views = P4.apply_view_page(views, GP.page("workspace", GP.WS_LINES[:1], reset=True), **kw)
    assert len(views["workspace"]) == 1
    # the ticket view still holds a line with ws_seq 2 > the workspace view: it must be dropped or truncated
    assert len(views.get(TICKET, [])) <= 1
