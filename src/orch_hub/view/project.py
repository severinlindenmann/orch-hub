"""A small projection of the logs the hub holds (workspace log, one ticket log) into exactly what the hub needs:
the member-list version, the workspace prefix and owner, the ticket's definition values, people, open questions.

This is NOT the F1 replay (protocol.md §10.7 "What the hub trusts"): it does not check who was allowed to sign what or
re-run authorization. It reads fields of events the host signed, and every value it derives is re-checked by the host
against its own log when the signed event arrives (§8.3 step 9). It also never reads body text or artifacts (not
synced in hv 0). Pure functions over decoded lines; any shape it cannot read is ``Refused("unavailable")``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..contract import phase4 as P4
from ..contract import suite as S
from ..contract.canon import CanonError, cj
from ..contract.hub import Refused

ROSTER_TYPES = ("workspace.created", "member.added", "member.removed", "role.changed")
TICKET_ROLES = ("ticket_owner", "assignees", "reviewers", "watchers")
_QUESTION = re.compile(r"Q[1-9][0-9]{0,5}")
_NO_HASH = "sha256:" + "00" * 32
_KEY = re.compile(r"([A-Z][A-Z0-9]{0,15})-([0-9]{1,9})")

#: ``ticket.json`` defaults for the seven paths a channel may ``set`` (ticket-format §3).
DEFAULTS: dict[str, Any] = {
    "ticket.title": None,
    "ticket.priority": "medium",
    "ticket.size": None,
    "ticket.labels": [],
    "ticket.due": None,
    "ticket.parent": None,
    "ticket.blocked_by": [],
}


def _bad() -> Refused:
    return Refused("unavailable")


def value_hash(value: Any) -> str:
    """``H("orch/v2/value|" || cj(value))`` (ticket-format §5.6): the ``base_rev`` of a ``ticket.json`` path."""
    try:
        return "sha256:" + S.sha256(b"orch/v2/value|" + cj(value)).hex()
    except CanonError:
        raise _bad() from None


def question_id(workspace_id: str, ticket_uid: str, question: str) -> str:
    """``qid``: first 16 bytes, 32 hex, of ``H("orch/v2/question-id|" || cj({workspace_id, ticket, question}))``."""
    body = {"workspace_id": workspace_id, "ticket": ticket_uid, "question": question}
    return S.sha256(b"orch/v2/question-id|" + cj(body))[:16].hex()


#: The question keys outside ``spec`` (ticket-format §5.6.1): routing and the two parts hashed on their own.
_NOT_SPEC = ("id", "to", "blocking", "text", "options")
#: What this hub can render and verify (design #1123 rev 4 §2). Any other kind, spec key or option key makes that ONE
#: question "unverifiable": shown, never answerable, the ticket stays.
KINDS = ("choice", "text")
SPEC_KEYS = frozenset({"kind", "why", "details", "recommended", "allow_other"})
OPTION_KEYS = frozenset({"key", "label", "text", "facts", "cost"})


def question_spec(question: Mapping[str, Any]) -> dict[str, Any]:
    """``spec``: every key of the raw question except ``id``, ``to``, ``blocking``, ``text``, ``options``."""
    return {k: v for k, v in question.items() if k not in _NOT_SPEC}


def question_hash(qid: str, ticket_uid: str, question: Mapping[str, Any]) -> str:
    """``H("orch/v2/question|" || cj({question_id, ticket, text, options, spec}))`` over the RAW question: ``options``
    is ``[]`` when absent, ``spec`` is :func:`question_spec`. The one hash entry (core ``canon.question_hash``); it
    hashes what it is given and checks no limits (:func:`renderable` is the reader's check)."""
    try:
        body = {
            "question_id": qid,
            "ticket": ticket_uid,
            "text": question["text"],
            "options": question.get("options") or [],
            "spec": question_spec(question),
        }
        return "sha256:" + S.sha256(b"orch/v2/question|" + cj(body)).hex()
    except CanonError, KeyError, TypeError:
        raise _bad() from None


def _str(x: Any) -> bool:
    return type(x) is str and x != ""


def _option_ok(o: Any) -> bool:
    if type(o) is not dict or not set(o) <= OPTION_KEYS or not (_str(o.get("key")) and _str(o.get("label"))):
        return False
    if not all(_str(o[k]) for k in ("text", "cost") if k in o):
        return False
    f = o.get("facts")
    return f is None or (
        type(f) is list
        and 1 <= len(f) <= 3
        and all(type(p) is list and len(p) == 2 and all(_str(v) for v in p) for p in f)
    )


def _clean(x: Any) -> bool:
    """No string in ``x`` holds a character :func:`~orch_hub.contract.phase4.render_text` would escape (a tab is the one
    other control core allows, in ``details``). Core's own text rule refuses these, so a clean question is shown verbatim
    and nothing hostile ever leaves the view raw."""
    if type(x) is str:
        flat = x.replace("\t", " ")
        return P4.render_text(flat) == flat
    if type(x) is list:
        return all(_clean(v) for v in x)
    if type(x) is dict:
        return all(_clean(v) for v in x.values())
    return True  # bool, None, numbers: not text


def renderable(q: Mapping[str, Any]) -> bool:
    """Whether this hub knows every part of the question well enough to show it and to check its hash: a known kind, only
    known spec and option keys, ``[label, value]`` facts arrays. Not the core limits (the host checked those)."""
    spec, opts = question_spec(q), q.get("options")
    kind = spec.get("kind")
    if (
        kind not in KINDS
        or not set(spec) <= SPEC_KEYS
        or not _str(q.get("text"))
        or not _clean([q["text"], opts, spec])
    ):
        return False
    if not all(_str(spec[k]) for k in ("why", "details") if k in spec) or (
        "allow_other" in spec and spec["allow_other"] is not True
    ):
        return False
    if kind == "text":
        return opts is None and "recommended" not in spec and "allow_other" not in spec
    if type(opts) is not list or not 2 <= len(opts) <= 6 or not all(_option_ok(o) for o in opts):
        return False
    keys = [o["key"] for o in opts]
    return len(set(keys)) == len(keys) and ("recommended" not in spec or spec["recommended"] in keys)


@dataclass
class Workspace:
    roster_v: int = 0
    prefix: str | None = None
    owner_person: str | None = None
    next_number: int = 1  # filled by the caller from the ticket keys it knows


def project_workspace(lines: list[dict[str, Any]]) -> Workspace:
    w = Workspace()
    for e in lines:
        t = e.get("type")
        if t in ROSTER_TYPES:
            w.roster_v += 1
        if t == "workspace.created":
            p, o = e.get("prefix"), e.get("owner")
            if type(p) is str and type(o) is dict and type(o.get("person")) is str:
                w.prefix, w.owner_person = p, o["person"]
    if not lines:
        raise _bad()
    return w


@dataclass
class Question:
    id: str
    qid: str
    hash: str
    obj: dict[str, Any]
    answered: bool = False
    verified: bool = True  # the hash recomputes from the raw question AND this hub can render every part of it


@dataclass
class Ticket:
    uid: str
    key: str = ""
    title: str = ""
    ticket_type: str = ""
    closed: bool = False
    values: dict[str, Any] = field(default_factory=lambda: dict(DEFAULTS))
    people: dict[str, list[str]] = field(default_factory=lambda: {r: [] for r in TICKET_ROLES})
    visibility: Any = "workspace"
    questions: dict[str, Question] = field(default_factory=dict)

    def next_question(self) -> str:
        n = max((int(q[1:]) for q in self.questions), default=0)
        return f"Q{n + 1}"


def project_ticket(lines: list[dict[str, Any]], workspace_id: str, uid: str) -> Ticket:
    """Replay of the ticket log's definition-level events. ``restore`` never appears in a view the hub accepted past a
    ``reset``, so it is not special here."""
    t = Ticket(uid)
    try:
        for e in lines:
            typ = e.get("type")
            if typ == "ticket.created":
                t.key, t.title, t.ticket_type = e["key"], e["title"], e["ticket_type"]
                t.values["ticket.title"] = e["title"]
                t.people["ticket_owner"] = [e["owner"]]
            elif typ == "ticket.updated":
                for path, v in (e.get("set") or {}).items():
                    if path in DEFAULTS:
                        t.values[path] = v
                if "ticket.title" in (e.get("set") or {}):
                    t.title = t.values["ticket.title"]
            elif typ == "ticket.closed":
                t.closed = True
            elif typ == "ticket.reopened":
                t.closed = False
            elif typ == "visibility.changed":
                t.visibility = e["visibility"]
            elif typ == "people.changed":
                role = "ticket_owner" if e["role"] == "owner" else e["role"]
                if role in t.people:
                    cur = [p for p in t.people[role] if p not in e["remove"]]
                    t.people[role] = sorted(set(cur) | set(e["add"])) if role != "ticket_owner" else (e["add"] or cur)
            elif typ == "question.asked":
                q = e["question"]
                qn = q["id"]
                if not _QUESTION.fullmatch(qn):
                    raise _bad()
                qid = question_id(workspace_id, uid, qn)
                try:
                    h: Any = question_hash(qid, uid, q)
                except Refused:
                    h = None
                claimed = e.get("hash")
                # a question that fails to verify stays in the ticket, marked: never shown as answerable, never drops it
                ok = h is not None and e.get("qid") == qid and claimed == h and renderable(q)
                t.questions[qn] = Question(qn, qid, claimed if P4._hash(claimed) else _NO_HASH, q, verified=ok)
            elif typ == "question.answered":
                q2 = t.questions.get(e["question"])
                if q2 is not None and q2.hash == e.get("hash"):
                    q2.answered = True
    except KeyError, TypeError, AttributeError, ValueError:
        raise _bad() from None
    if not t.key:
        raise _bad()
    return t


def key_number(key: Any) -> tuple[str, int] | None:
    m = _KEY.fullmatch(key) if type(key) is str else None
    return (m[1], int(m[2])) if m else None


def identities(w: Workspace, user_id: str, owner_alias: str | None) -> set[str]:
    """The person ids this hub user answers to: their ``u_`` id, plus the workspace owner's person id when the hub
    aliased the owner to this user (registry owner alias)."""
    me = {"u_" + user_id}
    if w.owner_person and owner_alias == user_id:
        me.add(w.owner_person)
    return me


def visible_to(t: Ticket, me: set[str]) -> bool:
    """The ONE visibility rule (needs-you AND build), core's ``can_see`` without membership: protocol.md §10.7
    "Visibility", vectors ``visible_*``. The ticket owner has no special standing."""
    return P4.visible(t.visibility, me)
