"""Regression tests for confirm-risk action binding (V8.2).

/api/teammate/action/execute used to run whatever action+args the client
posted, using the token only to visually close a card. So any script holding
the session could POST send_email with an arbitrary recipient — the agent
never had to propose it. Confirm-risk tools are now bound to a genuine pending
[confirm_action] card: consumed atomically by token, with the action verified.
"""
import json
import re
import types

import pytest

import app as app_module

# Reuse the streaming-loop scaffolding.
from test_tool_loop import (  # noqa: E402
    _FakeOAI, _msg, _toolcall, _resp, _setup, _post, tclient, _TUSER,
)


def _pending_card_token(teammate):
    """Pull the token out of the most recent [confirm_action] card in the thread."""
    thr = app_module.load_thread(teammate, _TUSER)
    for m in reversed(thr):
        c = m.get("content") or ""
        mt = re.search(r"\[confirm_action\]([\s\S]*?)\[/confirm_action\]", c)
        if mt:
            return json.loads(mt.group(1)).get("token")
    return None


def _propose_send_email(monkeypatch, tclient, to="client@real.com"):
    """Drive the agent to propose a send_email, producing a real pending card."""
    _setup(monkeypatch, [
        _resp(_msg("", [_toolcall("s1", "send_email",
                                  {"to": to, "subject": "Hi", "body": "Hello there"})])),
    ])
    _post(tclient, "Alex", "email the client")
    return _pending_card_token("Alex")


def _execute(tclient, **payload):
    payload.setdefault("teammate", "Alex")
    r = tclient.post("/api/teammate/action/execute", json=payload,
                     headers={"X-CSRF-Token": getattr(tclient, "csrf_token", "")})
    return r.status_code, r.get_json()


def test_send_email_with_valid_card_and_token_runs(monkeypatch, tclient):
    token = _propose_send_email(monkeypatch, tclient)
    assert token, "agent should have produced a pending card with a token"

    sent = {}
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda u, to, subj, body: (sent.update(to=to) or (True, "smtp", "")))
    status, d = _execute(tclient, action="send_email",
                         args={"to": "client@real.com", "subject": "Hi", "body": "Hello there"},
                         token=token)
    assert status == 200 and d.get("ok") is True
    assert sent.get("to") == "client@real.com"


def test_send_email_without_token_is_rejected(monkeypatch, tclient):
    _propose_send_email(monkeypatch, tclient)
    # An attacker script forging a send with no card token of its own.
    called = {"n": 0}
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (called.update(n=called["n"] + 1) or (True, "smtp", "")))
    status, d = _execute(tclient, action="send_email",
                         args={"to": "attacker@evil.com", "subject": "x", "body": "x"},
                         token="")
    assert status == 409 and not d.get("ok")
    assert called["n"] == 0, "no email may be sent without a bound card"


def test_send_email_with_bogus_token_is_rejected(monkeypatch, tclient):
    _propose_send_email(monkeypatch, tclient)
    called = {"n": 0}
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (called.update(n=called["n"] + 1) or (True, "smtp", "")))
    status, d = _execute(tclient, action="send_email",
                         args={"to": "attacker@evil.com", "subject": "x", "body": "x"},
                         token="deadbeefdead")
    assert status == 409 and called["n"] == 0


def test_token_is_single_use_no_double_send(monkeypatch, tclient):
    token = _propose_send_email(monkeypatch, tclient)
    calls = {"n": 0}
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda *a, **k: (calls.update(n=calls["n"] + 1) or (True, "smtp", "")))
    s1, d1 = _execute(tclient, action="send_email",
                      args={"to": "client@real.com", "subject": "Hi", "body": "Hello there"},
                      token=token)
    s2, d2 = _execute(tclient, action="send_email",
                      args={"to": "client@real.com", "subject": "Hi", "body": "Hello there"},
                      token=token)
    assert s1 == 200 and d1.get("ok")
    assert s2 == 409 and not d2.get("ok")
    assert calls["n"] == 1, "a replayed token must not send twice"


def test_token_bound_to_action_cannot_be_swapped(monkeypatch, tclient):
    """A token minted for a send_email card can't be redeemed as book_meeting."""
    token = _propose_send_email(monkeypatch, tclient)
    status, d = _execute(tclient, action="book_meeting",
                         args={"title": "x", "date": "2026-01-01", "time": "10:00"},
                         token=token)
    assert status == 409 and not d.get("ok")


def test_recipient_edit_before_send_is_honoured(monkeypatch, tclient):
    """The card lets the operator tweak the draft; a valid token still sends the
    client-supplied (edited) args — we bind the action, not freeze the args."""
    token = _propose_send_email(monkeypatch, tclient, to="typo@rea.com")
    sent = {}
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda u, to, subj, body: (sent.update(to=to) or (True, "smtp", "")))
    status, d = _execute(tclient, action="send_email",
                         args={"to": "fixed@real.com", "subject": "Hi", "body": "Hello there"},
                         token=token)
    assert status == 200 and d.get("ok")
    assert sent.get("to") == "fixed@real.com"
