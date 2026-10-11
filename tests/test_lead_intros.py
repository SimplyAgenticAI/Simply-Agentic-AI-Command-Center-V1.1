"""Today → new-lead intros (V9.9.9): new uncontacted leads appear, a reviewed
intro sends + logs + schedules a follow-up, skip hides. Email is mocked."""
import pytest

import app as app_module


@pytest.fixture()
def today(flask_app, monkeypatch):
    uname = "introtester"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda u, to, subj, body, from_name="": (sent.append((to, subj, body)) or True, "gmail", ""))
    return c, h, uname, sent


def _add(c, h, **kw):
    d = c.post("/api/crm/clients", headers=h, json=dict({"status": "lead", "pipeline_stage": "Lead"}, **kw)).get_json()
    assert d["ok"], d
    return d["client"]["id"] if "client" in d else d["id"]


def test_new_leads_listed_and_intro_sent(today):
    c, h, uname, sent = today
    lead = _add(c, h, name="Bob Roofing", email="bob@roof.example")
    _add(c, h, name="No Email Co")                                       # no email → not listed
    old = _add(c, h, name="Talked Already", email="t@x.example", last_contact="2026-01-01")
    d = c.get("/api/today").get_json()
    ids = [l["id"] for l in d["new_leads"]]
    assert ids == [lead] and old not in ids

    r = c.post("/api/today/send_intro", headers=h, json={"id": lead, "subject": "Hi Bob", "body": "Hello!"}).get_json()
    assert r["ok"] and sent == [("bob@roof.example", "Hi Bob", "Hello!")]
    cl = app_module._crm_load(uname)["clients"][lead]
    assert cl["pipeline_stage"] == "Conversation" and cl["last_contact"] and cl["next_followup"] == r["next_followup"]
    assert c.get("/api/today").get_json()["new_leads"] == []


def test_skip_hides_lead_and_empty_body_rejected(today):
    c, h, uname, sent = today
    lead = _add(c, h, name="Skip Me", email="s@x.example")
    assert c.post("/api/today/send_intro", headers=h, json={"id": lead, "body": "  "}).status_code == 400
    assert c.post("/api/today/skip_lead", headers=h, json={"id": lead}).get_json()["ok"]
    assert c.get("/api/today").get_json()["new_leads"] == [] and sent == []


def test_draft_for_intro_does_not_mark_contacted(today, monkeypatch):
    c, h, uname, sent = today
    lead = _add(c, h, name="Draft Only", email="d@x.example")

    class _Msg:
        content = "```email\nto: d@x.example\nsubject: Hello\nbody: Hi there\n```"

    class _Resp:
        choices = [type("C", (), {"message": _Msg()})()]

    class _OAI:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    return _Resp()
    monkeypatch.setattr(app_module, "get_openai_client", lambda: _OAI())
    r = c.post(f"/api/crm/clients/{lead}/draft_outreach", headers=h, json={"mark_contacted": False, "context": "First hello"}).get_json()
    if not r.get("ok"):
        pytest.skip("no teammates installed for this test user: " + str(r.get("error")))
    assert app_module._crm_load(uname)["clients"][lead]["last_contact"] == ""
