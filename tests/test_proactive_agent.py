"""Proactive teammates (V11.4): morning standing jobs draft emails into
Ready for you, approvals send to the contact's own address, the trust dial
offers auto-send after unedited approvals, and jobs run once per day.
LLM, lead search and email are mocked."""
import json

import pytest

import app as app_module


@pytest.fixture()
def agent(flask_app, monkeypatch):
    uname = "agentuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda u, to, subj, body, from_name="": (sent.append((to, subj, body)) or True, "smtp", ""))
    # the model tries to pick a different recipient — it must be ignored
    monkeypatch.setattr(app_module, "call_llm", lambda *a, **k: json.dumps(
        {"subject": "Quick hello", "body": "Hi there, short note.", "to": "attacker@evil.example"}))
    monkeypatch.setattr(app_module, "_check_msg_limit", lambda u, p: (True, 0, 0, 0, 0, False))
    today = app_module._user_now_local(uname).strftime("%Y-%m-%d")
    app_module._crm_save(uname, {"clients": {
        "f1": {"id": "f1", "name": "Fay Due", "email": "fay@x.example", "pipeline_stage": "Interested", "next_followup": today},
        "f2": {"id": "f2", "name": "Gus Later", "email": "gus@x.example", "next_followup": "2999-01-01"}},
        "pipeline": {"stages": app_module._default_pipeline_stages()}})
    app_module._agent_path(uname).unlink(missing_ok=True)
    return c, h, uname, sent


def test_followups_job_drafts_for_approval_not_sends(agent):
    c, h, uname, sent = agent
    r = app_module._agent_run_job(uname, "followups")
    assert r == {"ok": True, "queued": 1, "sent": 0, "note": ""} and sent == []
    view = c.get("/api/agent").get_json()
    assert [a["client_name"] for a in view["approvals"]] == ["Fay Due"]
    assert view["approvals"][0]["to"] == "fay@x.example"
    assert app_module._agent_run_job(uname, "followups")["queued"] == 0       # no duplicate drafts
    assert all(f["name"] != "Fay Due" for f in c.get("/api/today").get_json()["followups"])


def test_approve_sends_to_contact_and_trust_dial(agent, monkeypatch):
    c, h, uname, sent = agent
    monkeypatch.setattr(app_module, "AGENT_TRUST_OFFER_AT", 2)
    app_module._agent_run_job(uname, "followups")
    aid = c.get("/api/agent").get_json()["approvals"][0]["id"]
    r = c.post(f"/api/agent/approvals/{aid}/approve", headers=h, json={}).get_json()
    assert r["ok"] and sent == [("fay@x.example", "Quick hello", "Hi there, short note.")]     # never the model's address
    cl = app_module._crm_load(uname)["clients"]["f1"]
    assert cl["last_contact"] and cl["next_followup"] > cl["last_contact"]
    assert c.post(f"/api/agent/approvals/{aid}/approve", headers=h, json={}).status_code == 404   # can't send twice
    # second unedited approval reaches the (patched) threshold → offer appears
    crm = app_module._crm_load(uname)
    crm["clients"]["f2"]["next_followup"] = "2000-01-01"
    app_module._crm_save(uname, crm)
    app_module._agent_run_job(uname, "followups")
    aid2 = c.get("/api/agent").get_json()["approvals"][0]["id"]
    r = c.post(f"/api/agent/approvals/{aid2}/approve", headers=h, json={}).get_json()
    assert r["offer"]["kind"] == "followup"
    # turn auto-send on → next job sends without asking
    c.post("/api/agent/settings", headers=h, json={"trust": "followup", "auto": True})
    crm = app_module._crm_load(uname)
    crm["clients"]["f1"]["next_followup"] = "2000-01-01"
    app_module._crm_save(uname, crm)
    r = app_module._agent_run_job(uname, "followups")
    assert r["sent"] == 1 and len(sent) == 3
    assert [a["client_name"] for a in c.get("/api/agent").get_json()["sent_for_you"]] == ["Fay Due"]


def test_edited_approval_resets_streak(agent):
    c, h, uname, sent = agent
    app_module._agent_run_job(uname, "followups")
    aid = c.get("/api/agent").get_json()["approvals"][0]["id"]
    c.post(f"/api/agent/approvals/{aid}/approve", headers=h, json={"subject": "Quick hello", "body": "My own words"})
    assert sent[-1][2] == "My own words"
    trust = {t["kind"]: t for t in c.get("/api/agent").get_json()["trust"]}
    assert trust["followup"]["streak"] == 0


def test_new_leads_job_uses_profile_and_drafts_intros(agent, monkeypatch):
    c, h, uname, sent = agent
    assert app_module._agent_run_job(uname, "new_leads")["ok"] is False      # no audience yet
    monkeypatch.setattr(app_module, "_load_operator_profile", lambda u: {"audience": "roofers in Austin, TX"})
    seen = {}

    def fake_find(u, tm, args):
        seen.update(args)
        return {"ok": True, "leads": [{"name": "Bob's Roofing", "company": "Bob's Roofing", "email": "bob@roof.example"}]}
    monkeypatch.setattr(app_module, "_tool_find_leads", fake_find)
    _orig_llm = app_module.call_llm
    monkeypatch.setattr(app_module, "call_llm",                                # V15.2 quality check passes it;
                        lambda system, msgs, **k: '{"keep": [0]}' if "Candidate leads" in msgs[0]["content"]
                        else _orig_llm(system, msgs, **k))                   # drafting keeps the fixture's stub
    r = app_module._agent_run_job(uname, "new_leads")
    assert r["ok"] and r["queued"] == 1 and seen["niche"] == "roofers" and seen["location"] == "Austin, TX"
    assert seen["strict"] is True                                              # no filler in the automatic run
    ap = c.get("/api/agent").get_json()["approvals"]
    assert any(a["kind"] == "intro" and a["to"] == "bob@roof.example" for a in ap)


def test_tick_runs_each_job_once_per_day(agent, monkeypatch):
    c, h, uname, sent = agent
    runs = []
    monkeypatch.setattr(app_module, "_agent_run_job", lambda u, k: runs.append((u, k)) or {"ok": True})
    d = app_module._agent_load(uname)
    for k in d["jobs"]:
        d["jobs"][k]["hour"] = 0
    d["jobs"]["new_leads"]["enabled"] = False
    app_module._agent_save(uname, d)
    app_module._agent_tick()
    app_module._agent_tick()
    assert [r for r in runs if r[0] == uname] == [(uname, "followups")]
