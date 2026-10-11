"""First-run quickstart (V10.2): three answers → profile + objective saved,
real leads added to Contacts as new leads Today can welcome. Search is mocked."""
import time

import pytest

import app as app_module


@pytest.fixture()
def newbie(flask_app, monkeypatch):
    uname = "qsnewbie"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    return c, h, uname


def _wait(c, jid):
    for _ in range(100):
        j = c.get(f"/api/video/job/{jid}").get_json()
        if j.get("status") != "working":
            return j
        time.sleep(0.05)
    raise AssertionError("job timed out")


def test_quickstart_adds_leads_and_hides_itself(newbie, monkeypatch):
    c, h, uname = newbie
    assert c.get("/api/quickstart/status").get_json()["show"] is True
    seen = {}

    def fake_find(u, tm, args):
        seen.update(args)
        return {"ok": True, "leads": [
            {"name": "Bob's Roofing", "company": "Bob's Roofing", "email": "bob@roof.example", "phone": "", "website": "https://bob.example", "warm_reason": "No booking form"},
            {"name": "Ace Roofs", "company": "Ace Roofs", "email": "", "phone": "555-0100", "website": "", "warm_reason": ""},
            {"name": "Bob's Roofing", "company": "Bob's Roofing", "email": "bob@roof.example"}]}   # duplicate
    monkeypatch.setattr(app_module, "_tool_find_leads", fake_find)
    d = c.post("/api/quickstart", headers=h, json={"business": "Websites for contractors",
                                                  "customer": "roofers", "location": "Austin, TX"}).get_json()
    j = _wait(c, d["job_id"])
    assert j["ok"] and j["added"] == 2 and j["with_email"] == 1, j
    assert seen == {"niche": "roofers", "location": "Austin, TX", "count": 10}
    prof = app_module._load_operator_profile(uname)
    assert prof["business"] == "Websites for contractors" and prof["audience"] == "roofers in Austin, TX"
    assert "roofers" in app_module._os_load(uname)["session_objective"]["title"]
    today = c.get("/api/today").get_json()
    assert [l["name"] for l in today["new_leads"]] == ["Bob's Roofing"]       # the one with an email
    assert c.get("/api/quickstart/status").get_json()["show"] is False


def test_quickstart_needs_customer_and_skip_hides(newbie):
    c, h, uname = newbie
    assert c.post("/api/quickstart", headers=h, json={"business": "x"}).status_code == 400
    assert c.post("/api/quickstart/skip", headers=h).get_json()["ok"]
    assert c.get("/api/quickstart/status").get_json()["show"] is False


def test_quickstart_search_failure_is_reported(newbie, monkeypatch):
    c, h, uname = newbie
    monkeypatch.setattr(app_module, "_tool_find_leads", lambda u, t, a: {"ok": False, "summary": "You've used all 3 lead searches for today."})
    d = c.post("/api/quickstart", headers=h, json={"customer": "dentists"}).get_json()
    j = _wait(c, d["job_id"])
    assert not j["ok"] and "lead searches" in j["error"]
