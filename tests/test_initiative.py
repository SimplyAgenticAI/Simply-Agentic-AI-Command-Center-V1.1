"""Agent initiative endpoint â€” rules-based CRM scan surfacing proactive suggestions."""
import pytest

import app as app_module


@pytest.fixture()
def auth_client(flask_app):
    """Own auth fixture (same pattern as test_tool_loop): register-or-login, so
    this file works whether or not another test file registered smoketest first."""
    with flask_app.test_client() as c:
        c.post("/register", data={
            "username": "smoketest", "email": "",
            "password": "TestPass123!", "password2": "TestPass123!",
            "tos_accepted": "on",
        }, follow_redirects=True)
        c.post("/login", data={"username": "smoketest", "password": "TestPass123!"},
               follow_redirects=True)
        c.csrf_token = c.get("/api/csrf_token").get_json()["csrf_token"]
        yield c


def test_initiative_requires_auth(client):
    r = client.get("/api/agent/initiative")
    assert r.status_code == 401


def test_initiative_surfaces_overdue_due_and_quiet(auth_client):
    uname = "smoketest"
    for nm, em in (("Overdue Olly", "olly@x.com"), ("Quiet Quinn", "quinn@x.com")):
        res = app_module._execute_teammate_tool("crm_add_client", {"name": nm, "email": em}, uname, "Alex")
        assert res["ok"], res
    crm = app_module._crm_load(uname)
    for c in crm["clients"].values():
        if c.get("name") == "Overdue Olly":
            c["next_followup"] = "2020-01-01"
        elif c.get("name") == "Quiet Quinn":
            c["last_contact"] = "2020-01-01"
    app_module._crm_save(uname, crm)

    r = auth_client.get("/api/agent/initiative")
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert 1 <= len(d["items"]) <= 3
    titles = " | ".join(i["title"] for i in d["items"])
    assert "Overdue Olly" in titles
    assert "Quiet Quinn" in titles
    for it in d["items"]:
        assert it["prompt"] and it["teammate"]
        # prompts must be self-contained: name the contact and the action
        assert it["client"] in it["prompt"]


def test_previously_broken_authed_endpoints_no_longer_500(auth_client):
    # DATA_DIR (str) was joined with / â€” TypeError -> 500 on every call since
    # launch. These must all succeed for a real authenticated session now.
    r = auth_client.get("/api/visuals")
    assert r.status_code == 200 and r.get_json()["ok"] is True

    r = auth_client.get("/api/analyze/reports")
    assert r.status_code == 200 and r.get_json()["ok"] is True

    r = auth_client.post("/api/analyze/reports", json={"url": "https://x.com", "analysis": {"score": 88}}, headers={"X-CSRF-Token": auth_client.csrf_token})
    assert r.status_code == 200 and r.get_json()["ok"] is True
    r = auth_client.get("/api/analyze/reports")
    assert any(rep.get("url") == "https://x.com" for rep in r.get_json()["reports"])

    # Without Stripe configured this must be a friendly page, never a 5xx.
    r = auth_client.get("/stripe/manage")
    assert r.status_code < 500


