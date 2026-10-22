"""V13.4: 'email all my clients' writes one personal draft per contact into an
Email Console queue; each send goes only to that contact's own saved email.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import pytest

import app as app_module


@pytest.fixture()
def eb(flask_app, monkeypatch):
    uname = "batchuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    monkeypatch.setattr(app_module, "_agent_draft_email",
                        lambda u, cl, purpose: (f"Hi {cl.get('name')}", f"Dear {cl.get('name')}, {purpose}"))
    sent = []
    monkeypatch.setattr(app_module, "_crm_send_email_to",
                        lambda user, to, subject, body: (sent.append((to, subject, body)) or (True, "smtp", "")))
    app_module._crm_save(uname, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    for name, email in (("Ann", "ann@example.com"), ("Bob", "bob@example.com"), ("NoMail", "")):
        assert c.post("/api/crm/clients", headers=h, json={"name": name, "email": email}).get_json()["ok"]
    yield c, h, uname, sent
    data = app_module.load_users()
    (data.get("users") or {}).pop(uname, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def test_one_personal_draft_per_contact_with_email(eb):
    c, h, uname, sent = eb
    r = app_module._execute_teammate_tool("draft_emails_to_contacts", {"purpose": "holiday hours"}, uname, "Sunshine")
    assert r["ok"] and r["count"] == 2
    assert "personal emails in your email console" in r["summary"].lower()   # the page opens the console on this
    b = c.get("/api/email_batch").get_json()["batch"]
    assert [(i["name"], i["to"]) for i in b["items"]] == [("Ann", "ann@example.com"), ("Bob", "bob@example.com")]
    assert b["items"][0]["body"].startswith("Dear Ann")
    assert not sent   # drafting never sends


def test_send_uses_contacts_own_email_and_skip(eb):
    c, h, uname, sent = eb
    app_module._execute_teammate_tool("draft_emails_to_contacts", {"purpose": "x"}, uname, "Sunshine")
    bid = c.get("/api/email_batch").get_json()["batch"]["id"]
    r = c.post(f"/api/email_batch/{bid}/0/send", headers=h, json={"subject": "Edited", "body": "Edited body"}).get_json()
    assert r["ok"] and sent == [("ann@example.com", "Edited", "Edited body")]
    assert c.post(f"/api/email_batch/{bid}/1/skip", headers=h).get_json()["status"] == "skipped"
    items = c.get("/api/email_batch").get_json()["batch"]["items"]
    assert [i["status"] for i in items] == ["sent", "skipped"]
    ann = next(x for x in app_module._crm_load(uname)["clients"].values() if x["name"] == "Ann")
    assert ann.get("last_contact")
    assert c.post(f"/api/email_batch/wrongid/0/send", headers=h).status_code == 404


def test_no_contacts_with_email(eb):
    c, h, uname, sent = eb
    r = app_module._execute_teammate_tool("draft_emails_to_contacts", {"purpose": "x", "tag": "nobody"}, uname, "Sunshine")
    assert not r["ok"]
