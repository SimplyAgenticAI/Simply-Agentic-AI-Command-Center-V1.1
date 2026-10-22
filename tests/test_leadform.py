"""V14.9 Lead Form: public /f/<token> page + submit → contact + reply draft.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import pytest

import app as app_module

U = "leadformuser"


@pytest.fixture()
def lf(flask_app, monkeypatch):
    data = app_module.load_users()
    data.setdefault("users", {})[U] = {"username": U, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    app_module._crm_save(U, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    with app_module._AGENT_LOCK:
        d = app_module._agent_load(U); d["approvals"] = []; app_module._agent_save(U, d)
    monkeypatch.setattr(app_module, "_rate_limit_check", lambda key, limit: (True, ""))
    monkeypatch.setattr(app_module, "_agent_draft_email", lambda u, cl, purpose: ("Thanks for reaching out", f"Hi {cl['name']}!"))
    emitted = []
    monkeypatch.setattr(app_module, "_AGENT_EVENTS_ON", True)
    monkeypatch.setattr(app_module, "_AGENT_EVENTS_INLINE", True)
    monkeypatch.setattr(app_module, "_agent_handle_event", lambda u, ev, data: emitted.append(ev))
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = U
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    yield c, h, emitted
    data = app_module.load_users()
    (data.get("users") or {}).pop(U, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _token(c):
    return c.get("/api/leadform").get_json()["url"].rsplit("/", 1)[-1]


def test_settings_and_public_page_escape_and_embed(lf, flask_app):
    c, h, _ = lf
    r = c.post("/api/leadform", headers=h, json={"title": "<script>alert(1)</script>Book us", "company": True}).get_json()
    assert r["ok"] and r["form"]["company"] is True and "<iframe" in r["embed"]
    anon = flask_app.test_client()
    page = anon.get(f"/f/{_token(c)}?embed=1")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "<script>alert(1)" not in body and "&lt;script&gt;" in body and 'name="company"' in body
    assert "X-Frame-Options" not in page.headers and "frame-ancestors" in page.headers.get("Content-Security-Policy", "")


def test_submit_creates_contact_and_one_reply(lf, flask_app):
    c, h, emitted = lf
    c.post("/api/leadform", headers=h, json={"stage": "Lead", "tag": "site"})
    anon = flask_app.test_client()
    r = anon.post(f"/f/{_token(c)}", json={"name": "Jo Rivera", "email": "jo@example.com", "message": "Need a quote"})
    assert r.status_code == 200 and r.get_json()["ok"]
    clients = list(app_module._crm_load(U)["clients"].values())
    assert len(clients) == 1 and clients[0]["email"] == "jo@example.com" and "site" in clients[0]["tags"]
    appr = [a for a in app_module._agent_load(U)["approvals"] if a.get("status") == "pending"]
    assert len(appr) == 1 and appr[0]["kind"] == "form_reply" and appr[0]["to"] == "jo@example.com"
    assert emitted == []                                          # no extra generic "hello"
    # Same person again → note on the existing contact, not a duplicate
    anon.post(f"/f/{_token(c)}", json={"name": "Jo R", "email": "JO@example.com", "message": "Following up"})
    assert len(app_module._crm_load(U)["clients"]) == 1
    assert c.get("/api/leadform").get_json()["count"] == 2


def test_lead_magnet_file_download_and_reply(lf, flask_app, monkeypatch):
    import io
    c, h, _ = lf
    purposes = []
    monkeypatch.setattr(app_module, "_agent_draft_email", lambda u, cl, purpose: (purposes.append(purpose), ("Hi", "Hello"))[1])
    bad = c.post("/api/leadform/magnet", headers=h, data={"file": (io.BytesIO(b"x"), "evil.exe")}, content_type="multipart/form-data")
    assert bad.status_code == 400
    assert c.post("/api/leadform", headers=h, json={"magnet_on": True, "magnet_name": "X"}).status_code == 400   # nothing to give yet
    r = c.post("/api/leadform/magnet", headers=h, data={"file": (io.BytesIO(b"%PDF-1.4 guide"), "Pricing Checklist.pdf")},
               content_type="multipart/form-data").get_json()
    assert r["ok"] and r["form"]["magnet_filename"] == "Pricing Checklist.pdf" and r["form"]["magnet_name"] == "Pricing Checklist"
    assert c.post("/api/leadform", headers=h, json={"magnet_on": True}).get_json()["form"]["magnet_on"] is True
    anon = flask_app.test_client()
    tok = _token(c)
    page = anon.get(f"/f/{tok}").get_data(as_text=True)
    assert "FREE DOWNLOAD" in page and "Send me the Pricing Checklist" in page
    res = anon.post(f"/f/{tok}", json={"name": "Ana", "email": "ana@example.com"}).get_json()
    assert res["download_url"].startswith(f"/f/{tok}/d/") and res["download_name"] == "Pricing Checklist"
    assert "Pricing Checklist" in purposes[0]                                    # reply draft mentions it
    dl = anon.get(res["download_url"])
    assert dl.status_code == 200 and dl.get_data() == b"%PDF-1.4 guide" and "attachment" in dl.headers["Content-Disposition"]
    anon.get(res["download_url"])                                               # second download isn't logged again
    cid = next(iter(app_module._crm_load(U)["clients"]))
    logged = [a for a in app_module._crm_activity_log(U, cid) if "Downloaded" in str(a)]
    assert len(logged) == 1
    assert anon.get(res["download_url"] + "x").status_code == 410                 # tampered link


def test_lead_magnet_link_redirects(lf, flask_app):
    c, h, _ = lf
    assert c.post("/api/leadform", headers=h, json={"magnet_url": "javascript:alert(1)"}).status_code == 400
    assert c.post("/api/leadform", headers=h, json={"magnet_on": True, "magnet_name": "Guide", "magnet_url": "https://example.com/guide.pdf"}).get_json()["form"]["magnet_file"] == ""
    anon = flask_app.test_client()
    tok = _token(c)
    res = anon.post(f"/f/{tok}", json={"name": "Bo", "email": "bo@example.com"}).get_json()
    r = anon.get(res["download_url"])
    assert r.status_code == 302 and r.headers["Location"] == "https://example.com/guide.pdf"


def test_honeypot_bad_email_and_new_link(lf, flask_app):
    c, h, _ = lf
    tok = _token(c)
    anon = flask_app.test_client()
    assert anon.post(f"/f/{tok}", json={"name": "Bot", "email": "b@x.com", "hp_website": "spam.biz"}).get_json()["ok"]
    assert app_module._crm_load(U)["clients"] == {}
    assert anon.post(f"/f/{tok}", json={"name": "No Email", "email": "nope"}).status_code == 400
    new = c.post("/api/leadform", headers=h, json={"new_link": True}).get_json()["url"].rsplit("/", 1)[-1]
    assert new != tok and anon.get(f"/f/{tok}").status_code == 404 and anon.get(f"/f/{new}").status_code == 200
    c.post("/api/leadform", headers=h, json={"enabled": False})
    assert anon.get(f"/f/{new}").status_code == 404
