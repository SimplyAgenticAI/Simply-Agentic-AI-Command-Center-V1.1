"""Regression: /api/crm/lead_lab 500'd on every run (V9.6.11 fix).

A later `_uname = ...` assignment inside the streaming generator made `_uname`
a generator-local, so its first line raised UnboundLocalError before any
searching happened. Discovery is stubbed so this stays offline and fast.
"""
import app as app_module


def test_lead_lab_streams_results(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "_crm_discover_public_leads",
                        lambda *a, **k: [{"name": "Test Roofing", "domain": "testroofing.example", "email": "hi@testroofing.example"}])
    uname = "leadlabtester"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()

    c = flask_app.test_client()
    tok = c.get("/api/csrf_token").get_json()["csrf_token"]
    with c.session_transaction() as s:
        s["user"] = uname
    r = c.post("/api/crm/lead_lab", json={"niche": "regression-roofers", "location": "Nowhere, ZZ", "lead_count": 5},
               headers={"X-CSRF-Token": tok})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert '"ok": true' in body and "Test Roofing" in body
    assert "Lead Lab server error" not in body
