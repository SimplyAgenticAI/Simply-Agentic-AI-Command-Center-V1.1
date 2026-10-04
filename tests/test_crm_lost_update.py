"""Regression (V9.7.6): editing a contact used to start a background thread
that re-loaded the whole CRM and saved it back later, silently erasing any
task / contact / note written in between. Rules now apply inline."""
import time

import app as app_module


def _client(flask_app, uname):
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    return c, h


def test_contact_edit_does_not_erase_following_writes(flask_app):
    c, h = _client(flask_app, "lostupdate")
    cid = c.post("/api/crm/clients", json={"name": "Pat", "email": "pat@example.com"}, headers=h).get_json()["client"]["id"]
    for i in range(5):
        c.post(f"/api/crm/clients/{cid}", json={"notes": f"edit {i}"}, headers=h)
        c.post("/api/crm/tasks", json={"title": f"task {i}", "due": "2030-01-01"}, headers=h)
    time.sleep(0.5)  # give any (former) background writer time to clobber
    titles = {t["title"] for t in (app_module._crm_load("lostupdate").get("tasks") or {}).values()}
    assert titles == {f"task {i}" for i in range(5)}, titles


def test_pipeline_rules_still_apply_on_update(flask_app):
    c, h = _client(flask_app, "rulesinline")
    osd = app_module._os_load("rulesinline")
    osd["pipeline_rules"] = [{"enabled": True, "trigger": "tag_present", "match": "hot", "action": "set_stage", "value": "Interested"}]
    app_module._os_save("rulesinline", osd)
    cid = c.post("/api/crm/clients", json={"name": "Lee"}, headers=h).get_json()["client"]["id"]
    d = c.post(f"/api/crm/clients/{cid}", json={"tags": ["hot"]}, headers=h).get_json()
    assert d["client"]["pipeline_stage"] == "Interested"
    assert app_module._crm_load("rulesinline")["clients"][cid]["pipeline_stage"] == "Interested"
