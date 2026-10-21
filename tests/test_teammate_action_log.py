"""Action log + undo (V12.5): every teammate tool call is recorded at the single
chokepoint, shows on Today via /api/agent, and Undo reverses exactly what that
action created — once, for its owner, within the undo window."""
from datetime import timedelta

import pytest

import app as app_module


def _login(flask_app, uname):
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    return c, h


@pytest.fixture()
def acts(flask_app):
    uname = "actionuser"
    c, h = _login(flask_app, uname)
    app_module._crm_save(uname, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    app_module._actions_path(uname).unlink(missing_ok=True)
    app_module._agent_path(uname).unlink(missing_ok=True)
    yield c, h, uname
    # Remove our users again (conftest's auth_client wants to be the first
    # registration, which is also why this file must sort after test_client_crud).
    data = app_module.load_users()
    for n in (uname, "intruder"):
        (data.get("users") or {}).pop(n, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _actions(c):
    return c.get("/api/agent").get_json()["actions"]


def test_tool_call_is_logged_and_bumps_rev(acts):
    c, h, uname = acts
    rev0 = c.get("/api/agent/rev").get_json()["rev"]
    res = app_module._execute_teammate_tool("crm_add_client", {"name": "Pat Kim", "email": "pat@x.example"}, uname, "Sunshine")
    assert res["ok"]
    assert c.get("/api/agent/rev").get_json()["rev"] > rev0
    a = _actions(c)[0]
    assert a["tool"] == "crm_add_client" and a["teammate"] == "Sunshine" and a["changes"] and a["can_undo"]
    assert a["source"] == "chat"


def test_undo_add_client_removes_only_that_contact(acts):
    c, h, uname = acts
    keep = app_module._execute_teammate_tool("crm_add_client", {"name": "Keep Me"}, uname, "Sunshine")
    gone = app_module._execute_teammate_tool("crm_add_client", {"name": "Remove Me"}, uname, "Sunshine")
    aid = _actions(c)[0]["id"]
    r = c.post(f"/api/actions/{aid}/undo", headers=h, json={})
    assert r.status_code == 200 and r.get_json()["ok"]
    clients = app_module._crm_load(uname)["clients"]
    assert gone["client_id"] not in clients and keep["client_id"] in clients
    # second click can't run it again
    r2 = c.post(f"/api/actions/{aid}/undo", headers=h, json={})
    assert r2.status_code == 400
    assert _actions(c)[0]["undone"] and not _actions(c)[0]["can_undo"]


def test_undo_add_client_drops_its_pending_draft(acts):
    c, h, uname = acts
    res = app_module._execute_teammate_tool("crm_add_client", {"name": "Lead Lo"}, uname, "Sunshine")
    with app_module._AGENT_LOCK:
        d = app_module._agent_load(uname)
        d["approvals"].append({"id": "a1", "status": "pending", "client_id": res["client_id"], "title": "Hello"})
        d["approvals"].append({"id": "a2", "status": "pending", "client_id": "other", "title": "Other"})
        app_module._agent_save(uname, d)
    aid = _actions(c)[0]["id"]
    assert c.post(f"/api/actions/{aid}/undo", headers=h, json={}).get_json()["ok"]
    ids = [a["id"] for a in app_module._agent_load(uname)["approvals"]]
    assert ids == ["a2"]


def test_undo_note_task_post_vault_notepad(acts):
    c, h, uname = acts
    cl = app_module._execute_teammate_tool("crm_add_client", {"name": "Note Target"}, uname, "Alex")
    app_module._execute_teammate_tool("crm_log_activity", {"client_id": cl["client_id"], "note": "keep"}, uname, "Alex")
    app_module._execute_teammate_tool("crm_log_activity", {"client_id": cl["client_id"], "note": "drop"}, uname, "Alex")
    note_aid = _actions(c)[0]["id"]
    assert c.post(f"/api/actions/{note_aid}/undo", headers=h, json={}).get_json()["ok"]
    notes = [e["detail"] for e in app_module._crm_activity_log(uname, cl["client_id"])]
    assert "keep" in notes and "drop" not in notes

    t = app_module._execute_teammate_tool("create_calendar_task", {"title": "Call", "date": "2030-01-02"}, uname, "Alex")
    assert c.post(f"/api/actions/{_actions(c)[0]['id']}/undo", headers=h, json={}).get_json()["ok"]
    assert all(x.get("id") != t["task_id"] for x in app_module._load_cal_tasks(uname))

    p = app_module._execute_teammate_tool("draft_social_post", {"caption": "Hi"}, uname, "Alex")
    assert c.post(f"/api/actions/{_actions(c)[0]['id']}/undo", headers=h, json={}).get_json()["ok"]
    assert all(x.get("id") != p["post_id"] for x in app_module._load_sp_posts(uname))

    v = app_module._execute_teammate_tool("save_to_vault", {"text": "reply"}, uname, "Alex")
    assert c.post(f"/api/actions/{_actions(c)[0]['id']}/undo", headers=h, json={}).get_json()["ok"]
    assert all(x.get("id") != v["id"] for x in app_module._vault_load(uname))

    n = app_module._execute_teammate_tool("add_to_notepad", {"content": "x"}, uname, "Alex")
    assert c.post(f"/api/actions/{_actions(c)[0]['id']}/undo", headers=h, json={}).get_json()["ok"]
    assert all(x.get("id") != n["note_id"] for x in app_module._load_notes(uname))


def test_published_post_is_not_deleted_by_undo(acts):
    c, h, uname = acts
    p = app_module._execute_teammate_tool("draft_social_post", {"caption": "Live"}, uname, "Alex")
    posts = app_module._load_sp_posts(uname)
    for x in posts:
        if x["id"] == p["post_id"]:
            x["status"] = "published"
    app_module._save_sp_posts(uname, posts)
    r = c.post(f"/api/actions/{_actions(c)[0]['id']}/undo", headers=h, json={})
    assert r.status_code == 400
    assert any(x["id"] == p["post_id"] for x in app_module._load_sp_posts(uname))
    assert _actions(c)[0]["can_undo"]   # claim released, not marked undone


def test_reads_and_failures_are_logged_but_not_undoable(acts):
    c, h, uname = acts
    app_module._execute_teammate_tool("crm_find_client", {"query": "nobody"}, uname, "Alex")
    app_module._execute_teammate_tool("crm_add_client", {}, uname, "Alex")   # fails: no name
    fail, read = _actions(c)[0], _actions(c)[1]
    assert not fail["ok"] and not fail["can_undo"]
    assert not read["changes"] and not read["can_undo"]


def test_old_actions_expire(acts, monkeypatch):
    c, h, uname = acts
    app_module._execute_teammate_tool("add_to_notepad", {"content": "old"}, uname, "Alex")
    real = app_module._utcnow
    monkeypatch.setattr(app_module, "_utcnow", lambda: real() + timedelta(days=app_module.ACTION_UNDO_DAYS + 1))
    aid = _actions(c)[0]["id"]
    assert not _actions(c)[0]["can_undo"]
    assert c.post(f"/api/actions/{aid}/undo", headers=h, json={}).status_code == 400


def test_cannot_undo_another_users_action(acts, flask_app):
    c, h, uname = acts
    app_module._execute_teammate_tool("crm_add_client", {"name": "Mine"}, uname, "Alex")
    aid = _actions(c)[0]["id"]
    c2, h2 = _login(flask_app, "intruder")
    assert c2.post(f"/api/actions/{aid}/undo", headers=h2, json={}).status_code == 400
    assert len(app_module._crm_load(uname)["clients"]) == 1


def test_meeting_undo_cancels_with_attendee_notice(acts, monkeypatch):
    c, h, uname = acts
    calls = []
    monkeypatch.setattr(app_module, "_calendar_creds_for_user", lambda u: ("tok", ""))
    monkeypatch.setattr(app_module, "_calendar_create_event", lambda *a, **k: {"id": "evt1", "hangoutLink": ""})
    monkeypatch.setattr(app_module, "_calendar_delete_event",
                        lambda tok, eid, calendar_id="primary", send_updates="": calls.append((eid, send_updates)) or (True, ""))
    app_module._execute_teammate_tool("book_meeting", {"title": "Sync", "date": "2030-01-02", "start": "10:00"}, uname, "Alex")
    a = _actions(c)[0]
    assert a["undo_label"] == "Cancel meeting"
    assert c.post(f"/api/actions/{a['id']}/undo", headers=h, json={}).get_json()["ok"]
    assert calls == [("evt1", "all")]


def test_sent_email_is_marked_irreversible(acts):
    c, h, uname = acts
    app_module._action_record(uname, "Sunshine", "send_email", {"ok": True, "summary": "Sent"}, "trigger")
    a = _actions(c)[0]
    assert a["irreversible"] and not a["can_undo"] and a["source"] == "trigger"


def test_undo_requires_csrf(acts):
    c, h, uname = acts
    app_module._execute_teammate_tool("add_to_notepad", {"content": "x"}, uname, "Alex")
    aid = _actions(c)[0]["id"]
    assert c.post(f"/api/actions/{aid}/undo", json={}).status_code in (400, 403)
    assert _actions(c)[0]["can_undo"]
