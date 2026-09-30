"""Today screen aggregate (/api/today) + morning brief email tick (V9.6.9)."""
from datetime import date, timedelta

import app as app_module


def _h(c):
    return {"X-CSRF-Token": c.csrf_token}


def test_cal_task_recurrence_rules():
    occurs = app_module._cal_task_occurs_on
    mon = date(2026, 9, 28)  # a Monday
    assert occurs({"date": "2026-09-28", "recurring": "none"}, mon)
    assert not occurs({"date": "2026-09-27", "recurring": "none"}, mon)
    assert occurs({"date": "2026-09-01", "recurring": "daily"}, mon)
    assert not occurs({"date": "2026-10-01", "recurring": "daily"}, mon)  # before start
    assert occurs({"date": "2026-09-01", "recurring": "weekdays"}, mon)
    assert not occurs({"date": "2026-09-01", "recurring": "weekdays"}, mon + timedelta(days=5))  # Saturday
    assert occurs({"date": "2026-09-21", "recurring": "weekly"}, mon)
    assert not occurs({"date": "2026-09-21", "recurring": "biweekly"}, mon)
    assert occurs({"date": "2026-09-14", "recurring": "biweekly"}, mon)
    assert occurs({"date": "2026-09-01", "recurring": "custom", "recur_days": [1]}, mon)
    assert not occurs({"date": "2026-09-01", "recurring": "custom", "recur_days": [2]}, mon)
    assert occurs({"date": "2026-08-28", "recurring": "monthly"}, mon)
    assert not occurs({"date": "bad", "recurring": "daily"}, mon)


def test_today_aggregate_and_brief(flask_app, monkeypatch):
    # Own user: the shared "smoketest" account gets mutated by other tests in a full run
    c = flask_app.test_client()
    uname = "todaytester"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c.csrf_token = c.get("/api/csrf_token").get_json()["csrf_token"]
    with c.session_transaction() as sess:
        sess["user"] = uname
    assert c.get("/api/today").status_code == 200
    today = app_module._user_now_local(uname).date()
    past = (today - timedelta(days=3)).strftime("%Y-%m-%d")
    today_s = today.strftime("%Y-%m-%d")

    # A contact overdue for follow-up, a task due today, an overdue CRM task, a done task
    r = c.post("/api/crm/clients", json={"name": "Dana Follow", "email": "dana@example.com"}, headers=_h(c))
    assert "client" in r.get_json(), r.get_json()
    cid = r.get_json()["client"]["id"]
    c.post(f"/api/crm/clients/{cid}", json={"next_followup": past}, headers=_h(c))
    c.post("/api/cal/tasks", json={"title": "Write proposal", "date": today_s, "start": "10:00"}, headers=_h(c))
    c.post("/api/crm/tasks", json={"title": "Send invoice", "due": past}, headers=_h(c))
    done = c.post("/api/crm/tasks", json={"title": "Old thing", "due": past}, headers=_h(c)).get_json()["task"]
    c.post(f"/api/crm/tasks/{done['id']}", json={"status": "done"}, headers=_h(c))
    c.post("/api/os/session_objective", json={"title": "Close the Acme deal"}, headers=_h(c))

    d = c.get("/api/today").get_json()
    assert d["ok"] is True
    assert d["objective"] == "Close the Acme deal"
    assert d["calendar_connected"] is False
    titles = [t["title"] for t in d["tasks"]]
    assert "Write proposal" in titles and "Send invoice" in titles and "Old thing" not in titles
    assert titles[0] == "Send invoice"  # overdue sorts first
    assert [f["name"] for f in d["followups"]] == ["Dana Follow"]
    assert d["followups"][0]["days_overdue"] == 3

    # Patch the sender before enabling: the app's background scheduler thread
    # may run the tick at any moment once the brief is on.
    sent = []
    monkeypatch.setattr(app_module, "_send_platform_email", lambda to, subj, body: sent.append((to, subj, body)) or True)

    # Brief can't be enabled without an account email
    r = c.post("/api/today/brief_settings", json={"enabled": True, "hour": 0}, headers=_h(c))
    assert r.status_code == 400
    app_module.update_user(uname, lambda rec: rec.update({"email": "me@example.com"}) or rec)
    app_module._invalidate_users_cache()
    r = c.post("/api/today/brief_settings", json={"enabled": True, "hour": 0}, headers=_h(c))
    assert r.get_json()["ok"] is True

    app_module._daily_brief_tick()
    app_module._daily_brief_tick()  # same day: must not send twice
    assert len(sent) == 1
    to, subj, body = sent[0]
    assert to == "me@example.com"
    assert "Close the Acme deal" in body and "Dana Follow" in body and "Send invoice" in body

    # Turning it off stops sends
    c.post("/api/today/brief_settings", json={"enabled": False}, headers=_h(c))
    assert c.get("/api/today").get_json()["brief"]["enabled"] is False
