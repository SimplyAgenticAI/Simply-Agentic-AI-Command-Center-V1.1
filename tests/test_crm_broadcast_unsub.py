"""Email Broadcast (V11.1–11.2): no unsubscribe footer unless asked,
resubscribe, scheduled broadcasts send, and paced sending — one email at a
time with random gaps, a daily cap, Stop, and restart-safe (never resends).
Email sending is mocked."""
from datetime import timedelta

import pytest

import app as app_module


@pytest.fixture()
def bc(flask_app, monkeypatch):
    uname = "bcuser"
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
                        lambda u, to, subj, body, from_name="": (sent.append((to, body)) or True, "smtp", ""))
    app_module._crm_save(uname, {"clients": {
        "a": {"id": "a", "name": "Ann", "email": "ann@x.example", "pipeline_stage": "Lead"},
        "b": {"id": "b", "name": "Bob", "email": "bob@x.example", "pipeline_stage": "Lead", "email_unsubscribed": True}},
        "pipeline": {"stages": app_module._default_pipeline_stages()}})
    for f in app_module._BQ_DIR.glob(f"{uname}*.json"):
        f.unlink()
    return c, h, uname, sent


def _add_contacts(uname, n):
    crm = app_module._crm_load(uname)
    for i in range(n):
        crm["clients"][f"c{i}"] = {"id": f"c{i}", "name": f"P{i}", "email": f"p{i}@x.example", "pipeline_stage": "Lead"}
    app_module._crm_save(uname, crm)


def test_no_footer_by_default_and_optional(bc):
    c, h, uname, sent = bc
    r = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "Hi", "body": "Just my words."}).get_json()
    assert r["ok"] and r["async"] and sent == []          # queued, not blasted
    app_module._bq_drain(uname)
    assert sent == [("ann@x.example", "Just my words.")]
    sent.clear()
    c.post("/api/crm/broadcast/email", headers=h, json={"subject": "Hi", "body": "Promo", "unsub_footer": True})
    app_module._bq_drain(uname)
    assert "unsubscribe" in sent[0][1].lower()


def test_dry_run_reports_skipped_and_resubscribe_restores(bc):
    c, h, uname, sent = bc
    d = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b", "dry_run": True, "stage": "Lead"}).get_json()
    assert d["count"] == 1 and d["skipped_unsubscribed"] == 1
    assert c.post("/api/crm/clients/b/resubscribe", headers=h).get_json()["ok"]
    d = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b", "dry_run": True}).get_json()
    assert d["count"] == 2 and d["skipped_unsubscribed"] == 0


def test_paced_one_at_a_time_with_gaps(bc):
    c, h, uname, sent = bc
    _add_contacts(uname, 4)
    jid = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b"}).get_json()["job_id"]
    assert app_module._bq_step(uname) is True and len(sent) == 1     # first goes right away
    assert app_module._bq_step(uname) is False and len(sent) == 1    # then waits for the gap
    job = c.get(f"/api/crm/broadcast/job/{jid}").get_json()["job"]
    wait = (app_module.datetime.fromisoformat(job["next_at"].replace("Z", "")) - app_module._utcnow()).total_seconds()
    assert app_module.BROADCAST_GAP_MIN - 2 <= wait <= app_module.BROADCAST_GAP_MAX + 1
    assert job["status"] == "running" and job["progress"] == 1 and job["count"] == 5
    assert [j["id"] for j in c.get("/api/crm/broadcast/active").get_json()["jobs"]] == [jid]


def test_daily_cap_pauses_until_tomorrow(bc, monkeypatch):
    c, h, uname, sent = bc
    _add_contacts(uname, 3)
    monkeypatch.setattr(app_module, "BROADCAST_DAILY_CAP", 2)
    jid = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b"}).get_json()["job_id"]
    app_module._bq_drain(uname)
    job = c.get(f"/api/crm/broadcast/job/{jid}").get_json()["job"]
    assert len(sent) == 2 and job["status"] == "waiting_daily"
    assert app_module.datetime.fromisoformat(job["next_at"].replace("Z", "")) > app_module._utcnow()


def test_stop_and_restart_never_resends(bc):
    c, h, uname, sent = bc
    _add_contacts(uname, 3)
    jid = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b"}).get_json()["job_id"]
    app_module._bq_step(uname, force=True)
    # simulate a restart mid-send: the next item is stuck in "sending"
    jobs = app_module._bq_load(uname)
    next(it for it in jobs[-1]["items"] if it["state"] == "pending")["state"] = "sending"
    app_module._bq_save(uname, jobs)
    app_module._bq_step(uname, force=True)
    states = [it["state"] for it in app_module._bq_find(uname, jid)["items"]]
    assert states[:3] == ["sent", "unknown", "sent"] and len(sent) == 2
    assert c.post(f"/api/crm/broadcast/job/{jid}/stop", headers=h).get_json()["ok"]
    app_module._bq_drain(uname)
    assert len(sent) == 2 and app_module._bq_find(uname, jid)["status"] == "stopped"


def test_scheduled_broadcast_starts_once_and_stale_is_missed(bc):
    c, h, uname, sent = bc
    now = app_module._utcnow()
    iso = lambda t: t.isoformat() + "Z"
    app_module.save_json(app_module._sched_broadcast_path(uname), [
        {"id": "due", "send_at": iso(now - timedelta(minutes=1)), "status": "pending",
         "payload": {"subject": "Due", "body": "Hello", "audience": "stage", "audience_val": "Lead"}},
        {"id": "old", "send_at": iso(now - timedelta(days=3)), "status": "pending", "payload": {"subject": "Old", "body": "x"}},
        {"id": "later", "send_at": iso(now + timedelta(hours=1)), "status": "pending", "payload": {"subject": "L", "body": "y"}}])
    app_module._sched_broadcast_tick()
    app_module._sched_broadcast_tick()                       # second tick must not queue it again
    st = {x["id"]: x for x in app_module.load_json(app_module._sched_broadcast_path(uname), [])}
    assert st["due"]["status"] == "started" and st["due"]["job_id"]
    assert st["old"]["status"] == "missed" and st["later"]["status"] == "pending"
    app_module._bq_drain(uname)
    assert sent == [("ann@x.example", "Hello")]
