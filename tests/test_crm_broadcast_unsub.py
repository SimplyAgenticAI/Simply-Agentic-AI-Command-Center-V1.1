"""Email Broadcast (V11.1): no unsubscribe footer unless asked, unsubscribed
contacts can be resubscribed, and scheduled broadcasts actually send (stale
ones are never blasted late). Email sending is mocked."""
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
    return c, h, uname, sent


def test_no_footer_by_default_and_optional(bc):
    c, h, uname, sent = bc
    r = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "Hi", "body": "Just my words."}).get_json()
    assert r["ok"] and sent == [("ann@x.example", "Just my words.")]
    sent.clear()
    c.post("/api/crm/broadcast/email", headers=h, json={"subject": "Hi", "body": "Promo", "unsub_footer": True})
    assert "unsubscribe" in sent[0][1].lower()


def test_dry_run_reports_skipped_and_resubscribe_restores(bc):
    c, h, uname, sent = bc
    d = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b", "dry_run": True, "stage": "Lead"}).get_json()
    assert d["count"] == 1 and d["skipped_unsubscribed"] == 1
    assert c.post("/api/crm/clients/b/resubscribe", headers=h).get_json()["ok"]
    d = c.post("/api/crm/broadcast/email", headers=h, json={"subject": "s", "body": "b", "dry_run": True}).get_json()
    assert d["count"] == 2 and d["skipped_unsubscribed"] == 0


def test_scheduled_broadcast_sends_once_and_stale_is_missed(bc):
    c, h, uname, sent = bc
    now = app_module._utcnow()
    iso = lambda t: t.isoformat() + "Z"
    app_module.save_json(app_module._sched_broadcast_path(uname), [
        {"id": "due", "send_at": iso(now - timedelta(minutes=1)), "status": "pending",
         "payload": {"subject": "Due", "body": "Hello", "audience": "stage", "audience_val": "Lead"}},
        {"id": "old", "send_at": iso(now - timedelta(days=3)), "status": "pending", "payload": {"subject": "Old", "body": "x"}},
        {"id": "later", "send_at": iso(now + timedelta(hours=1)), "status": "pending", "payload": {"subject": "L", "body": "y"}}])
    app_module._sched_broadcast_tick()
    app_module._sched_broadcast_tick()                       # second tick must not resend
    st = {x["id"]: x for x in app_module.load_json(app_module._sched_broadcast_path(uname), [])}
    assert st["due"]["status"] == "sent" and st["due"]["sent"] == 1
    assert st["old"]["status"] == "missed" and st["later"]["status"] == "pending"
    assert sent == [("ann@x.example", "Hello")]
