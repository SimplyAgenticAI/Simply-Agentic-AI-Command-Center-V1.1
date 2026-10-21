"""Bulk actions (V12.6): Ready-for-you send/skip many, and Content Planner
delete / unschedule / shift many. (Sorts after test_client_crud on purpose.)"""
import pytest

import app as app_module


@pytest.fixture()
def pr(flask_app, monkeypatch):
    uname = "bulkplanner"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    sent = []
    monkeypatch.setattr(app_module, "_agent_send",
                        lambda u, a, subj, body: (sent.append(a["id"]) or (a["id"] != "bad", "" if a["id"] != "bad" else "SMTP down")))
    app_module._agent_path(uname).unlink(missing_ok=True)
    app_module._sp_posts_path(uname).unlink(missing_ok=True)
    yield c, h, uname, sent
    data = app_module.load_users()
    (data.get("users") or {}).pop(uname, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _seed_approvals(uname, ids):
    with app_module._AGENT_LOCK:
        d = app_module._agent_load(uname)
        d["approvals"] = [{"id": i, "kind": "intro", "status": "pending", "client_id": "c" + i,
                           "subject": "Hi", "body": "Hello there", "to": i + "@x.example"} for i in ids]
        app_module._agent_save(uname, d)


def _status(uname):
    return {a["id"]: a["status"] for a in app_module._agent_load(uname)["approvals"]}


def test_bulk_send_sends_selected_and_keeps_failures_pending(pr):
    c, h, uname, sent = pr
    _seed_approvals(uname, ["a", "bad", "c"])
    r = c.post("/api/agent/approvals/bulk", headers=h, json={"action": "approve", "ids": ["a", "bad"]}).get_json()
    assert r["ok"] and r["done"] == 1 and r["failed"][0]["id"] == "bad"
    st = _status(uname)
    assert st["a"] == "sent" and st["bad"] == "pending" and st["c"] == "pending"
    assert sorted(sent) == ["a", "bad"]


def test_bulk_send_does_not_build_trust_streak(pr):
    c, h, uname, sent = pr
    _seed_approvals(uname, ["a", "b"])
    c.post("/api/agent/approvals/bulk", headers=h, json={"action": "approve", "ids": ["a", "b"]})
    assert int((app_module._agent_load(uname)["trust"].get("intro") or {}).get("streak") or 0) == 0


def test_bulk_skip_and_no_double_send(pr):
    c, h, uname, sent = pr
    _seed_approvals(uname, ["a", "b"])
    assert c.post("/api/agent/approvals/bulk", headers=h, json={"action": "skip", "ids": ["a", "b"]}).get_json()["done"] == 2
    r = c.post("/api/agent/approvals/bulk", headers=h, json={"action": "approve", "ids": ["a", "b"]}).get_json()
    assert r["done"] == 0 and sent == []
    assert set(_status(uname).values()) == {"skipped"}


def test_bulk_approvals_validates_input(pr):
    c, h, uname, sent = pr
    assert c.post("/api/agent/approvals/bulk", headers=h, json={"action": "nuke", "ids": ["a"]}).status_code == 400
    assert c.post("/api/agent/approvals/bulk", headers=h, json={"action": "skip", "ids": "a"}).status_code == 400


def _seed_posts(uname):
    app_module._save_sp_posts(uname, [
        {"id": "d1", "caption": "draft", "status": "draft", "scheduled_at": ""},
        {"id": "s1", "caption": "sched", "status": "scheduled", "scheduled_at": "2030-01-10T15:00:00Z"},
        {"id": "s2", "caption": "sched2", "status": "scheduled", "scheduled_at": "2030-01-11T15:00:00"},
        {"id": "pb", "caption": "busy", "status": "publishing", "scheduled_at": "2030-01-01T10:00:00Z"},
        {"id": "pd", "caption": "done", "status": "published", "scheduled_at": "2029-12-01T10:00:00Z"},
    ])


def _posts(uname):
    return {p["id"]: p for p in app_module._load_sp_posts(uname)}


def test_posts_bulk_delete_skips_publishing(pr):
    c, h, uname, _ = pr
    _seed_posts(uname)
    r = c.post("/api/social/posts/bulk", headers=h, json={"action": "delete", "ids": ["d1", "pb", "pd"]}).get_json()
    assert r["ok"] and r["done"] == 2 and r["skipped"] == 1
    assert set(_posts(uname)) == {"s1", "s2", "pb"}


def test_posts_bulk_unschedule_only_scheduled(pr):
    c, h, uname, _ = pr
    _seed_posts(uname)
    r = c.post("/api/social/posts/bulk", headers=h, json={"action": "unschedule", "ids": ["s1", "d1"]}).get_json()
    assert r["done"] == 1 and r["skipped"] == 1
    assert _posts(uname)["s1"]["status"] == "draft"


def test_posts_bulk_shift_keeps_format(pr):
    c, h, uname, _ = pr
    _seed_posts(uname)
    r = c.post("/api/social/posts/bulk", headers=h, json={"action": "shift", "days": 7, "ids": ["s1", "s2", "d1", "pd"]}).get_json()
    assert r["done"] == 2 and r["skipped"] == 2       # draft without a date, already published
    p = _posts(uname)
    assert p["s1"]["scheduled_at"] == "2030-01-17T15:00:00Z"
    assert p["s2"]["scheduled_at"] == "2030-01-18T15:00:00"
    assert p["pd"]["scheduled_at"] == "2029-12-01T10:00:00Z"


def test_posts_bulk_shift_validates_days(pr):
    c, h, uname, _ = pr
    _seed_posts(uname)
    for bad in (0, "x", 9999):
        assert c.post("/api/social/posts/bulk", headers=h, json={"action": "shift", "days": bad, "ids": ["s1"]}).status_code == 400
    assert _posts(uname)["s1"]["scheduled_at"] == "2030-01-10T15:00:00Z"
