"""Content Planner via LeadConnector (HighLevel Social Planner) — V9.9.
HighLevel's API is mocked; no network."""
from datetime import timedelta

import pytest

import app as app_module

LOC = "LocAbc123XYZ"


class _Resp:
    def __init__(self, status, data):
        self.status_code, self._data = status, data
        self.content = b"x"
        self.text = str(data)

    def json(self):
        return self._data


@pytest.fixture()
def lc(flask_app, monkeypatch):
    calls = []
    state = {"version_ok": "v3"}

    def fake_request(method, url, timeout=None, json=None, headers=None):
        calls.append({"method": method, "url": url, "json": json, "headers": headers})
        if headers.get("Authorization") == "Bearer bad":
            return _Resp(401, {"message": "Invalid JWT"})
        if headers.get("Version") != state["version_ok"]:
            return _Resp(400, {"message": "Version header is invalid"})
        if url.endswith("/accounts"):
            return _Resp(200, {"success": True, "results": {"accounts": [
                {"id": "fb1", "name": "Acme Page", "platform": "facebook"},
                {"id": "ig1", "name": "@acme", "platform": "instagram"},
                {"id": "tt1", "name": "acme", "platform": "tiktok", "isExpired": True},
                {"id": "li1", "name": "Acme Co", "platform": "linkedin"}], "groups": []}})
        if method == "POST" and url.endswith("/posts"):
            return _Resp(201, {"success": True, "results": {"post": {"_id": "hl_post_1", "status": json.get("status")}}})
        if method in ("PUT", "DELETE"):
            return _Resp(200, {"success": True})
        return _Resp(404, {"message": "nope"})

    monkeypatch.setattr(app_module.requests, "request", fake_request)
    uname = "plannertester"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    return c, h, uname, calls, state


def test_connect_lists_accounts_with_version_fallback(lc):
    c, h, uname, calls, state = lc
    bad = c.post("/api/social/lc/connect", headers=h, json={"token": "bad", "location_id": LOC}).get_json()
    assert not bad["ok"] and "Private Integration token" in bad["error"]
    d = c.post("/api/social/lc/connect", headers=h, json={"token": "pit-123", "location_id": LOC}).get_json()
    assert d["ok"] and [a["id"] for a in d["accounts"]] == ["fb1", "ig1", "tt1", "li1"]
    assert d["accounts"][2]["expired"] is True
    conn = c.get("/api/social/connections").get_json()["connections"]["leadconnector"]
    assert conn["connected"] and conn["location_id"] == LOC and "token" not in conn
    # remembered version → the next call goes straight to v3
    calls.clear()
    c.post("/api/social/lc/refresh", headers=h)
    assert [x["headers"]["Version"] for x in calls] == ["v3"]


def test_schedule_edit_publish_delete(lc):
    c, h, uname, calls, state = lc
    c.post("/api/social/lc/connect", headers=h, json={"token": "pit-123", "location_id": LOC})
    calls.clear()
    when = "2030-01-02T15:00:00.000Z"
    d = c.post("/api/social/posts", headers=h, json={"caption": "Big launch", "lc_accounts": ["fb1", "li1"],
               "platforms": ["facebook", "linkedin"], "media_url": "https://x.example/v.mp4",
               "status": "scheduled", "scheduled_utc": when}).get_json()
    assert d["ok"], d
    post = d["post"]
    assert post["lc_post_id"] == "hl_post_1" and post["scheduled_via"] == "leadconnector"
    sent = calls[-1]
    assert sent["method"] == "POST" and sent["json"]["accountIds"] == ["fb1", "li1"]
    assert sent["json"]["status"] == "scheduled" and sent["json"]["scheduleDate"] == when
    assert sent["json"]["media"] == [{"url": "https://x.example/v.mp4", "type": "video/mp4"}]

    # Re-saving edits the same HighLevel post (PUT), never duplicates it
    d = c.post("/api/social/posts", headers=h, json={"id": post["id"], "caption": "Bigger launch", "lc_accounts": ["fb1"],
               "status": "scheduled", "scheduled_utc": when}).get_json()
    assert d["ok"] and calls[-1]["method"] == "PUT" and calls[-1]["url"].endswith("/posts/hl_post_1")

    # Deleting a scheduled post cancels it in HighLevel too
    c.delete(f"/api/social/posts/{post['id']}", headers=h)
    assert calls[-1]["method"] == "DELETE" and calls[-1]["url"].endswith("/posts/hl_post_1")

    # Publish now
    d = c.post("/api/social/posts", headers=h, json={"caption": "Now!", "lc_accounts": ["ig1"], "status": "draft"}).get_json()
    r = c.post(f"/api/social/publish/{d['post']['id']}", headers=h).get_json()
    assert r["ok"] and r["status"] == "published"
    assert calls[-1]["json"]["status"] == "published" and calls[-1]["json"]["accountIds"] == ["ig1"]


def test_schedule_rejected_falls_back_to_draft_with_reason(lc, monkeypatch):
    c, h, uname, calls, state = lc
    c.post("/api/social/lc/connect", headers=h, json={"token": "pit-123", "location_id": LOC})
    r = c.post("/api/social/posts", headers=h, json={"caption": "x", "lc_accounts": ["fb1"], "status": "scheduled"})
    assert r.status_code == 400 and "date and time" in r.get_json()["error"]
    assert r.get_json()["post"]["status"] == "draft"


def test_scheduler_publishes_due_and_flags_stale(lc, monkeypatch):
    c, h, uname, calls, state = lc
    posted = []
    monkeypatch.setattr(app_module, "_sp_publish_facebook", lambda post, conns: (posted.append(post["id"]) or True, "fbid"))
    now = app_module._utcnow()
    fresh = (now - timedelta(minutes=5)).isoformat() + "Z"
    stale = (now - timedelta(days=30)).isoformat() + "Z"
    future = (now + timedelta(days=1)).isoformat() + "Z"
    app_module._save_sp_posts(uname, [
        {"id": "p1", "caption": "a", "platforms": ["facebook"], "status": "scheduled", "scheduled_utc": fresh},
        {"id": "p2", "caption": "b", "platforms": ["facebook"], "status": "scheduled", "scheduled_utc": stale},
        {"id": "p3", "caption": "c", "platforms": ["facebook"], "status": "scheduled", "scheduled_utc": future},
        {"id": "p4", "caption": "d", "lc_accounts": ["fb1"], "status": "scheduled", "scheduled_via": "leadconnector", "scheduled_utc": fresh},
    ])
    app_module._sp_tick()
    st = {p["id"]: p for p in app_module._load_sp_posts(uname)}
    assert posted == ["p1"] and st["p1"]["status"] == "published"
    assert st["p2"]["status"] == "failed" and "Missed" in st["p2"]["error"]     # never blasted out
    assert st["p3"]["status"] == "scheduled"
    assert st["p4"]["status"] == "scheduled"                                    # HighLevel handles it


def test_legacy_facebook_token_connection_can_publish(monkeypatch):
    conns = {"facebook": {"access_token": "EAAB", "page_id": "123", "page_name": "Pg"}}
    seen = {}

    def fake_post(url, data=None, timeout=None):
        seen["url"] = url
        return _Resp(200, {"id": "123_456"})
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    ok, info = app_module._sp_publish_facebook({"caption": "hi"}, conns)
    assert ok and "/123/feed" in seen["url"]
