"""V17.3: media rules per platform (YouTube/TikTok video only, Instagram needs
media), incompatible platforms skipped not attempted, and posts stuck
'publishing' after a server restart get unstuck. (Sorts after test_client_crud.)"""
from datetime import timedelta

import app as app_module


def test_media_problems():
    mp = app_module._sp_media_problems
    assert set(mp(["facebook", "linkedin", "youtube", "tiktok", "instagram"], "")) == {"youtube", "tiktok", "instagram"}
    photo = mp(["youtube", "instagram", "facebook"], "https://x.example/spm/abc.jpg")
    assert set(photo) == {"youtube"} and "photo" in photo["youtube"]
    assert mp(["youtube", "tiktok", "instagram"], "https://x.example/spm/abc.mp4") == {}


def test_text_post_skips_video_platforms(monkeypatch):
    monkeypatch.setattr(app_module, "_load_sp_conns", lambda u: {})
    monkeypatch.setattr(app_module, "_sp_publish_facebook", lambda post, conns: (True, "111_222"))
    called = []
    monkeypatch.setattr(app_module, "_sp_publish_youtube", lambda *a: called.append("yt") or (True, "x"))
    res = app_module._sp_publish_one("u", {"caption": "Hi", "platforms": ["facebook", "youtube"], "media_url": ""})
    assert res["facebook"]["ok"] and not res["youtube"]["ok"] and "Skipped" in res["youtube"]["info"]
    assert called == []                                   # never attempted


def test_stuck_publishing_is_unstuck():
    old = (app_module._utcnow() - timedelta(hours=1)).isoformat()
    fresh = app_module._utcnow().isoformat()
    posts = [{"id": "a", "status": "publishing", "publishing_started": old},
             {"id": "b", "status": "publishing", "publishing_started": fresh},
             {"id": "c", "status": "publishing"},                       # from before this version
             {"id": "d", "status": "published"}]
    assert app_module._sp_unstick(posts)
    assert [p["status"] for p in posts] == ["failed", "publishing", "failed", "published"]
    assert "interrupted" in posts[0]["error"]


def test_publish_route_rejects_when_nothing_can_take_it(flask_app):
    uname = "sprulesuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        app_module._save_sp_posts(uname, [{"id": "p1", "caption": "x", "platforms": ["youtube", "tiktok"],
                                           "status": "draft", "media_url": ""}])
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
        r = c.post("/api/social/publish/p1", headers=h)
        assert r.status_code == 400 and "video" in r.get_json()["error"]
        assert app_module._load_sp_posts(uname)[0]["status"] == "draft"       # not left 'publishing'
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()


def test_progress_reported_per_platform(monkeypatch):
    monkeypatch.setattr(app_module, "_load_sp_conns", lambda u: {})
    monkeypatch.setattr(app_module, "_sp_publish_facebook", lambda post, conns: (True, "111_222"))
    monkeypatch.setattr(app_module, "_sp_publish_youtube", lambda u, post, conns: (False, "quota exceeded"))
    seen = []
    app_module._sp_publish_one("u", {"caption": "Hi", "platforms": ["facebook", "youtube", "tiktok"], "media_url": "https://x/a.jpg"},
                               progress=lambda pl, st, info: seen.append((pl, st)))
    assert seen == [("facebook", "working"), ("facebook", "done"), ("youtube", "skipped"), ("tiktok", "skipped")]
    seen.clear()
    app_module._sp_publish_one("u", {"caption": "Hi", "platforms": ["youtube"], "media_url": "https://x/a.mp4"},
                               progress=lambda pl, st, info: seen.append((pl, st, info)))
    assert seen == [("youtube", "working", ""), ("youtube", "failed", "quota exceeded")]
