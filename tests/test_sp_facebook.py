"""V15.3: Facebook publishing sends videos (incl. Video Editor clips) to
/videos, photos to /photos, and text to /feed.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import app as app_module


class _Resp:
    status_code = 200
    def json(self):
        return {"id": "123_456"}


def test_posts_to_every_picked_page_and_names_failures(monkeypatch):
    calls = []
    class _Bad:
        status_code = 400
        def json(self):
            return {"error": {"message": "Permissions error"}}
    def fake_post(url, data=None, timeout=None):
        calls.append(url)
        return _Bad() if "/P3/" in url else _Resp()
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    conns = {"facebook": {"pages": [{"id": "P1", "access_token": "a", "name": "One"},
                                    {"id": "P2", "access_token": "b", "name": "Two"},
                                    {"id": "P3", "access_token": "c", "name": "Three"}]}}
    ok, _ = app_module._sp_publish_facebook({"caption": "x", "fb_page_ids": ["P1", "P2"]}, conns)
    assert ok and [u.split("/")[-2] for u in calls] == ["P1", "P2"]
    ok, info = app_module._sp_publish_facebook({"caption": "x", "fb_page_ids": ["P1", "P3"]}, conns)
    assert not ok and "Three: Permissions error" in info and "posted on 1 other Page" in info
    calls.clear()
    app_module._sp_publish_facebook({"caption": "x"}, conns)                       # nothing picked → first Page
    assert [u.split("/")[-2] for u in calls] == ["P1"]


def test_connections_list_pages_without_tokens_and_posts_keep_picks(flask_app):
    uname = "spfbuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        app_module._save_sp_conns(uname, {"facebook": {"access_token": "USERTOK", "pages": [
            {"id": "111", "name": "Alpha", "access_token": "SECRET1"}, {"id": "222", "name": "Beta", "access_token": "SECRET2"}]}})
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
        body = c.get("/api/social/connections").get_data(as_text=True)
        assert "SECRET" not in body and "USERTOK" not in body
        fb = c.get("/api/social/connections").get_json()["connections"]["facebook"]
        assert [p["name"] for p in fb["pages"]] == ["Alpha", "Beta"] and "picture" in fb["pages"][0]
        r = c.post("/api/social/posts", headers=h, json={"caption": "Hi", "platforms": ["facebook"],
                                                          "fb_page_ids": ["222", "not-a-page-id"], "status": "draft"}).get_json()
        assert r["post"]["fb_page_ids"] == ["222"]
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()


def test_live_links_built_and_kept_on_edit(flask_app):
    links = app_module._sp_live_links({"facebook": {"ok": True, "info": "111_222, 333_444"},
                                       "youtube": {"ok": True, "info": "dQw4w9WgXcQ"},
                                       "instagram": {"ok": False, "info": "nope"},
                                       "linkedin": {"ok": True, "info": "<script>"}})
    assert [l["url"] for l in links] == ["https://www.facebook.com/111_222", "https://www.facebook.com/333_444",
                                         "https://youtu.be/dQw4w9WgXcQ"]
    assert links[0]["label"] == "View on Facebook (1)"
    uname = "splinkuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        app_module._save_sp_posts(uname, [{"id": "p1", "caption": "x", "platforms": ["facebook"], "status": "draft",
                                           "live_links": links[:1]}])
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
        r = c.post("/api/social/posts", headers=h, json={"id": "p1", "caption": "x", "platforms": ["facebook"],
                                                          "scheduled_at": "2031-01-05T09:00:00", "status": "draft"}).get_json()
        assert r["post"]["live_links"] == links[:1]                       # moving a post keeps its links
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()


def test_facebook_routes_by_media(monkeypatch):
    calls = []
    monkeypatch.setattr(app_module.requests, "post", lambda url, data=None, timeout=None: calls.append((url, data)) or _Resp())
    conns = {"facebook": {"pages": [{"id": "PAGE", "access_token": "TOK", "name": "My Page"}]}}
    for media in ("https://app.example/vclip/abc.def.mp4", "https://cdn.example/clip.MOV?x=1", "https://cdn.example/pic.jpg", ""):
        ok, _ = app_module._sp_publish_facebook({"caption": "Hi", "media_url": media}, conns)
        assert ok
    ends = [u.rsplit("/", 1)[-1] for u, _ in calls]
    assert ends == ["videos", "videos", "photos", "feed"]
    assert calls[0][1]["file_url"].endswith(".mp4") and calls[0][1]["description"] == "Hi"
