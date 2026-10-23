"""V15.6: Instagram publishing — every connected account is pickable, Reels
wait for processing before publishing, and live posts link to Instagram.
(File must sort after test_client_crud.)"""
import app as app_module


class _R:
    def __init__(self, body, code=200):
        self._b, self.status_code = body, code

    def json(self):
        return self._b


def test_ig_accounts_falls_back_to_legacy_single_account():
    assert app_module._ig_accounts({}) == []
    legacy = {"instagram": {"ig_user_id": "9", "access_token": "T", "name": "old"}}
    assert app_module._ig_accounts(legacy)[0]["id"] == "9"


def test_reel_waits_for_processing_then_publishes_to_picked_accounts(monkeypatch):
    posts, gets = [], []
    status = iter(["IN_PROGRESS", "FINISHED", "IN_PROGRESS", "FINISHED"])

    def fake_post(url, data=None, timeout=None):
        posts.append((url, dict(data)))
        return _R({"id": "C1" if url.endswith("/media") else "M1"})

    def fake_get(url, params=None, timeout=None):
        gets.append(params["fields"])
        if params["fields"] == "status_code":
            return _R({"status_code": next(status)})
        return _R({"permalink": "https://www.instagram.com/reel/abc/"})

    monkeypatch.setattr(app_module.requests, "post", fake_post)
    monkeypatch.setattr(app_module.requests, "get", fake_get)
    monkeypatch.setattr(app_module.time, "sleep", lambda s: None)
    conns = {"instagram": {"accounts": [{"id": "1", "access_token": "a", "username": "one"},
                                        {"id": "2", "access_token": "b", "username": "two"},
                                        {"id": "3", "access_token": "c", "username": "three"}]}}
    ok, info = app_module._sp_publish_instagram(
        {"caption": "Hi", "media_url": "https://x.example/vclip/a.mp4", "ig_account_ids": ["1", "3"]}, conns)
    assert ok and info == "https://www.instagram.com/reel/abc/, https://www.instagram.com/reel/abc/"
    assert [u.split("/")[-2] for u, _ in posts] == ["1", "1", "3", "3"]
    assert posts[0][1]["media_type"] == "REELS" and posts[0][1]["video_url"].endswith(".mp4")
    assert gets.count("status_code") == 4                     # never published before FINISHED


def test_photo_needs_media_and_failed_processing_is_reported(monkeypatch):
    conns = {"instagram": {"accounts": [{"id": "1", "access_token": "a", "username": "one"}]}}
    ok, info = app_module._sp_publish_instagram({"caption": "Hi"}, conns)
    assert not ok and "photo or video" in info
    monkeypatch.setattr(app_module.requests, "post", lambda url, data=None, timeout=None: _R({"id": "C"}))
    monkeypatch.setattr(app_module.requests, "get", lambda url, params=None, timeout=None: _R({"status_code": "ERROR"}))
    ok, info = app_module._sp_publish_instagram({"caption": "Hi", "media_url": "https://x.example/c.mp4"}, conns)
    assert not ok and "couldn't process" in info


def test_missing_instagram_reason_names_the_cause(monkeypatch):
    monkeypatch.delenv("META_INSTAGRAM", raising=False)
    assert "META_INSTAGRAM" in app_module._ig_missing_reason("t", [], {})
    monkeypatch.setenv("META_INSTAGRAM", "1")
    monkeypatch.setattr(app_module.requests, "get", lambda url, params=None, timeout=None: _R(
        {"data": [{"permission": "pages_show_list", "status": "granted"}]}))
    assert "wasn't allowed" in app_module._ig_missing_reason("t", [{"name": "P"}], {})
    monkeypatch.setattr(app_module.requests, "get", lambda url, params=None, timeout=None: _R({"data": [
        {"permission": "instagram_basic", "status": "granted"}, {"permission": "instagram_content_publish", "status": "granted"}]}))
    assert "My Shop" in app_module._ig_missing_reason("t", [{"name": "My Shop"}], {})


def test_live_link_and_connections_hide_tokens(flask_app):
    links = app_module._sp_live_links({"instagram": {"ok": True, "info": "https://www.instagram.com/p/XYZ/, 1789"}})
    assert [l["url"] for l in links] == ["https://www.instagram.com/p/XYZ/"]
    uname = "spiguser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        app_module._save_sp_conns(uname, {"instagram": {"access_token": "SECRETX", "ig_user_id": "17841", "accounts": [
            {"id": "17841", "username": "shop", "picture": "", "access_token": "SECRETA"}]}})
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
        resp = c.get("/api/social/connections")
        assert "SECRET" not in resp.get_data(as_text=True)
        ig = resp.get_json()["connections"]["instagram"]
        assert ig["connected"] and ig["accounts"][0]["username"] == "shop"
        r = c.post("/api/social/posts", headers=h, json={"caption": "Hi", "platforms": ["instagram"],
                                                          "ig_account_ids": ["17841", "bad id"], "status": "draft"}).get_json()
        assert r["post"]["ig_account_ids"] == ["17841"]
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()
