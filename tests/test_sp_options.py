"""V17.4: per-platform post settings + presets. (Sorts after test_client_crud.)"""
import json

import app as app_module


class _R:
    def __init__(self, body=None, code=200, headers=None, text=""):
        self._b, self.status_code, self.headers, self.text = body or {}, code, headers or {}, text

    def json(self):
        return self._b


def test_clean_options_keeps_only_known_safe_values():
    o = app_module._sp_clean_options({
        "youtube": {"title": "<b>Hi</b>" + "x" * 200, "privacy": "secret", "made_for_kids": "yes",
                    "category": "999", "tags": "#one, two ,,", "ai_content": 1},
        "tiktok": {"privacy": "EVERYBODY", "allow_comment": "on"},
        "instagram": {"type": "carousel", "alt_text": "a dog"},
        "linkedin": {"visibility": "WEIRD"}, "myspace": {"x": 1}})
    assert len(o["youtube"]["title"]) == 100 and "<" not in o["youtube"]["title"]
    assert o["youtube"]["privacy"] == "public" and o["youtube"]["made_for_kids"] is True
    assert o["youtube"]["category"] == "22" and o["youtube"]["tags"] == ["one", "two"] and o["youtube"]["notify"] is True
    assert o["tiktok"]["privacy"] == "" and o["tiktok"]["allow_comment"] is True and o["tiktok"]["allow_duet"] is False
    assert o["instagram"]["type"] == "" and o["linkedin"]["visibility"] == "PUBLIC" and "myspace" not in o


def test_youtube_upload_uses_settings(monkeypatch, tmp_path):
    vid = tmp_path / "v.mp4"
    vid.write_bytes(b"0" * 100)
    monkeypatch.setattr(app_module, "_sp_youtube_token", lambda u, c: ("TOK", ""))
    monkeypatch.setattr(app_module, "_sp_media_file", lambda u, url: (vid, False, ""))
    seen = {}

    def fake_post(url, headers=None, data=None, timeout=None):
        seen["url"], seen["body"] = url, json.loads(data)
        return _R(code=200, headers={"Location": "https://up.example/1"})
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    monkeypatch.setattr(app_module.requests, "put", lambda url, data=None, headers=None, timeout=None: _R({"id": "VID123"}))
    post = {"caption": "First line\nMore", "media_url": "x.mp4", "options": app_module._sp_clean_options(
        {"youtube": {"title": "My Title", "privacy": "unlisted", "made_for_kids": False, "category": "27",
                     "tags": ["a", "b"], "ai_content": True, "notify": False}})}
    ok, info = app_module._sp_publish_youtube("u", post, {})
    assert ok and info == "https://youtu.be/VID123"
    b = seen["body"]
    assert b["snippet"]["title"] == "My Title" and b["snippet"]["categoryId"] == "27" and b["snippet"]["tags"] == ["a", "b"]
    assert b["status"] == {"privacyStatus": "unlisted", "selfDeclaredMadeForKids": False, "containsSyntheticMedia": True}
    assert "notifySubscribers=false" in seen["url"]


def test_instagram_story_reel_and_alt_text(monkeypatch):
    sent = []
    monkeypatch.setattr(app_module.requests, "post", lambda url, data=None, timeout=None: sent.append(dict(data or {})) or _R({"id": "C"}))
    monkeypatch.setattr(app_module.requests, "get", lambda url, params=None, timeout=None: _R({"status_code": "FINISHED", "permalink": "https://www.instagram.com/p/Z/"}))
    acct = {"id": "55", "access_token": "t"}
    app_module._ig_publish_one(acct, "https://x/a.jpg", "Hi", opts={"type": "story"})
    assert sent[0]["media_type"] == "STORIES" and sent[0]["image_url"].endswith(".jpg")
    sent.clear()
    app_module._ig_publish_one(acct, "https://x/a.mp4", "Hi", opts={"share_to_feed": False})
    assert sent[0]["media_type"] == "REELS" and sent[0]["share_to_feed"] == "false"
    sent.clear()
    app_module._ig_publish_one(acct, "https://x/a.jpg", "Hi", opts={"alt_text": "a red barn"})
    assert sent[0]["alt_text"] == "a red barn" and "media_type" not in sent[0]


def test_presets_saved_without_tiktok_privacy(flask_app):
    uname = "sppresetuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
        r = c.post("/api/social/presets", headers=h, json={"platform": "tiktok",
                   "options": {"privacy": "PUBLIC_TO_EVERYONE", "allow_comment": True}}).get_json()
        assert r["ok"] and "privacy" not in r["presets"]["tiktok"] and r["presets"]["tiktok"]["allow_comment"]
        c.post("/api/social/presets", headers=h, json={"platform": "youtube", "options": {"privacy": "unlisted"}})
        g = c.get("/api/social/presets").get_json()
        assert g["presets"]["youtube"]["privacy"] == "unlisted" and g["youtube_categories"]["27"] == "Education"
        assert c.post("/api/social/presets", headers=h, json={"platform": "myspace", "options": {}}).status_code == 400
        p = c.post("/api/social/posts", headers=h, json={"caption": "x", "platforms": ["linkedin"], "status": "draft",
                                                          "options": {"linkedin": {"visibility": "CONNECTIONS"}}}).get_json()
        assert p["post"]["options"]["linkedin"]["visibility"] == "CONNECTIONS"
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()
