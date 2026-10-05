"""Direct platform connections (V9.9.2): setup status, YouTube resumable
upload, LinkedIn posts, background publishing, media-link safety. Platform
APIs are mocked; no network."""
import tempfile
import time
from pathlib import Path

import pytest

import app as app_module


class _R:
    def __init__(self, status, data=None, headers=None):
        self.status_code, self._d, self.headers = status, data or {}, headers or {}
        self.content, self.text = b"x", str(data)

    def json(self):
        return self._d


@pytest.fixture()
def social(flask_app, monkeypatch):
    uname = "socialtester"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    return c, h, uname


def test_setup_hides_developer_details_from_non_admins(social, monkeypatch):
    c, h, uname = social
    monkeypatch.setattr(app_module, "LINKEDIN_CLIENT_ID", "")
    d = c.get("/api/social/setup").get_json()
    assert d["ok"] and d["ready"]["linkedin"] is False
    assert "redirects" not in d and "env" not in d


def test_youtube_resumable_upload(social, monkeypatch):
    c, h, uname = social
    vid = Path(tempfile.mkdtemp()) / "v.mp4"
    vid.write_bytes(b"\x00" * 2048)
    monkeypatch.setattr(app_module, "_sp_media_file", lambda u, url: (vid, False, ""))
    monkeypatch.setattr(app_module, "_sp_youtube_token", lambda u, conns: ("ya29.tok", ""))
    seen = {}

    def fake_post(url, headers=None, data=None, timeout=None, **kw):
        seen["init"] = (url, headers)
        return _R(200, {}, {"Location": "https://upload.example/session1"})

    def fake_put(url, data=None, headers=None, timeout=None):
        seen["put"] = (url, headers)
        return _R(200, {"id": "abc123"})
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    monkeypatch.setattr(app_module.requests, "put", fake_put)
    ok, info = app_module._sp_publish_youtube(uname, {"caption": "My title line\nmore text", "media_url": "x"}, {})
    assert ok and info == "https://youtu.be/abc123"
    assert "uploadType=resumable" in seen["init"][0] and seen["init"][1]["X-Upload-Content-Length"] == "2048"
    assert seen["put"][0] == "https://upload.example/session1"


def test_youtube_needs_video(social, monkeypatch):
    c, h, uname = social
    monkeypatch.setattr(app_module, "_sp_youtube_token", lambda u, conns: ("tok", ""))
    ok, info = app_module._sp_publish_youtube(uname, {"caption": "x", "media_url": ""}, {})
    assert not ok and "video" in info.lower()


def test_linkedin_post(social, monkeypatch):
    c, h, uname = social
    seen = {}

    def fake_post(url, json=None, timeout=None, headers=None, **kw):
        seen.update(url=url, json=json, headers=headers)
        return _R(201, {}, {"x-restli-id": "urn:li:share:1"})
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    conns = {"linkedin": {"access_token": "AQX", "person_urn": "urn:li:person:p1", "expires_at": app_module._now_epoch() + 999}}
    ok, info = app_module._sp_publish_linkedin(uname, {"caption": "Hello LinkedIn"}, conns)
    assert ok and info == "urn:li:share:1"
    assert seen["json"]["author"] == "urn:li:person:p1"
    assert seen["json"]["specificContent"]["com.linkedin.ugc.ShareContent"]["shareCommentary"]["text"] == "Hello LinkedIn"
    expired = {"linkedin": dict(conns["linkedin"], expires_at=1)}
    ok, info = app_module._sp_publish_linkedin(uname, {"caption": "x"}, expired)
    assert not ok and "reconnect" in info


def test_youtube_publish_runs_in_background(social, monkeypatch):
    c, h, uname = social
    monkeypatch.setattr(app_module, "_sp_publish_youtube", lambda u, p, conns: (time.sleep(0.3) or True, "https://youtu.be/z"))
    pid = c.post("/api/social/posts", headers=h, json={"caption": "Clip!", "platforms": ["youtube"],
                 "media_url": "https://x.example/v.mp4", "status": "draft"}).get_json()["post"]["id"]
    r = c.post(f"/api/social/publish/{pid}", headers=h).get_json()
    assert r["ok"] and r["status"] == "publishing"
    p = None
    for _ in range(50):
        p = next((x for x in app_module._load_sp_posts(uname) if x["id"] == pid), p)   # tolerate a mid-swap read
        if p and p["status"] != "publishing":
            break
        time.sleep(0.1)
    assert p["status"] == "published" and p["publish_results"]["youtube"]["info"] == "https://youtu.be/z"


def test_media_link_safety(social):
    c, h, uname = social
    for url, frag in (("http://example.com/v.mp4", "https"), ("https://127.0.0.1/v.mp4", "publicly"),
                      ("https://10.0.0.5/v.mp4", "publicly"), ("", "no video")):
        path, tmp, err = app_module._sp_media_file(uname, url)
        assert path is None and frag in err.lower(), (url, err)
