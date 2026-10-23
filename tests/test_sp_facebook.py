"""V15.3: Facebook publishing sends videos (incl. Video Editor clips) to
/videos, photos to /photos, and text to /feed.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import app as app_module


class _Resp:
    status_code = 200
    def json(self):
        return {"id": "123_456"}


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
