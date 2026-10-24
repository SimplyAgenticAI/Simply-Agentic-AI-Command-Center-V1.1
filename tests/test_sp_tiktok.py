"""V16.7: TikTok video posting - chunked file upload, wait for processing,
24h token refresh, private-only until the app is approved.
(File must sort after test_client_crud.)"""
import app as app_module


class _R:
    def __init__(self, body=None, code=200):
        self._b, self.status_code = body or {}, code

    def json(self):
        return self._b


def test_chunk_rules():
    MB = 1024 * 1024
    assert app_module._tt_chunks(3 * MB) == (3 * MB, 1)
    assert app_module._tt_chunks(64 * MB) == (64 * MB, 1)
    chunk, count = app_module._tt_chunks(105 * MB)
    assert chunk == 10 * MB and count == 10               # last chunk carries the extra 5 MB (15 MB, under 128 MB)


def _setup(monkeypatch, tmp_path, opts, statuses):
    vid = tmp_path / "clip.mp4"
    vid.write_bytes(b"x" * 1000)
    monkeypatch.setattr(app_module, "_sp_media_file", lambda u, url: (vid, False, ""))
    monkeypatch.setattr(app_module.time, "sleep", lambda s: None)
    calls = {"init": None, "puts": [], "status": 0}
    status_iter = iter(statuses)

    def fake_post(url, headers=None, json=None, data=None, timeout=None):
        if url.endswith("/creator_info/query/"):
            return _R({"data": {"privacy_level_options": opts}, "error": {"code": "ok"}})
        if url.endswith("/video/init/"):
            calls["init"] = json
            return _R({"data": {"publish_id": "P1", "upload_url": "https://up.example/1"}, "error": {"code": "ok"}})
        if url.endswith("/status/fetch/"):
            calls["status"] += 1
            return _R({"data": next(status_iter)})
        raise AssertionError(url)

    monkeypatch.setattr(app_module.requests, "post", fake_post)
    monkeypatch.setattr(app_module.requests, "put",
                        lambda url, data=None, timeout=None, headers=None: calls["puts"].append(headers) or _R())
    return calls


def test_posts_publicly_when_allowed_and_waits_for_processing(monkeypatch, tmp_path):
    calls = _setup(monkeypatch, tmp_path, ["SELF_ONLY", "PUBLIC_TO_EVERYONE"],
                   [{"status": "PROCESSING_UPLOAD"}, {"status": "PUBLISH_COMPLETE", "publicaly_available_post_id": [777]}])
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4"}, conns)
    assert ok and info == "tiktok:777"
    assert calls["init"]["post_info"]["privacy_level"] == "PUBLIC_TO_EVERYONE"
    assert calls["init"]["source_info"] == {"source": "FILE_UPLOAD", "video_size": 1000, "chunk_size": 1000, "total_chunk_count": 1}
    assert calls["puts"][0]["Content-Range"] == "bytes 0-999/1000" and calls["status"] == 2


def test_unapproved_app_posts_private_and_says_so(monkeypatch, tmp_path):
    calls = _setup(monkeypatch, tmp_path, ["SELF_ONLY"], [{"status": "PUBLISH_COMPLETE"}])
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4"}, conns)
    assert ok and "private until TikTok approves" in info
    assert calls["init"]["post_info"]["privacy_level"] == "SELF_ONLY"


def test_failed_processing_is_reported(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, ["SELF_ONLY"], [{"status": "FAILED", "fail_reason": "duration_check"}])
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4"}, conns)
    assert not ok and "duration_check" in info


def test_expired_token_is_refreshed_and_saved(monkeypatch):
    saved = {}
    monkeypatch.setattr(app_module, "_load_sp_conns", lambda u: {})
    monkeypatch.setattr(app_module, "_save_sp_conns", lambda u, c: saved.update(c))
    monkeypatch.setattr(app_module.requests, "post", lambda url, timeout=None, headers=None, data=None: _R(
        {"access_token": "NEW", "refresh_token": "R2", "expires_in": 86400}))
    conns = {"tiktok": {"access_token": "OLD", "refresh_token": "R1", "expires_at": 1}}
    tok, err = app_module._tt_token("u", conns)
    assert tok == "NEW" and saved["tiktok"]["refresh_token"] == "R2"
    assert app_module._tt_token("u", {"tiktok": {"access_token": "OLD", "expires_at": 1}})[0] is None   # no refresh token
