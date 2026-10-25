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
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4", "options": {"tiktok": {"privacy": "PUBLIC_TO_EVERYONE", "allow_comment": True}}}, conns)
    assert ok and info == "tiktok:777"
    assert calls["init"]["post_info"]["privacy_level"] == "PUBLIC_TO_EVERYONE"
    assert calls["init"]["source_info"] == {"source": "FILE_UPLOAD", "video_size": 1000, "chunk_size": 1000, "total_chunk_count": 1}
    assert calls["puts"][0]["Content-Range"] == "bytes 0-999/1000" and calls["status"] == 2


def test_unapproved_app_posts_private_and_says_so(monkeypatch, tmp_path):
    calls = _setup(monkeypatch, tmp_path, ["SELF_ONLY"], [{"status": "PUBLISH_COMPLETE"}])
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4", "options": {"tiktok": {"privacy": "PUBLIC_TO_EVERYONE", "allow_comment": True}}}, conns)
    assert ok and "private until TikTok approves" in info
    assert calls["init"]["post_info"]["privacy_level"] == "SELF_ONLY"


def test_failed_processing_is_reported(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, ["SELF_ONLY"], [{"status": "FAILED", "fail_reason": "duration_check"}])
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4", "options": {"tiktok": {"privacy": "PUBLIC_TO_EVERYONE", "allow_comment": True}}}, conns)
    assert not ok and "duration_check" in info


def test_tiktok_needs_a_privacy_choice_and_sends_toggles(monkeypatch, tmp_path):
    calls = _setup(monkeypatch, tmp_path, ["PUBLIC_TO_EVERYONE", "SELF_ONLY"], [{"status": "PUBLISH_COMPLETE"}])
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    ok, info = app_module._sp_publish_tiktok("u", {"caption": "Hi", "media_url": "https://x/a.mp4"}, conns)
    assert not ok and "Choose who can view" in info
    post = {"caption": "Hi", "media_url": "https://x/a.mp4", "options": app_module._sp_clean_options(
        {"tiktok": {"privacy": "SELF_ONLY", "allow_duet": True, "disclose": True, "branded_content": True, "ai_generated": True}})}
    ok, _ = app_module._sp_publish_tiktok("u", post, conns)
    pi = calls["init"]["post_info"]
    assert ok and pi["privacy_level"] == "SELF_ONLY" and pi["disable_comment"] and not pi["disable_duet"]
    assert not pi["brand_content_toggle"] and not pi["brand_organic_toggle"] and pi["is_aigc"]   # branded content can't be private


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


def test_tiktok_refusals_are_explained():
    msg = app_module._tt_err({"error": {"code": "unaudited_client_can_only_post_to_private_accounts",
                                        "message": "Please review our integration guidelines"}})
    assert "PRIVATE TikTok account" in msg
    assert app_module._tt_err({"error": {"code": "weird_new_code", "message": "Nope"}}) == "Nope (weird_new_code)"
    assert app_module._tt_err({"error": {"code": "ok"}}) == ""


def test_unaudited_refusal_retries_as_only_me(monkeypatch, tmp_path):
    vid = tmp_path / "clip.mp4"
    vid.write_bytes(b"x" * 1000)
    monkeypatch.setattr(app_module, "_sp_media_file", lambda u, url: (vid, False, ""))
    monkeypatch.setattr(app_module.time, "sleep", lambda s: None)
    sent = []

    def fake_post(url, headers=None, json=None, data=None, timeout=None):
        if url.endswith("/creator_info/query/"):
            return _R({"data": {"privacy_level_options": ["FOLLOWER_OF_CREATOR", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"]}, "error": {"code": "ok"}})
        if url.endswith("/video/init/"):
            sent.append(json["post_info"]["privacy_level"])
            if json["post_info"]["privacy_level"] != "SELF_ONLY":
                return _R({"error": {"code": "unaudited_client_can_only_post_to_private_accounts", "message": "Please review"}})
            return _R({"data": {"publish_id": "P1", "upload_url": "https://up.example/1"}, "error": {"code": "ok"}})
        return _R({"data": {"status": "PUBLISH_COMPLETE"}})
    monkeypatch.setattr(app_module.requests, "post", fake_post)
    monkeypatch.setattr(app_module.requests, "put", lambda url, data=None, timeout=None, headers=None: _R())
    conns = {"tiktok": {"access_token": "T", "expires_at": app_module._now_epoch() + 3600}}
    post = {"caption": "Hi", "media_url": "x.mp4", "options": {"tiktok": {"privacy": "FOLLOWER_OF_CREATOR"}}}
    ok, info = app_module._sp_publish_tiktok("u", post, conns)
    assert ok and sent == ["FOLLOWER_OF_CREATOR", "SELF_ONLY"] and "private until TikTok approves" in info


def test_tiktok_coming_soon_for_users_not_admins(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "TIKTOK_CLIENT_KEY", "K")
    monkeypatch.setattr(app_module, "TIKTOK_CLIENT_SECRET", "S")
    monkeypatch.delenv("SP_COMING_SOON", raising=False)
    uname = "ttsoonuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        assert "tiktok" in c.get("/api/social/setup").get_json()["coming_soon"]
        r = c.get("/social/connect/tiktok")
        assert r.status_code == 200 and "coming soon" in r.get_data(as_text=True)
        monkeypatch.setattr(app_module, "_is_admin_user", lambda u: True)
        r2 = c.get("/social/connect/tiktok")
        assert r2.status_code == 302 and "tiktok.com" in r2.headers["Location"]      # admin can still connect
        monkeypatch.setenv("SP_COMING_SOON", "")
        assert app_module._sp_coming_soon() == set()                                 # cleared once approved
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()
