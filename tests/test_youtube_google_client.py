"""V16.3: YouTube can use its own Google keys (separate project, sensitive
scopes only), and old *.onrender.com page visits move to the real domain.
(File must sort after test_client_crud.)"""
from urllib.parse import parse_qs, urlparse

import app as app_module


def test_youtube_uses_its_own_keys_when_set(monkeypatch):
    monkeypatch.setattr(app_module, "GOOGLE_CLIENT_ID", "SHARED")
    monkeypatch.setattr(app_module, "YOUTUBE_CLIENT_ID", "")
    monkeypatch.setattr(app_module, "YOUTUBE_CLIENT_SECRET", "")
    assert app_module._yt_client() is None
    monkeypatch.setattr(app_module, "YOUTUBE_CLIENT_ID", "YTID")
    monkeypatch.setattr(app_module, "YOUTUBE_CLIENT_SECRET", "YTSEC")
    url = app_module._oauth_auth_url(app_module.YOUTUBE_SCOPES, "/social/callback/youtube", "s", app_module._yt_client())
    q = parse_qs(urlparse(url).query)
    assert q["client_id"] == ["YTID"] and "youtube.upload" in q["scope"][0] and "force-ssl" not in q["scope"][0]
    assert parse_qs(urlparse(app_module._oauth_auth_url(["x"], "/gmail/callback", "s")).query)["client_id"] == ["SHARED"]


def test_refresh_uses_the_keys_the_connection_was_made_with(monkeypatch):
    sent = []
    monkeypatch.setattr(app_module, "GOOGLE_CLIENT_ID", "SHARED")
    monkeypatch.setattr(app_module, "GOOGLE_CLIENT_SECRET", "SSEC")
    monkeypatch.setattr(app_module, "PUBLIC_BASE_URL", "https://www.example.com")
    monkeypatch.setattr(app_module, "YOUTUBE_CLIENT_ID", "YTID")
    monkeypatch.setattr(app_module, "YOUTUBE_CLIENT_SECRET", "YTSEC")
    monkeypatch.setattr(app_module, "_save_sp_conns", lambda u, c: None)
    monkeypatch.setattr(app_module, "_load_sp_conns", lambda u: {})

    class _R:
        status_code, content = 200, b"x"
        def json(self):
            return {"access_token": "NEW", "expires_in": 3600}
    monkeypatch.setattr(app_module.requests, "post", lambda url, data=None, timeout=None: sent.append(data["client_id"]) or _R())
    for client, want in (("youtube", "YTID"), ("google", "SHARED"), (None, "SHARED")):
        yt = {"access_token": "OLD", "refresh_token": "R", "expires_at": 1}
        if client:
            yt["client"] = client
        tok, err = app_module._sp_youtube_token("u", {"youtube": yt})
        assert tok == "NEW" and sent[-1] == want


def test_onrender_page_visits_move_to_the_real_domain(flask_app, monkeypatch):
    c = flask_app.test_client()
    host = {"Host": "simply-agentic-ai-command-center-v1-1-1.onrender.com"}
    monkeypatch.setattr(app_module, "PUBLIC_BASE_URL", "https://www.simplyagenticai.com")
    r = c.get("/login?next=/x", headers=host)
    assert r.status_code == 301 and r.headers["Location"] == "https://www.simplyagenticai.com/login?next=/x"
    assert c.get("/api/csrf_token", headers=host).status_code != 301        # API calls untouched
    assert c.post("/login", headers=host).status_code != 301                 # so are POSTs
    assert c.get("/login", headers={"Host": "www.simplyagenticai.com"}).status_code != 301
    monkeypatch.setattr(app_module, "PUBLIC_BASE_URL", "https://simply-agentic-ai-command-center-v1-1-1.onrender.com")
    assert c.get("/login", headers=host).status_code != 301                  # not switched yet → nothing moves
