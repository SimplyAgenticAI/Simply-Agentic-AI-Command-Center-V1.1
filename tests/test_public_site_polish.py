"""Public pages: meta tags, sitemap, favicon, llms.txt, and trailing slashes.

Sorts after test_client_crud. The first registered user in a test process is
the admin; these checks stay on the anonymous client except where a signed-in
shell is required.
"""
import re
from urllib.parse import urlparse

import app as app_module

ORIGIN = "https://www.simplyagenticai.com"

PUBLIC_PAGES = {
    "/login": "Sign in to Simply Agentic AI, your AI-powered business command center.",
    "/register": "Create a Simply Agentic AI account. An access code from your subscription is required once an account already exists.",
    "/pricing": "Plans for Simply Agentic AI. Every plan includes all 7 AI teammates, CRM, broadcasts, calendar, lead finding, and video clips.",
    "/terms": "Terms of Service for Simply Agentic AI: using the service, subscriptions and billing, API keys, acceptable use, and AI-generated content.",
    "/privacy": "Privacy Policy for Simply Agentic AI: account, billing, API key, and usage data, how it is used, and how to ask for deletion.",
}


def _ensure_an_account():
    """/ redirects to first-time setup only when the install has zero users."""
    data = app_module.load_users()
    users = data.setdefault("users", {})
    if users:
        return
    users["publicseed"] = {"username": "publicseed", "password_hash": "x", "is_admin": True}
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _attr(html, pattern):
    match = re.search(pattern, html)
    assert match, pattern
    return match.group(1)


def test_public_pages_have_unique_meta(client, monkeypatch):
    monkeypatch.setenv("ALLOW_SIGNUP", "1")
    seen = []
    for path, description in PUBLIC_PAGES.items():
        resp = client.get(path)
        assert resp.status_code == 200, path
        html = resp.get_data(as_text=True)
        got = _attr(html, r'<meta name="description" content="([^"]*)"')
        assert got == description
        assert _attr(html, r'<link rel="canonical" href="([^"]*)"') == ORIGIN + path
        assert _attr(html, r'<meta property="og:url" content="([^"]*)"') == ORIGIN + path
        assert _attr(html, r'<meta property="og:description" content="([^"]*)"') == description
        assert _attr(html, r'<meta property="og:type" content="([^"]*)"') == "website"
        assert _attr(html, r'<meta property="og:site_name" content="([^"]*)"') == "Simply Agentic AI"
        assert _attr(html, r'<meta property="og:title" content="([^"]*)"')
        assert _attr(html, r'<meta name="twitter:card" content="([^"]*)"') == "summary_large_image"
        image = ORIGIN + "/static/og-image.png"
        assert _attr(html, r'<meta property="og:image" content="([^"]*)"') == image
        assert _attr(html, r'<meta name="twitter:image" content="([^"]*)"') == image
        assert f"V{app_module.APP_VERSION}" not in html
        assert 'href="/favicon.ico"' in html
        seen.append(description)
    assert len(set(seen)) == len(PUBLIC_PAGES)


def test_signed_in_shell_has_favicon_without_public_canonical():
    html = app_module._INDEX_TEMPLATE.render(
        app_title="Simply Agentic AI",
        model="gpt-4o",
        trial_banner="",
        PUBLIC_BASE_URL="",
        csrf_token="tok",
    )
    assert 'href="/favicon.ico"' in html
    assert 'rel="canonical"' not in html
    assert 'content="summary"' not in html


def test_sitemap_lists_only_real_public_pages(client, monkeypatch):
    _ensure_an_account()
    monkeypatch.setenv("ALLOW_SIGNUP", "1")
    resp = client.get("/sitemap.xml")
    assert resp.status_code == 200
    locs = re.findall(r"<loc>(.*?)</loc>", resp.get_data(as_text=True))
    paths = [urlparse(loc).path for loc in locs]
    assert paths == ["/", "/login", "/register", "/pricing", "/terms", "/privacy"]
    for path in paths:
        assert client.get(path).status_code == 200, path


def test_favicon_reuses_the_pwa_mark(client):
    resp = client.get("/favicon.ico")
    assert resp.status_code == 200
    assert resp.mimetype == "image/x-icon"
    body = resp.get_data()
    assert body[:4] == b"\x00\x00\x01\x00"
    assert body[22:26] == b"\x89PNG"
    page = client.get("/showcase")
    assert page.status_code == 200
    assert 'href="/favicon.ico"' in page.get_data(as_text=True)


def test_llms_txt_matches_the_public_site(client):
    resp = client.get("/llms.txt")
    assert resp.status_code == 200
    assert resp.mimetype == "text/plain"
    text = resp.get_data(as_text=True)
    assert "Simply Agentic AI" in text
    assert "MacRandle Acres" in text
    assert "1247 Johnson Rd" in text
    for path in ("/", "/showcase", "/pricing", "/login", "/register", "/terms", "/privacy", "/sitemap.xml"):
        assert ORIGIN + path in text
    assert "public homepage" in text
    assert "sends visitors to sign in" not in text
    assert "$" not in text


def test_trailing_slash_redirects_public_gets_only(client):
    for path in ("/login/", "/register/", "/pricing/", "/terms/", "/privacy/", "/showcase/", "/sitemap.xml/"):
        resp = client.get(path)
        assert resp.status_code == 301, path
        assert urlparse(resp.headers["Location"]).path == path.rstrip("/")

    priced = client.get("/pricing/?plan=solo")
    assert priced.status_code == 301
    parsed = urlparse(priced.headers["Location"])
    assert parsed.path == "/pricing"
    assert parsed.query == "plan=solo"

    assert client.head("/login/").status_code == 301

    posted = client.post("/login/", data={"username": "a", "password": "b"})
    assert posted.status_code != 301

    login = client.post("/login", data={"username": "nobody-seo", "password": "not-a-password"})
    assert login.status_code == 200

    # /admin/ is a real prefix (login redirect when signed out). It must not
    # be rewritten to /admin.
    anon_admin = client.get("/admin/")
    assert anon_admin.status_code != 301
    assert urlparse(anon_admin.headers.get("Location") or "").path != "/admin"
    assert client.get("/admin/users").status_code != 301


def test_logged_out_root_is_the_marketing_page(client):
    _ensure_an_account()
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "7 Specialists" in html
    assert ">Log in<" in html
    assert ">Start<" in html
    assert "unlimited teammates" not in html.lower()
    assert "7 custom teammates" in html
    assert "local service" in html.lower()
    assert "NJ real estate" not in html
    assert f"V{app_module.APP_VERSION}" not in html
    assert _attr(html, r'<link rel="canonical" href="([^"]*)"') == ORIGIN + "/"
    assert _attr(html, r'<meta property="og:image" content="([^"]*)"') == ORIGIN + "/static/og-image.png"
    assert _attr(html, r'<meta name="twitter:image" content="([^"]*)"') == ORIGIN + "/static/og-image.png"
    same = client.get("/showcase")
    assert same.status_code == 200
    show = same.get_data(as_text=True)
    assert "7 Specialists" in show
    assert _attr(show, r'<link rel="canonical" href="([^"]*)"') == ORIGIN + "/"
    assert f"V{app_module.APP_VERSION}" not in show


def test_logged_in_root_stays_the_app(client):
    _ensure_an_account()
    data = app_module.load_users()
    data["users"]["homeuser"] = {"username": "homeuser", "password_hash": "x", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    with client.session_transaction() as s:
        s["user"] = "homeuser"
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert 'id="tableWrap"' in html
    assert "7 Specialists" not in html
    assert f"V{app_module.APP_VERSION}" in html
    assert 'id="saConnBanner"' in html
    assert "saDayOneStart" in html
    assert ">Discuss<" in html
    assert "Do. Agents take real actions with tools." in html
