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
        assert _attr(html, r'<meta name="twitter:card" content="([^"]*)"') == "summary"
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
    monkeypatch.setenv("ALLOW_SIGNUP", "1")
    resp = client.get("/sitemap.xml")
    assert resp.status_code == 200
    locs = re.findall(r"<loc>(.*?)</loc>", resp.get_data(as_text=True))
    paths = [urlparse(loc).path for loc in locs]
    assert paths == ["/login", "/register", "/pricing", "/terms", "/privacy", "/showcase"]
    assert all(path not in ("", "/") for path in paths)
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
    for path in ("/showcase", "/pricing", "/login", "/register", "/terms", "/privacy", "/sitemap.xml"):
        assert ORIGIN + path in text
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
