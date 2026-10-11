"""App page scripts are served as cacheable files (V10.3) and the page still
carries a working CSRF token. No accounts are created here: other tests expect
the first account in the run to come from /register."""
import re

import app as app_module


def _page(token="tok-1234567890abcdef"):
    return app_module._INDEX_TEMPLATE.render(csrf_token=token, app_title="", model="", trial_banner="", PUBLIC_BASE_URL="")


def test_index_scripts_are_external_and_cacheable(flask_app):
    html = _page()
    srcs = re.findall(r'<script src="/appjs/([0-9a-f]{16})\.js"></script>', html)
    assert len(srcs) >= 10
    inline = re.findall(r"<script>([\s\S]*?)</script>", html)
    assert sum(len(b) for b in inline) < 60_000            # was ~1.4 MB inline
    assert "window._csrfToken='tok-1234567890abcdef'" in html
    c = flask_app.test_client()                          # logged out is fine: no user data in these files
    r = c.get(f"/appjs/{srcs[0]}.js", headers={"Accept-Encoding": "gzip"})
    assert r.status_code == 200 and r.headers["Content-Encoding"] == "gzip"
    assert "immutable" in r.headers["Cache-Control"]
    plain = c.get(f"/appjs/{srcs[0]}.js")
    assert plain.status_code == 200 and "Content-Encoding" not in plain.headers
    assert c.get("/appjs/ffffffffffffffff.js").status_code == 404


def test_scripts_keep_original_order():
    src = open("templates/index.html", encoding="utf-8").read()
    bodies = [b for b in re.findall(r"<script>([\s\S]*?)</script>", src) if len(b) >= 2048]
    served = [app_module._APPJS[h][0].decode() for h in re.findall(r'/appjs/([0-9a-f]{16})\.js', _page())]
    assert [b.replace(app_module._CSRF_JINJA, "", 1) for b in bodies] == served
