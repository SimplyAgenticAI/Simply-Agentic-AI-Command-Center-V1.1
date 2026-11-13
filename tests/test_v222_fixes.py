"""V22.2: LeadConnector settings, Today vs the connection bar, PWA icon, Team Goal."""
import json
import re
import xml.etree.ElementTree as ET

import app as app_module

LOC = "LocAbc123XYZ"
SVG = "{http://www.w3.org/2000/svg}"


def _user(name):
    data = app_module.load_users()
    data.setdefault("users", {})[name] = {"username": name, "password_hash": "x", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _client(flask_app, name):
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = name
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    return c, h


def _drop(name):
    data = app_module.load_users()
    (data.get("users") or {}).pop(name, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    app_module._sp_conns_path(name).unlink(missing_ok=True)


def test_app_version_is_22_2():
    assert app_module.APP_VERSION == "22.2"
    assert all("\u2014" not in item for item in app_module.WHATS_NEW_ITEMS)


def test_pwa_icon_svg_is_a_valid_image(client):
    resp = client.get("/pwa-icon.svg")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"] == "image/svg+xml"
    body = resp.get_data()
    assert body.startswith(b"<svg")
    assert b"<!doctype" not in body.lower()
    root = ET.fromstring(body)
    assert root.tag == SVG + "svg"
    assert root.get("width") == "512"
    assert root.get("height") == "512"
    manifest = client.get("/manifest.json")
    assert manifest.status_code == 200
    assert manifest.mimetype == "application/manifest+json"
    icon = next(i for i in manifest.get_json()["icons"] if i["src"] == "/pwa-icon.svg")
    assert icon["type"] == "image/svg+xml"
    assert icon["sizes"] == "any"


def test_lc_connect_uses_existing_fields_and_encrypts(flask_app, monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setattr(app_module, "_FERNET", Fernet(Fernet.generate_key()))

    class _Resp:
        def __init__(self, status, data):
            self.status_code, self._data = status, data
            self.content, self.text = b"x", ""

        def json(self):
            return self._data

    def fake_request(method, url, timeout=None, json=None, headers=None):
        if headers and headers.get("Authorization") == "Bearer bad-token":
            return _Resp(401, {"message": "Invalid JWT"})
        return _Resp(200, {"results": {"accounts": [{"id": "fb1", "name": "Acme", "platform": "facebook"}]}})

    monkeypatch.setattr(app_module.requests, "request", fake_request)
    name = "lcsettings"
    _user(name)
    try:
        c, h = _client(flask_app, name)
        bad = c.post("/api/social/lc/connect", headers=h, json={"token": "bad-token", "location_id": LOC})
        assert bad.status_code == 400 and not bad.get_json()["ok"]
        assert app_module._lc_conn(name) is None

        saved = c.post("/api/social/lc/connect", headers=h, json={"token": "pit-secret-value", "location_id": LOC})
        assert saved.status_code == 200 and saved.get_json()["ok"]
        on_disk = app_module._sp_conns_path(name).read_text(encoding="utf-8")
        assert "pit-secret-value" not in on_disk
        blob = json.loads(on_disk)
        assert blob["_encrypted"].startswith("enc:")
        loaded = app_module._load_sp_conns(name)["leadconnector"]
        assert loaded["token"] == "pit-secret-value" and loaded["location_id"] == LOC

        ready = c.get("/api/connections/readiness").get_json()
        assert ready["crm"] is True
        summary = c.get("/api/social/connections").get_json()["connections"]["leadconnector"]
        assert summary["connected"] is True and summary["location_id"] == LOC and "token" not in summary

        tested = c.post("/api/social/lc/refresh", headers=h).get_json()
        assert tested["ok"] and tested["accounts"][0]["id"] == "fb1"

        assert c.post("/api/social/disconnect/leadconnector", headers=h).get_json()["ok"]
        assert c.get("/api/connections/readiness").get_json()["crm"] is False
        assert app_module._lc_conn(name) is None
    finally:
        _drop(name)


def _served_app(client):
    """The signed-in page plus the external scripts it loads, in order."""
    html = client.get("/").get_data(as_text=True)
    parts = [html]
    for h in re.findall(r'/appjs/([0-9a-f]{16})\.js', html):
        parts.append(client.get(f"/appjs/{h}.js").get_data(as_text=True))
    return html, "\n".join(parts)


def test_signed_in_shell_points_at_the_new_surfaces(client):
    _user("v222shell")
    try:
        with client.session_transaction() as s:
            s["user"] = "v222shell"
        html, src = _served_app(client)
        assert "openSettings('lcConnectCard')" in src
        assert "openPlanner('cpLcStatus')" not in src
        assert 'id="lcConnectCard"' in html
        assert 'id="lcToken"' in html
        assert 'id="lcLocationId"' in html
        assert 'id="lcConnectBtn"' in html
        assert 'id="lcTestBtn"' in html
        assert 'id="lcDisconnectBtn"' in html
        assert "/api/social/lc/connect" in src
        assert "/api/social/lc/refresh" in src
        assert "/api/social/disconnect/leadconnector" in src
        assert "saPinTodayBelowBanner" in src
        card = html.split('id="lcConnectCard"', 1)[1].split("INBOX", 1)[0]
        assert "\u2014" not in card
        assert 'id="teamGoalOpenBtn"' in html
        assert 'id="stTeamGoalOpen"' in html
        assert 'id="stTeamGoalTab"' in html
        assert html.count(">Do: Team Goal<") >= 3
        assert 'id="teamGoalBtn"' in html
        assert "if(window.saPinTodayBelowBanner) window.saPinTodayBelowBanner();" in src
    finally:
        _drop("v222shell")
