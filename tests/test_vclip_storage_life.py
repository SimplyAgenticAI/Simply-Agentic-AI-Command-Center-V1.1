"""V14.3 clip storage lifecycle: used clips drop their source copy after
VCLIP_SLIM_DAYS (finished video stays), unused clips are deleted after
VCLIP_UNUSED_DAYS, and Keep stops both.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
from datetime import timedelta

import pytest

import app as app_module

U = "lifeuser"


def _ago(days):
    return (app_module._utcnow() - timedelta(days=days)).isoformat() + "Z"


def _clip(**extra):
    c = app_module._vc_new_clip(U, "abc123", 0.0, 20.0, title="T")
    with app_module._VC_ACTIVE_LOCK:
        app_module._VC_ACTIVE.discard((U, c["id"]))
    d = app_module._vc_dir(U) / c["id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "master.mp4").write_bytes(b"m" * 4096)
    (d / "clip_v1.mp4").write_bytes(b"c" * 512)
    app_module._vc_update(U, c["id"], lambda x: x.update(dict({"status": "ready", "file": "clip_v1.mp4"}, **extra)))
    return c["id"]


@pytest.fixture()
def life(flask_app):
    data = app_module.load_users()
    data.setdefault("users", {})[U] = {"username": U, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    app_module._vc_save(U, [])
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = U
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    yield c, h
    data = app_module.load_users()
    (data.get("users") or {}).pop(U, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def test_sweep_rules(life):
    old_unused = _clip(created_at=_ago(31))
    fresh_unused = _clip(created_at=_ago(5))
    used_long_ago = _clip(created_at=_ago(20), used_at=_ago(8))
    kept = _clip(created_at=_ago(60), kept=True)
    res = app_module._vc_sweep(U, force=True)
    assert res == {"slimmed": 1, "deleted": 1}
    ids = {c["id"] for c in app_module._vc_load(U)}
    assert old_unused not in ids and {fresh_unused, used_long_ago, kept} <= ids
    d = app_module._vc_dir(U) / used_long_ago
    assert not (d / "master.mp4").exists() and (d / "clip_v1.mp4").exists()   # finished video kept
    assert app_module._vc_get(U, used_long_ago)["slim"] is True
    assert (app_module._vc_dir(U) / kept / "master.mp4").exists()


def test_slim_clip_blocks_reedit_but_allows_title(life):
    c, h = life
    cid = _clip(slim=True, used_at=_ago(9))
    assert c.post(f"/api/vclips/{cid}", headers=h, json={"hook": "x", "defer": True}).status_code == 409
    assert c.post(f"/api/vclips/{cid}", headers=h, json={"title": "Renamed"}).get_json()["clip"]["title"] == "Renamed"


def test_download_marks_used_and_list_reports_life(life):
    c, h = life
    cid = _clip(created_at=_ago(26))
    lst = c.get("/api/vclips").get_json()
    me = next(x for x in lst["clips"] if x["id"] == cid)
    assert me["life"]["expires_in_days"] == 4 and lst["auto_free"] > 0
    assert c.get(f"/api/vclips/{cid}/file?download=1").status_code == 200
    assert app_module._vc_get(U, cid).get("used_at")
    assert c.post(f"/api/vclips/{cid}/touch", headers=h).get_json()["ok"]
