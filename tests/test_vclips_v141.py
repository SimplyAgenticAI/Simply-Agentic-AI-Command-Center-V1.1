"""V14.1 Video Editor: live preview + deferred render, auto zoom, keyword
captions, face-following crop, Schedule all.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import pytest

import app as app_module


@pytest.fixture()
def vc(flask_app, monkeypatch):
    uname = "vc141user"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    started = []
    monkeypatch.setattr(app_module, "_vc_start_render", lambda u, user, cid: started.append(cid))
    clip = app_module._vc_new_clip(uname, "abc123", 0.0, 20.0, title="T", aspect="9:16", captions_on=True)
    app_module._vc_update(uname, clip["id"], lambda x: x.update({"status": "ready", "m_start": 0.0, "m_end": 20.0}))
    with app_module._VC_ACTIVE_LOCK:
        app_module._VC_ACTIVE.discard((uname, clip["id"]))
    yield c, h, uname, clip["id"], started
    data = app_module.load_users()
    (data.get("users") or {}).pop(uname, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def test_deferred_save_marks_edited_without_rendering(vc):
    c, h, uname, cid, started = vc
    r = c.post(f"/api/vclips/{cid}", headers=h, json={"hook": "New hook", "auto_zoom": True, "defer": True}).get_json()
    assert r["ok"] and r["rerender"] and r["clip"]["stale"] is True and r["clip"]["auto_zoom"] is True
    assert started == []                                   # nothing rendered yet
    assert c.post(f"/api/vclips/{cid}/render", headers=h).get_json()["ok"]
    assert started == [cid]                                # renders once, on demand


def test_master_preview_needs_the_file(vc):
    c, h, uname, cid, _ = vc
    assert c.get(f"/api/vclips/{cid}/master").status_code == 404
    d = app_module._vc_dir(uname) / cid
    d.mkdir(parents=True, exist_ok=True)
    (d / "master.mp4").write_bytes(b"\x00" * 64)
    assert c.get(f"/api/vclips/{cid}/master").status_code == 200


def test_schedule_needs_clips(vc):
    c, h, *_ = vc
    assert c.post("/api/vclips/schedule", headers=h, json={"ids": []}).status_code == 400


def test_keyword_captions_use_brand_colour():
    words = [{"w": "Most", "s": 0, "e": .3}, {"w": "businesses", "s": .4, "e": .9}, {"w": "lose", "s": 1, "e": 1.2},
             {"w": "40%", "s": 1.3, "e": 1.6}, {"w": "of", "s": 1.7, "e": 1.8}, {"w": "leads.", "s": 1.9, "e": 2.3}]
    kw = app_module._vc_keyword_idx(words)
    assert 1 in kw and 3 in kw                              # long meaningful word + the number
    ass = app_module._vc_build_ass(720, 1280, words, "bold", "", "#FF0000", 3.0, keywords=kw)
    assert "\\fscx112" in ass and "&H000000FF" in ass        # ASS colour is BGR


def test_zoom_and_reframe_plans_cover_the_clip():
    words = [{"w": w, "s": i * .5, "e": i * .5 + .4} for i, w in enumerate("One idea. Then another one here. And a third point now.".split())]
    plan = app_module._vc_zoom_plan(words, 6.0)
    assert plan[0][0] == 0.0 and plan[-1][1] == 6.0 and {z for *_, z in plan} == {1.0, 1.12}
    g = app_module._vc_reframe_graph("vc", "vs", 720, 1280, 1280, 720, 6.0, plan, [(0.0, .3), (3.0, .6)], cover=True)
    assert g[-1].endswith("[vs]") and "concat=n=" in g[-1] and all("setsar=1" in x for x in g[1:-1])
