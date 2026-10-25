"""V17.9: real video files in the Media Library (save a recording/clip copy,
list, download, delete). (Sorts after test_client_crud.)"""
import app as app_module


def test_save_list_download_delete(flask_app, monkeypatch, tmp_path):
    src = tmp_path / "clip.mp4"
    src.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"1" * 200)
    monkeypatch.setattr(app_module, "_vc_get", lambda u, cid: {"id": cid, "title": "Recording Oct 25", "start": 0, "end": 12.5} if cid == "c1" else None)
    monkeypatch.setattr(app_module, "_vc_file", lambda u, c, *a: src if c else None)
    uname = "mvuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
        r = c.post("/api/media/videos/save", headers=h, json={"clip_id": "c1"}).get_json()
        assert r["ok"] and r["video"]["id"].startswith("mv_") and r["video"]["duration"] == 12.5
        vid = r["video"]["id"]
        src.unlink()                                                    # the copy survives the clip going away
        lst = c.get("/api/media/videos").get_json()["videos"]
        assert [v["id"] for v in lst] == [vid]
        dl = c.get(f"/api/media/videos/{vid}/file?download=1")
        assert dl.status_code == 200 and "attachment" in dl.headers["Content-Disposition"] and "Recording Oct 25.mp4" in dl.headers["Content-Disposition"]
        dl.close()
        assert c.post("/api/media/videos/save", headers=h, json={"clip_id": "nope"}).status_code == 404
        assert c.get("/api/media/videos/../../etc/file").status_code == 404
        d = c.post("/api/media/videos/delete", headers=h, json={"ids": [vid]}).get_json()
        assert d["deleted"] == 1 and c.get("/api/media/videos").get_json()["videos"] == []
        assert flask_app.test_client().get(f"/api/media/videos/{vid}/file").status_code in (302, 401)
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()
