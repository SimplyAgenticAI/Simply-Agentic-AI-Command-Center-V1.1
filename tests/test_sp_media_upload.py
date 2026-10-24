"""V17.1: plain photo/video uploads in the Content Planner - stored on disk,
photos converted to JPEG (Instagram needs it), signed public links, owner-only
local resolve for TikTok/YouTube. (File must sort after test_client_crud.)"""
import io

import app as app_module


def _client(flask_app, uname):
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    return c, h


def _drop(uname):
    data = app_module.load_users()
    (data.get("users") or {}).pop(uname, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _png_bytes():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGBA", (40, 30), (200, 50, 50, 128)).save(buf, "PNG")
    return buf.getvalue()


def test_photo_upload_becomes_public_jpeg(flask_app):
    uname = "spmuser1"
    c, h = _client(flask_app, uname)
    try:
        r = c.post("/api/social/media", headers=h, content_type="multipart/form-data",
                   data={"file": (io.BytesIO(_png_bytes()), "pic.png")}).get_json()
        assert r["ok"] and r["kind"] == "image" and r["url"].endswith(".jpg")
        path = "/spm/" + r["url"].split("/spm/")[1]
        anon = flask_app.test_client()                                   # public: no login needed
        got = anon.get(path)
        assert got.status_code == 200 and got.mimetype == "image/jpeg" and got.data[:3] == b"\xff\xd8\xff"
        assert anon.get(path.replace(".jpg", "x.jpg")).status_code == 404   # tampered link
        assert app_module._spm_local_file(uname, r["url"]) is not None
        assert app_module._spm_local_file("someoneelse", r["url"]) is None  # owner only
    finally:
        _drop(uname)


def test_video_upload_and_rejects(flask_app):
    uname = "spmuser2"
    c, h = _client(flask_app, uname)
    try:
        r = c.post("/api/social/media", headers=h, content_type="multipart/form-data",
                   data={"file": (io.BytesIO(b"\x00\x00\x00\x18ftypmp42" + b"0" * 500), "clip.MOV")}).get_json()
        assert r["ok"] and r["kind"] == "video" and r["url"].endswith(".mov")
        assert app_module._sp_is_video(r["url"])
        p, is_tmp, err = app_module._sp_media_file(uname, r["url"])           # TikTok/YouTube read it from disk
        assert p is not None and not is_tmp
        bad = c.post("/api/social/media", headers=h, content_type="multipart/form-data",
                     data={"file": (io.BytesIO(b"x"), "notes.txt")})
        assert bad.status_code == 400
        assert c.post("/api/social/media", headers=h, content_type="multipart/form-data", data={}).status_code == 400
        assert flask_app.test_client().post("/api/social/media").status_code in (400, 401, 403)
    finally:
        _drop(uname)
