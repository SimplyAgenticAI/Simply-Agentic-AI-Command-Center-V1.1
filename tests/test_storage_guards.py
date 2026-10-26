"""V19.6: planner uploads are cleaned up safely, uploads stop with a clear message
when the disk is nearly full, and /health warns early.
(File must sort after test_client_crud.)"""
import os
import time
import app as app_module


def _old(p, days=40):
    t = time.time() - days * 86400
    os.utime(p, (t, t))


def test_sweep_keeps_media_of_unpublished_posts(monkeypatch):
    uname = "spmsweepuser"
    d = app_module._spm_dir(uname)
    keep_mid, pub_mid, orphan_mid, new_mid = "a" * 24, "b" * 24, "c" * 24, "d" * 24
    for mid in (keep_mid, pub_mid, orphan_mid, new_mid):
        (d / f"{mid}.jpg").write_bytes(b"x")
    for mid in (keep_mid, pub_mid, orphan_mid):
        _old(d / f"{mid}.jpg")
    posts = [{"status": "scheduled", "media_url": app_module._spm_public_url(uname, keep_mid, ".jpg")},
             {"status": "published", "media_url": app_module._spm_public_url(uname, pub_mid, ".jpg")}]
    monkeypatch.setattr(app_module, "_load_sp_posts", lambda u: posts)
    try:
        assert app_module._spm_sweep(uname, force=True) == 2
        left = sorted(p.name.split(".")[0] for p in d.iterdir())
        assert left == sorted([keep_mid, new_mid])
    finally:
        for p in d.iterdir():
            p.unlink()


def test_sweep_does_nothing_if_posts_cannot_be_read(monkeypatch, tmp_path):
    uname = "spmsweepunread"
    d = app_module._spm_dir(uname)
    (d / ("e" * 24 + ".jpg")).write_bytes(b"x")
    _old(d / ("e" * 24 + ".jpg"))
    fake = tmp_path / "posts.json"
    fake.write_text("{corrupt json ............}")
    monkeypatch.setattr(app_module, "_sp_posts_path", lambda u: fake)
    monkeypatch.setattr(app_module, "_load_sp_posts", lambda u: [])
    try:
        assert app_module._spm_sweep(uname, force=True) == 0
        assert len(list(d.iterdir())) == 1
    finally:
        for p in d.iterdir():
            p.unlink()


def test_uploads_refused_when_disk_nearly_full(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "_disk_free_mb", lambda: 500)
    with flask_app.test_request_context():
        resp, code = app_module._disk_full_response(0)
        assert code == 507 and "nearly full" in resp.get_json()["error"]
    monkeypatch.setattr(app_module, "_disk_free_mb", lambda: 5000)
    with flask_app.test_request_context():
        assert app_module._disk_full_response(10 * 1048576) is None


def test_video_limits_fit_the_disk():
    L = app_module.VCLIP_STORAGE_LIMITS
    assert L["founder"] <= L["solo"] <= L["teams"] <= 5 * app_module._GB
