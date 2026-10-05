"""Record Studio (V9.8): chunked live upload of separate screen/camera tracks →
finish → composited clip whose layout can be changed after recording.
Real ffmpeg on synthetic VP8/Opus WebM (what Chrome's MediaRecorder emits)."""
import io
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

import app as app_module


def _webm(path: Path, size: str, audio: bool, color_src: str) -> bool:
    args = [app_module._ffmpeg_bin(), "-y", "-f", "lavfi", "-i", f"{color_src}=size={size}:rate=30:duration=4"]
    if audio:
        args += ["-f", "lavfi", "-i", "sine=frequency=330:duration=4", "-c:a", "libopus"]
    args += ["-c:v", "libvpx", "-b:v", "800k", "-shortest" if audio else "-an", str(path)]
    if not audio:
        args = [a for a in args if a != "-shortest"]
    r = subprocess.run(args, capture_output=True, timeout=120)
    return r.returncode == 0 and path.exists()


@pytest.fixture()
def rec_client(flask_app):
    uname = "recorder"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    return c, h, uname


def _upload(c, h, rid, track, blob, parts=3):
    size = len(blob) // parts + 1
    chunks = [blob[i:i + size] for i in range(0, len(blob), size)]
    for i, ch in enumerate(chunks):
        r = c.post("/api/rec/chunk", headers=h, content_type="multipart/form-data",
                   data={"rec_id": rid, "track": track, "idx": str(i), "chunk": (io.BytesIO(ch), "c.webm")})
        assert r.get_json()["ok"], r.get_json()
    return chunks


def _finish(c, h, rid):
    d = c.post("/api/rec/finish", headers=h, json={"rec_id": rid, "title": "My demo"}).get_json()
    assert d["ok"] and d["job_id"], d
    for _ in range(600):
        j = c.get(f"/api/video/job/{d['job_id']}").get_json()
        if j.get("status") != "working":
            return j
        time.sleep(0.3)
    raise AssertionError("finish never completed")


def _wait_ready(c, cid):
    for _ in range(600):
        clip = next(x for x in c.get("/api/vclips").get_json()["clips"] if x["id"] == cid)
        if clip["status"] != "rendering":
            return clip
        time.sleep(0.3)
    raise AssertionError("render timed out")


def test_screen_and_camera_recording_with_layouts(rec_client):
    c, h, uname = rec_client
    tmp = Path(tempfile.mkdtemp())
    scr, cam = tmp / "screen.webm", tmp / "cam.webm"
    if not (_webm(scr, "1280x720", True, "testsrc") and _webm(cam, "640x480", False, "smptebars")):
        pytest.skip("ffmpeg build lacks libvpx/libopus")
    rid = c.post("/api/rec/start", headers=h, json={"mode": "screen_cam"}).get_json()["rec_id"]
    chunks = _upload(c, h, rid, "screen", scr.read_bytes())
    _upload(c, h, rid, "cam", cam.read_bytes())

    # A retried (duplicate) chunk is acknowledged but not appended; a gap is refused
    r = c.post("/api/rec/chunk", headers=h, content_type="multipart/form-data",
               data={"rec_id": rid, "track": "screen", "idx": "0", "chunk": (io.BytesIO(chunks[0]), "c.webm")})
    assert r.get_json().get("dup") is True
    r = c.post("/api/rec/chunk", headers=h, content_type="multipart/form-data",
               data={"rec_id": rid, "track": "screen", "idx": "9", "chunk": (io.BytesIO(b"x"), "c.webm")})
    assert r.status_code == 409

    j = _finish(c, h, rid)
    assert j["ok"], j
    clip = _wait_ready(c, j["clip_id"])
    assert clip["status"] == "ready", clip
    assert clip["rec"]["tracks"] == ["cam", "screen"]
    assert clip["layout"]["type"] == "bubble" and (clip["width"], clip["height"]) == (1280, 720)
    assert 3.0 <= clip["duration"] <= 4.6

    cid = clip["id"]
    for lay, dims in (("stacked", (720, 1280)), ("cam", (720, 1280)), ("screen", (1280, 720))):
        d = c.post(f"/api/vclips/{cid}", headers=h, json={"layout": {"type": lay}}).get_json()
        assert d["ok"] and d["rerender"], d
        clip = _wait_ready(c, cid)
        assert clip["status"] == "ready" and (clip["width"], clip["height"]) == dims, (lay, clip)

    # Bubble corner/size change re-renders too
    d = c.post(f"/api/vclips/{cid}", headers=h, json={"layout": {"type": "bubble", "corner": "tl", "size": "l"}}).get_json()
    assert d["rerender"] and _wait_ready(c, cid)["status"] == "ready"

    # Recorded clips can always be re-trimmed (tracks persist — no source upload needed)
    d = c.post(f"/api/vclips/{cid}", headers=h, json={"start": 1.0, "end": 3.5}).get_json()
    assert d["ok"] and d["rerender"], d
    assert _wait_ready(c, cid)["status"] == "ready"


def test_camera_take_to_clips(rec_client):
    c, h, uname = rec_client
    tmp = Path(tempfile.mkdtemp())
    take = tmp / "take.webm"
    if not _webm(take, "960x540", True, "testsrc"):
        pytest.skip("ffmpeg build lacks libvpx/libopus")
    rid = c.post("/api/rec/start", headers=h, json={"mode": "cam"}).get_json()["rec_id"]
    _upload(c, h, rid, "cam", take.read_bytes(), parts=2)
    j = _finish(c, h, rid)
    assert j["ok"], j
    clip = _wait_ready(c, j["clip_id"])
    assert clip["status"] == "ready" and clip["layout"]["type"] == "cam"
    assert (clip["width"], clip["height"]) == (960, 540)


def test_bad_sessions_rejected(rec_client):
    c, h, uname = rec_client
    r = c.post("/api/rec/chunk", headers=h, content_type="multipart/form-data",
               data={"rec_id": "r000000000000", "track": "screen", "idx": "0", "chunk": (io.BytesIO(b"x"), "c.webm")})
    assert r.status_code == 404
    assert c.post("/api/rec/finish", headers=h, json={"rec_id": "../etc"}).status_code == 400
    rid = c.post("/api/rec/start", headers=h, json={"mode": "screen"}).get_json()["rec_id"]
    j = _finish(c, h, rid)   # nothing uploaded
    assert not j["ok"] and "empty" in j["error"]
