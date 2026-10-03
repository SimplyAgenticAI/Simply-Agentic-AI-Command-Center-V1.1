"""Video Editor end-to-end on real media (V9.6.12): chunked upload → assemble →
range-request streaming → background export / audio jobs → HEVC preview proxy.
Uses the bundled ffmpeg (imageio-ffmpeg) to synthesise test clips."""
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

import app as app_module


def _make_clip(path: Path, vcodec: str) -> bool:
    r = subprocess.run([app_module._ffmpeg_bin(), "-y",
                        "-f", "lavfi", "-i", "testsrc=size=320x240:rate=24:duration=6",
                        "-f", "lavfi", "-i", "sine=frequency=440:duration=6",
                        "-c:v", vcodec, "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", str(path)],
                       capture_output=True, timeout=120)
    return r.returncode == 0 and path.exists()


def _client(flask_app, uname="videotester"):
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    tok = c.get("/api/csrf_token").get_json()["csrf_token"]
    with c.session_transaction() as s:
        s["user"] = uname
    return c, {"X-CSRF-Token": tok}


def _upload(c, h, path: Path, name: str) -> str:
    blob = path.read_bytes()
    size = max(1, len(blob) // 2 + 1)
    chunks = [blob[i:i + size] for i in range(0, len(blob), size)]
    uid = "ve_1700000000_abcd1234"
    import io
    for i, ch in enumerate(chunks):
        r = c.post("/api/video/upload_chunk", headers=h, content_type="multipart/form-data",
                   data={"upload_id": uid, "chunk_index": str(i), "total_chunks": str(len(chunks)),
                         "filename": name, "chunk": (io.BytesIO(ch), f"chunk_{i}")})
        assert r.get_json()["ok"], r.get_json()
    r = c.post("/api/video/upload", headers=h, json={"upload_id": uid, "filename": name})
    d = r.get_json()
    assert d["ok"], d
    return d["video_id"]


def _wait(c, resp):
    d = resp.get_json()
    assert d["ok"] and d.get("job_id"), d
    for _ in range(240):
        j = c.get(f"/api/video/job/{d['job_id']}").get_json()
        if j.get("status") != "working":
            return j
        time.sleep(0.25)
    raise AssertionError("job never finished")


def test_upload_stream_export_audio(flask_app):
    tmp = Path(tempfile.mkdtemp())
    src = tmp / "clip.mp4"
    assert _make_clip(src, "libx264")
    c, h = _client(flask_app)
    vid = _upload(c, h, src, "My Clip.MP4")

    # Seekable streaming (HTTP range) of the original
    r = c.get(f"/api/video/stream/{vid}", headers={"Range": "bytes=0-99"})
    assert r.status_code == 206 and len(r.data) == 100

    # Export a trimmed clip in the background, then download it
    j = _wait(c, c.post("/api/video/export", headers=h, json={"video_id": vid, "start": 1.5, "end": 4.0}))
    assert j["ok"], j
    dl = c.get(f"/api/video/download/{j['export_id']}")
    assert dl.status_code == 200 and dl.data[4:8] == b"ftyp"

    # Silent export
    j = _wait(c, c.post("/api/video/export", headers=h, json={"video_id": vid, "start": 0, "end": 2, "mute": True}))
    assert j["ok"], j

    # Audio extraction
    j = _wait(c, c.post("/api/video/extract_audio", headers=h, json={"video_id": vid, "start": 1, "end": 3}))
    assert j["ok"], j
    assert c.get(f"/api/video/download/{j['export_id']}").status_code == 200

    # Another user can't read this user's job
    c2, _h2 = _client(flask_app, "videotester2")
    jid = c.post("/api/video/export", headers=h, json={"video_id": vid, "start": 0, "end": 1}).get_json()["job_id"]
    assert c2.get(f"/api/video/job/{jid}").status_code == 404


def test_hevc_gets_playable_preview(flask_app):
    tmp = Path(tempfile.mkdtemp())
    src = tmp / "iphone.mov"
    if not _make_clip(src, "libx265"):
        pytest.skip("this ffmpeg build has no libx265")
    c, h = _client(flask_app)
    vid = _upload(c, h, src, "IMG_0001.MOV")
    j = _wait(c, c.post("/api/video/preview", headers=h, json={"video_id": vid}))
    assert j["ok"] and j["ready"], j
    r = c.get(f"/api/video/stream/{vid}?v=preview")
    assert r.status_code == 200 and r.mimetype == "video/mp4"
    # Second request is instant — preview already exists
    assert c.post("/api/video/preview", headers=h, json={"video_id": vid}).get_json() == {"ok": True, "ready": True}
