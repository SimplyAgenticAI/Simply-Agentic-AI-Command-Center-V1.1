"""Clip Studio (V9.7) end-to-end on real media. Whisper/GPT are stubbed;
ffmpeg renders for real (bundled imageio-ffmpeg)."""
import io
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

import pytest

import app as app_module

FAKE_WORDS = [  # source-time words; "um" is a filler, silence 3–6s
    {"w": "Hello", "s": 0.3, "e": 0.7}, {"w": "um", "s": 0.8, "e": 1.1}, {"w": "this", "s": 1.2, "e": 1.5},
    {"w": "is", "s": 1.6, "e": 1.8}, {"w": "a", "s": 1.9, "e": 2.0}, {"w": "test.", "s": 2.1, "e": 2.6},
    {"w": "Second", "s": 6.3, "e": 6.8}, {"w": "part", "s": 6.9, "e": 7.3}, {"w": "here.", "s": 7.4, "e": 7.9},
]


@pytest.fixture()
def studio(flask_app, monkeypatch):
    monkeypatch.setattr(app_module, "_vc_transcribe", lambda user, media, wd: [
        {"w": w["w"], "s": w["s"], "e": w["e"]} for w in FAKE_WORDS])
    monkeypatch.setattr(app_module, "_ve_source_transcript", lambda user, vid: list(FAKE_WORDS))
    monkeypatch.setattr(app_module, "_vc_pick_moments", lambda user, words, dur, n: [
        {"title": "Best bit", "hook": "You need this", "start": 0.2, "end": 2.8, "score": 88, "reason": "hook"},
        {"title": "Second bit", "hook": "Wait for it", "start": 6.0, "end": 8.5, "score": 70, "reason": "payoff"}])
    tmp = Path(tempfile.mkdtemp())
    src = tmp / "talk.mp4"
    r = subprocess.run([app_module._ffmpeg_bin(), "-y",
                        "-f", "lavfi", "-i", "testsrc=size=640x360:rate=24:duration=10",
                        "-f", "lavfi", "-i", "aevalsrc='if(between(t,3,6),0,0.5*sin(2*PI*440*t))':d=10",
                        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", str(src)],
                       capture_output=True, timeout=120)
    assert r.returncode == 0, r.stderr[-400:]
    uname = "cliptester"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    with c.session_transaction() as s:
        s["user"] = uname
    blob = src.read_bytes()
    uid = "ve_1700000001_cs123456"
    c.post("/api/video/upload_chunk", headers=h, content_type="multipart/form-data",
           data={"upload_id": uid, "chunk_index": "0", "total_chunks": "1", "filename": "talk.mp4",
                 "chunk": (io.BytesIO(blob), "chunk_0")})
    vid = c.post("/api/video/upload", headers=h, json={"upload_id": uid, "filename": "talk.mp4"}).get_json()["video_id"]
    return c, h, vid, uname


def _wait_clip(c, cid, timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        clip = next(x for x in c.get("/api/vclips").get_json()["clips"] if x["id"] == cid)
        if clip["status"] != "rendering":
            return clip
        time.sleep(0.3)
    raise AssertionError("render timed out")


def test_clip_lifecycle(studio):
    c, h, vid, uname = studio
    d = c.post("/api/vclips", headers=h, json={"video_id": vid, "start": 0, "end": 8.5, "title": "My first clip"}).get_json()
    assert d["ok"], d
    cid = d["clip"]["id"]
    clip = _wait_clip(c, cid)
    assert clip["status"] == "ready", clip
    assert (clip["width"], clip["height"]) == (640, 360)
    assert c.get(f"/api/vclips/{cid}/thumb").status_code == 200
    r = c.get(f"/api/vclips/{cid}/file", headers={"Range": "bytes=0-99"})
    assert r.status_code == 206

    # Rename only → no re-render
    d = c.post(f"/api/vclips/{cid}", headers=h, json={"title": "Renamed"}).get_json()
    assert d["ok"] and not d["rerender"] and d["clip"]["title"] == "Renamed"

    # The works: vertical, captions, hook, silence + filler removal, a deleted word, brand logo
    logo = Path(tempfile.mkdtemp()) / "logo.png"
    subprocess.run([app_module._ffmpeg_bin(), "-y", "-f", "lavfi", "-i", "color=c=red:s=200x80", "-frames:v", "1", str(logo)],
                   capture_output=True, timeout=60)
    assert c.post("/api/vclips/brand", headers=h, content_type="multipart/form-data",
                  data={"logo": (io.BytesIO(logo.read_bytes()), "logo.png")}).get_json()["brand"]["logo"]
    d = c.post(f"/api/vclips/{cid}", headers=h, json={
        "aspect": "9:16", "captions": {"on": True, "style": "pop"}, "hook": "Watch this",
        "remove_silence": True, "remove_fillers": True, "deleted": [3], "brand": True}).get_json()
    assert d["ok"] and d["rerender"], d
    clip = _wait_clip(c, cid)
    assert clip["status"] == "ready", clip
    assert (clip["width"], clip["height"]) == (720, 1280)
    assert clip["duration"] < 6.5, clip["duration"]  # ~3s of silence + filler + a word removed from 8.5s

    # Transcript for text editing
    t = c.get(f"/api/vclips/{cid}/transcript").get_json()
    assert [w["w"] for w in t["words"]][:2] == ["Hello", "um"] and t["deleted"] == [3]

    # Re-trim within the master
    d = c.post(f"/api/vclips/{cid}", headers=h, json={"start": 0, "end": 2.7}).get_json()
    assert d["rerender"]
    assert _wait_clip(c, cid)["status"] == "ready"

    # Duplicate, zip, public link, planner hand-off, delete
    dup = c.post(f"/api/vclips/{cid}/duplicate", headers=h).get_json()["clip"]
    z = zipfile.ZipFile(io.BytesIO(c.get(f"/api/vclips/zip?ids={cid},{dup['id']}").data))
    assert len(z.namelist()) == 2
    c.post(f"/api/vclips/{cid}", headers=h, json={"social": {"caption": "Big news", "hashtags": ["#growth", "smallbiz"]}})
    post = c.post(f"/api/vclips/{cid}/to_planner", headers=h, json={"platforms": ["tiktok"]}).get_json()["post"]
    assert post["caption"].startswith("Big news") and "#growth #smallbiz" in post["caption"]
    path = post["media_url"].split("://", 1)[1].split("/", 1)[1]
    anon = c.application.test_client()
    assert anon.get("/" + path).status_code == 200            # signed link works logged-out
    assert anon.get("/vclip/forged.mp4").status_code == 404     # forged token doesn't
    assert c.delete(f"/api/vclips/{dup['id']}", headers=h).get_json()["ok"]
    assert all(x["id"] != dup["id"] for x in c.get("/api/vclips").get_json()["clips"])


def test_make_shorts(studio):
    c, h, vid, uname = studio
    d = c.post("/api/vclips/make_shorts", headers=h, json={"video_id": vid}).get_json()
    assert d["ok"] and d["job_id"]
    for _ in range(600):
        j = c.get(f"/api/video/job/{d['job_id']}").get_json()
        if j.get("status") != "working":
            break
        time.sleep(0.3)
    assert j["ok"] and len(j["clip_ids"]) == 2, j
    clips = {x["id"]: x for x in c.get("/api/vclips").get_json()["clips"]}
    for cid in j["clip_ids"]:
        x = clips[cid]
        assert x["status"] == "ready", x
        assert x["aspect"] == "9:16" and x["captions"]["on"] and x["hook"] and x["score"] > 0


def test_other_user_cannot_touch_clips(studio, flask_app):
    c, h, vid, uname = studio
    cid = c.post("/api/vclips", headers=h, json={"video_id": vid, "start": 0, "end": 2}).get_json()["clip"]["id"]
    _wait_clip(c, cid)
    data = app_module.load_users()
    data["users"]["intruder"] = {"username": "intruder", "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c2 = flask_app.test_client()
    h2 = {"X-CSRF-Token": c2.get("/api/csrf_token").get_json()["csrf_token"]}
    with c2.session_transaction() as s:
        s["user"] = "intruder"
    assert c2.get(f"/api/vclips/{cid}/file").status_code == 404
    assert c2.post(f"/api/vclips/{cid}", headers=h2, json={"title": "x"}).status_code == 404


def test_many_cuts_never_drop_the_ending():
    cuts = [(i + 0.2, i + 0.6) for i in range(0, 200)]  # 200 tiny silences in a 200s clip
    segs = app_module._vc_keep_segments(0.0, 200.0, cuts)
    assert len(segs) <= app_module._VC_MAX_SEGS
    assert abs(segs[-1][1] - 200.0) < 1e-6 and segs[0][0] == 0.0  # start and END both kept


def test_reslice_keeps_cuts_and_spelling_fixes():
    c = {"words": [{"w": "a", "s": 5.0, "e": 5.2}, {"w": "Jon", "s": 5.3, "e": 5.6}, {"w": "um", "s": 5.7, "e": 5.9}],
         "deleted": [2]}
    c["words"][1]["w"] = "John"  # user's spelling fix
    wider = [{"w": "intro", "s": 1.0, "e": 1.4}, {"w": "a", "s": 5.0, "e": 5.2},
             {"w": "Jon", "s": 5.3, "e": 5.6}, {"w": "um", "s": 5.7, "e": 5.9}]
    app_module._vc_reslice_words(c, wider)
    assert c["deleted"] == [3]                 # still the "um", not whatever shifted into index 2
    assert c["words"][2]["w"] == "John"        # fix survived


def test_orphaned_render_is_restarted(studio):
    c, h, vid, uname = studio
    cid = c.post("/api/vclips", headers=h, json={"video_id": vid, "start": 0, "end": 2}).get_json()["clip"]["id"]
    assert _wait_clip(c, cid)["status"] == "ready"
    # Simulate a worker restart mid-render: status stuck on "rendering", no live thread
    app_module._vc_update(uname, cid, lambda x: x.update({"status": "rendering"}))
    with app_module._VC_ACTIVE_LOCK:
        app_module._VC_ACTIVE.discard((uname, cid))
    assert _wait_clip(c, cid)["status"] == "ready"   # list endpoint revived it


def test_bad_numbers_are_400_not_500(studio):
    c, h, vid, uname = studio
    cid = c.post("/api/vclips", headers=h, json={"video_id": vid, "start": 0, "end": 2}).get_json()["clip"]["id"]
    _wait_clip(c, cid)
    assert c.post(f"/api/vclips/{cid}", headers=h, json={"start": "abc"}).status_code == 400
    assert c.post(f"/api/vclips/{cid}", headers=h, json={"word_edits": {"x": "y"}}).status_code == 400
