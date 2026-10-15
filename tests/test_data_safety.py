"""Data-safety sweep (V12.0): customer-data stores go through the shared
locked, atomic JSON helpers; saving a visual works again; seats still get
created on a fresh install."""
import os
import subprocess
import sys
import tempfile

import pytest

import app as app_module


@pytest.fixture()
def user(flask_app):
    uname = "safetyuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    return c, {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}, uname


def test_saving_a_visual_works_again(user):
    c, h, uname = user
    r = c.post("/api/visuals/save", headers=h, json={"html": "<div>hi</div>", "prompt": "p"})
    assert r.status_code == 200 and r.get_json()["ok"]                     # used to 500 every time
    vid = r.get_json()["id"]
    assert [v["id"] for v in c.get("/api/visuals").get_json()["visuals"]] == [vid]
    assert c.delete(f"/api/visuals/{vid}", headers=h).get_json()["ok"]
    assert c.get("/api/visuals").get_json()["visuals"] == []


def test_stores_round_trip_through_safe_helpers(user):
    c, h, uname = user
    app_module._save_cal_tasks(uname, [{"id": "t1", "title": "Call Bob"}])
    assert app_module._load_cal_tasks(uname) == [{"id": "t1", "title": "Call Bob"}]
    assert not app_module._cal_tasks_path(uname).with_suffix(".tmp").exists()   # atomic write left no temp file
    app_module._save_notes(uname, [{"title": "n"}])
    assert app_module._load_notes(uname) == [{"title": "n"}]
    app_module._save_operator_profile(uname, {"business": "Roofing"})
    assert app_module._load_operator_profile(uname)["business"] == "Roofing"
    app_module._save_sp_conns(uname, {"linkedin": {"access_token": "x"}})
    assert app_module._load_sp_conns(uname)["linkedin"]["access_token"] == "x"
    # a corrupt file reads as empty instead of crashing
    app_module._cal_tasks_path(uname).write_text("{not json", encoding="utf-8")
    assert app_module._load_cal_tasks(uname) == []


def test_fresh_install_still_creates_seats():
    d = tempfile.mkdtemp(prefix="freshseats_")
    code = ("import app, json; s = app._load_seats(); "
            "print('SEATS', len((s or {}).get('seats') or {}))")
    env = dict(os.environ, DATA_DIR=d, APP_SECRET="x", PYTHONIOENCODING="utf-8")
    out = subprocess.run([sys.executable, "-c", code], cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    line = [l for l in out.stdout.splitlines() if l.startswith("SEATS")]
    assert line and int(line[0].split()[1]) > 0, (out.stdout[-500:], out.stderr[-500:])
