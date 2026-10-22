"""Bulk select (V12.6): Media Library images/videos can be deleted one or many
at a time (owner-only, files removed from disk), and bulk-deleting pipeline
contacts also drops their pending teammate drafts.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import pytest

import app as app_module


def _login(flask_app, uname):
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    c = flask_app.test_client()
    with c.session_transaction() as s:
        s["user"] = uname
    h = {"X-CSRF-Token": c.get("/api/csrf_token").get_json()["csrf_token"]}
    return c, h


@pytest.fixture()
def bulk(flask_app):
    c, h = _login(flask_app, "bulkuser")
    yield c, h, "bulkuser"
    data = app_module.load_users()
    for n in ("bulkuser", "otheruser"):
        (data.get("users") or {}).pop(n, None)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def _add_image(owner, name):
    fid = app_module.uuid.uuid4().hex
    sub = app_module.UPLOADS_DIR / "20300101"
    sub.mkdir(parents=True, exist_ok=True)
    fp = sub / f"{fid}_{name}"
    fp.write_bytes(b"\x89PNG fake")
    app_module.add_upload_record(fid, {"id": fid, "filename": name, "relpath": f"20300101/{fid}_{name}",
                                       "mimetype": "image/png", "owner": owner, "uploaded_at": app_module.now_iso()})
    return fid, fp


def test_delete_many_own_images_removes_records_and_files(bulk):
    c, h, uname = bulk
    a, fa = _add_image(uname, "a.png")
    b, fb = _add_image(uname, "b.png")
    keep, fk = _add_image(uname, "keep.png")
    listed = {i["id"]: i for i in c.get("/api/images").get_json()["images"]}
    assert listed[a]["can_delete"]
    r = c.post("/api/images/delete", headers=h, json={"ids": [a, b]}).get_json()
    assert r["ok"] and r["deleted"] == 2
    ids = {i["id"] for i in c.get("/api/images").get_json()["images"]}
    assert a not in ids and b not in ids and keep in ids
    assert not fa.exists() and not fb.exists() and fk.exists()


def test_cannot_delete_someone_elses_or_shared_images(bulk, flask_app):
    c, h, uname = bulk
    theirs, ft = _add_image("otheruser", "theirs.png")
    shared, fs = _add_image("", "shared.png")
    r = c.post("/api/images/delete", headers=h, json={"ids": [theirs, shared]}).get_json()
    assert r["deleted"] == 0 and r["skipped"] == 2
    assert ft.exists() and fs.exists()
    shared_row = next(i for i in c.get("/api/images").get_json()["images"] if i["id"] == shared)
    assert shared_row["can_delete"] is False


def test_image_delete_never_touches_files_outside_uploads(bulk):
    c, h, uname = bulk
    outside = app_module.DATA / "do_not_delete.txt"
    outside.write_text("x")
    fid = app_module.uuid.uuid4().hex
    app_module.add_upload_record(fid, {"id": fid, "filename": "x.png", "relpath": "../do_not_delete.txt",
                                       "mimetype": "image/png", "owner": uname})
    assert c.post("/api/images/delete", headers=h, json={"ids": [fid]}).get_json()["ok"]
    assert outside.exists()


def test_image_delete_requires_csrf_and_ids(bulk):
    c, h, uname = bulk
    a, fa = _add_image(uname, "c.png")
    assert c.post("/api/images/delete", json={"ids": [a]}).status_code in (400, 403)
    assert fa.exists()
    assert c.post("/api/images/delete", headers=h, json={"ids": []}).status_code == 400


def test_bulk_delete_visuals(bulk):
    c, h, uname = bulk
    for i in range(3):
        assert c.post("/api/visuals/save", headers=h, json={"html": f"<p>{i}</p>", "prompt": f"v{i}"}).get_json()["ok"]
    vis = c.get("/api/visuals").get_json()["visuals"]
    r = c.post("/api/visuals/delete", headers=h, json={"ids": [vis[0]["id"], vis[1]["id"]]}).get_json()
    assert r["ok"] and r["deleted"] == 2
    left = c.get("/api/visuals").get_json()["visuals"]
    assert [v["id"] for v in left] == [vis[2]["id"]]


def test_clearing_contacts_drops_their_pending_drafts(bulk):
    c, h, uname = bulk
    app_module._crm_save(uname, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    ids = [c.post("/api/crm/clients", headers=h, json={"name": f"Lead {i}"}).get_json()["client"]["id"] for i in range(3)]
    with app_module._AGENT_LOCK:
        d = app_module._agent_load(uname)
        d["approvals"] = [{"id": f"a{i}", "status": "pending", "client_id": cid} for i, cid in enumerate(ids)]
        app_module._agent_save(uname, d)
    r = c.post("/api/crm/clients/bulk", headers=h, json={"ids": ids[:2], "action": "delete"}).get_json()
    assert r["ok"] and r["changed"] == 2
    assert set(app_module._crm_load(uname)["clients"]) == {ids[2]}
    assert [a["client_id"] for a in app_module._agent_load(uname)["approvals"]] == [ids[2]]


def test_single_delete_drops_draft_and_stale_drafts_are_hidden(bulk):
    c, h, uname = bulk
    app_module._crm_save(uname, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    ids = [c.post("/api/crm/clients", headers=h, json={"name": f"S {i}"}).get_json()["client"]["id"] for i in range(2)]
    with app_module._AGENT_LOCK:
        d = app_module._agent_load(uname)
        d["approvals"] = [{"id": f"s{i}", "status": "pending", "client_id": cid} for i, cid in enumerate(ids)] + \
                         [{"id": "stale", "status": "pending", "client_id": "deleted-before-fix"}]
        app_module._agent_save(uname, d)
    assert c.delete(f"/api/crm/clients/{ids[0]}", headers=h).get_json()["ok"]
    stored = [a["client_id"] for a in app_module._agent_load(uname)["approvals"]]
    assert ids[0] not in stored and ids[1] in stored
    shown = [a["client_id"] for a in c.get("/api/agent").get_json()["approvals"]]
    assert shown == [ids[1]]  # the leftover draft for an already-gone contact is hidden


def test_bulk_move_stage(bulk):
    c, h, uname = bulk
    app_module._crm_save(uname, {"clients": {}, "pipeline": {"stages": app_module._default_pipeline_stages()}})
    ids = [c.post("/api/crm/clients", headers=h, json={"name": f"M {i}"}).get_json()["client"]["id"] for i in range(2)]
    stage = app_module._default_pipeline_stages()[-1]
    assert c.post("/api/crm/clients/bulk", headers=h, json={"ids": ids, "action": "stage", "value": stage}).get_json()["changed"] == 2
    assert all(cl["pipeline_stage"] == stage for cl in app_module._crm_load(uname)["clients"].values())


def test_bulk_rejects_non_list_ids(bulk):
    c, h, uname = bulk
    assert c.post("/api/crm/clients/bulk", headers=h, json={"ids": "abc", "action": "delete"}).status_code == 400
