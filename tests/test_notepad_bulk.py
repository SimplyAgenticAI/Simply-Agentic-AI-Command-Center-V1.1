"""V14.4: every note gets a stable id so the Notepad can tick and bulk-delete.
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import app as app_module


def test_notes_without_ids_get_stable_ids(flask_app):
    uname = "npbulkuser"
    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)
    app_module._invalidate_users_cache()
    try:
        app_module._save_notes(uname, [{"title": "old a", "content": ""}, {"title": "old b", "content": ""}, {"id": 7, "title": "has id"}])
        c = flask_app.test_client()
        with c.session_transaction() as s:
            s["user"] = uname
        notes = c.get("/api/notepad").get_json()["notes"]
        ids = [n["id"] for n in notes]
        assert len(set(ids)) == 3 and 7 in ids
        assert [n["id"] for n in c.get("/api/notepad").get_json()["notes"]] == ids   # stable across loads
    finally:
        data = app_module.load_users()
        (data.get("users") or {}).pop(uname, None)
        app_module.save_users(data)
        app_module._invalidate_users_cache()
