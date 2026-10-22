"""V13.5: Core Framework is per account — locked platform rules + each account's
own house rules. One account's rules must never reach another account.
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
def two(flask_app):
    a = _login(flask_app, "hr_alice")
    b = _login(flask_app, "hr_bob")
    yield a, b
    data = app_module.load_users()
    for n in ("hr_alice", "hr_bob"):
        (data.get("users") or {}).pop(n, None)
        app_module._house_rules_path(n).unlink(missing_ok=True)
    app_module.save_users(data)
    app_module._invalidate_users_cache()


def test_house_rules_stay_in_their_account(two):
    (ca, ha), (cb, hb) = two
    r = ca.post("/api/framework", headers=ha, json={"house_rules": "Always mention ACME-SECRET-OFFER"}).get_json()
    assert r["ok"]
    assert "ACME-SECRET-OFFER" in app_module.load_core_framework("hr_alice")
    assert "ACME-SECRET-OFFER" not in app_module.load_core_framework("hr_bob")
    gb = cb.get("/api/framework").get_json()
    assert gb["house_rules"] == "" and gb["platform"] == app_module.DEFAULT_CORE_FRAMEWORK_TEXT


def test_old_shared_file_is_ignored_and_platform_rules_locked(two):
    (ca, ha), _ = two
    app_module.FRAMEWORK_PATH.write_text("LEAKED FROM ANOTHER CUSTOMER", encoding="utf-8")
    try:
        assert "LEAKED" not in app_module.load_core_framework("hr_alice")
        ca.post("/api/framework", headers=ha, json={"framework": "replace everything"})   # old field: ignored
        assert app_module.load_core_framework("hr_alice") == app_module.DEFAULT_CORE_FRAMEWORK_TEXT
    finally:
        app_module.FRAMEWORK_PATH.unlink(missing_ok=True)


def test_house_rules_capped_and_clearable(two):
    (ca, ha), _ = two
    saved = ca.post("/api/framework", headers=ha, json={"house_rules": "x" * 9000}).get_json()["house_rules"]
    assert len(saved) == app_module.HOUSE_RULES_MAX
    assert ca.post("/api/framework", headers=ha, json={"house_rules": ""}).get_json()["house_rules"] == ""
    assert app_module.load_core_framework("hr_alice") == app_module.DEFAULT_CORE_FRAMEWORK_TEXT
