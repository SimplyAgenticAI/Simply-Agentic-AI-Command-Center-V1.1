"""REAL-session smoke sweep: every parameterless GET route, actually logged in.

The original smoke tests' sessions were never authenticated, so handlers 401'd
at the door and an entire class of launch-day 500s (e.g. the DATA_DIR-as-str
Path joins) went undetected. This sweep uses a genuine session and fails with
the full list of broken routes at once.
"""
import pytest

import app as app_module

_SKIP = {
    "/logout",            # would kill the session mid-sweep
    "/login",             # redirects when already authed — pointless here
}


@pytest.fixture()
def real_client(flask_app):
    with flask_app.test_client() as c:
        c.post("/register", data={
            "username": "smoketest", "email": "",
            "password": "TestPass123!", "password2": "TestPass123!",
            "tos_accepted": "on",
        }, follow_redirects=True)
        c.post("/login", data={"username": "smoketest", "password": "TestPass123!"},
               follow_redirects=True)
        # Sanity: the session must be real, or this whole sweep is theater.
        me = c.get("/api/me")
        assert me.status_code == 200 and (me.get_json() or {}).get("ok"), \
            "smoke sweep could not establish an authenticated session"
        yield c


def _get_routes():
    routes = set()
    for rule in app_module.app.url_map.iter_rules():
        if "GET" not in (rule.methods or set()):
            continue
        if rule.arguments:          # path params need real ids — out of scope
            continue
        r = str(rule.rule)
        if r.startswith("/static") or r in _SKIP:
            continue
        routes.add(r)
    return sorted(routes)


def test_every_parameterless_get_survives_a_real_session(real_client):
    failures = []
    for r in _get_routes():
        try:
            resp = real_client.get(r)
            if resp.status_code >= 500:
                failures.append(f"{r} -> {resp.status_code}")
        except Exception as e:
            failures.append(f"{r} -> EXCEPTION {type(e).__name__}: {e}")
    assert not failures, (
        f"{len(failures)} route(s) fail for a real authenticated session:\n"
        + "\n".join(failures)
    )
