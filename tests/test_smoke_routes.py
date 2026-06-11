"""Smoke tests: every parameter-free GET route should respond without a 500.

This is a regression safety net, not a correctness suite — a 4xx is fine
(means auth/validation worked), a 5xx means the route crashed.
"""
import pytest

import app as app_module

# Routes that legitimately make outbound network/API calls or have side
# effects we don't want in a smoke test (sending email, OAuth redirects to
# real providers that may error differently without configured credentials).
SKIP_PATHS = {
    "/api/tts/test",        # calls OpenAI TTS API
    "/extension/download",  # serves a packaged extension zip — large/slow
}


def _get_no_param_routes():
    rules = app_module.app.url_map.iter_rules()
    paths = set()
    for r in rules:
        if "GET" not in r.methods:
            continue
        if r.arguments:
            continue
        path = str(r)
        if path.startswith("/static"):
            continue
        if path in SKIP_PATHS:
            continue
        paths.add(path)
    return sorted(paths)


ROUTES = _get_no_param_routes()


@pytest.mark.parametrize("path", ROUTES)
def test_anonymous_get_does_not_500(client, path):
    resp = client.get(path)
    assert resp.status_code < 500, f"{path} returned {resp.status_code}"


@pytest.mark.parametrize("path", ROUTES)
def test_authenticated_get_does_not_500(auth_client, path):
    resp = auth_client.get(path)
    assert resp.status_code < 500, f"{path} returned {resp.status_code}"


def test_route_count_sanity():
    # Guards against the route map silently shrinking (e.g. an import-time
    # crash that registers far fewer routes than expected).
    assert len(ROUTES) > 100
