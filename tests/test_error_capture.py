"""Regression tests for automatic error capture:
- _capture_error records the failing request's path/method.
- Sensitive fields in the request body are redacted (never logged in plaintext).
- The global exception handler returns a clean JSON error for /api/ routes.
"""
import json

import app as app_module


def _read_error_log():
    p = app_module._error_log_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def test_capture_error_redacts_secrets_and_records_context(flask_app):
    # Clear any existing log so we can find our entry deterministically.
    try:
        app_module._error_log_path().write_text("[]", encoding="utf-8")
    except Exception:
        pass

    with flask_app.test_request_context(
        "/api/test/boom",
        method="POST",
        json={"prompt": "hello", "password": "supersecret", "openai_key": "sk-123"},
    ):
        app_module._capture_error(ValueError("kaboom"), context="unit_test")

    log = _read_error_log()
    assert log, "expected at least one captured error"
    entry = log[0]
    assert entry["type"] == "ValueError"
    assert entry["message"] == "kaboom"
    assert entry["path"] == "/api/test/boom"
    assert entry["method"] == "POST"
    assert entry["context"] == "unit_test"
    body = entry.get("body") or {}
    # Non-sensitive field preserved; secrets redacted.
    assert body.get("prompt") == "hello"
    assert body.get("password") == "***redacted***"
    assert body.get("openai_key") == "***redacted***"


def test_global_handler_returns_json_for_api_routes(client):
    # Hitting a non-existent API route should yield a JSON error body, not HTML
    # (auth gate may answer 401 before the 404 handler — either way it's JSON).
    resp = client.get("/api/definitely/not/a/real/route")
    assert resp.status_code in (401, 404)
    assert resp.is_json
    assert resp.get_json().get("ok") is False
