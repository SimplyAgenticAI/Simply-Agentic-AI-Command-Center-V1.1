"""V19.4: /health's last-error note says which route and app.py line failed.
(File must sort after test_client_crud.)"""
import json
import app as app_module


def test_api_error_note_keeps_route_and_line():
    with app_module.app.test_request_context("/api/usage/messages", method="GET"):
        try:
            app_module._normalize_plan_key(123)          # AttributeError raised inside app.py
        except AttributeError as e:
            app_module._handle_exception(e)
    rec = json.loads((app_module.DATA / "diag_last.json").read_text(encoding="utf-8"))["api_error"]
    assert rec["where"].startswith("GET /api/usage/messages at line ")
    assert rec["where"].endswith("in _normalize_plan_key")
    assert "AttributeError" in rec["detail"]
