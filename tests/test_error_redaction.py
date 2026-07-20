"""Regression tests for secret redaction in the error log (V8.1).

The old redactor only ran on the JSON body and only recursed into dicts:
  - request.args was copied verbatim, so the reset link's ?t=<token> landed
    in the admin-viewable error log in cleartext on any error during reset
  - a secret nested inside a list of dicts passed through untouched
"""
import app as app_module

r = app_module._redact_sensitive


def test_reset_token_query_arg_is_redacted():
    assert r({"u": "alice", "t": "LIVE-RESET-TOKEN"})["t"] == "***redacted***"


def test_plain_t_prefixed_key_is_not_over_redacted():
    # We match "t" exactly, not "contains t" — ordinary keys survive.
    out = r({"title": "hi", "text": "body", "count": 3})
    assert out == {"title": "hi", "text": "body", "count": 3}


def test_secret_in_list_of_dicts_is_redacted():
    out = r({"items": [{"api_key": "sk-secret"}, {"name": "ok"}]})
    assert out["items"][0]["api_key"] == "***redacted***"
    assert out["items"][1]["name"] == "ok"


def test_nested_dict_secret_is_redacted():
    out = r({"settings": {"openai_key": "sk-yy", "tooltip": "medium"}})
    assert out["settings"]["openai_key"] == "***redacted***"
    assert out["settings"]["tooltip"] == "medium"


def test_common_secret_keys_are_redacted():
    for key in ("password", "access_token", "refresh_token", "api_key", "cvv", "ssn"):
        assert r({key: "x"})[key] == "***redacted***"


def test_long_strings_are_truncated():
    out = r({"blob": "A" * 600})
    assert out["blob"].endswith("…") and len(out["blob"]) == 501


def test_deeply_nested_structure_terminates():
    # A pathological structure must not recurse without bound.
    d = cur = {}
    for _ in range(30):
        cur["x"] = {}
        cur = cur["x"]
    assert r(d) is not None  # returns without RecursionError


def test_capture_error_redacts_reset_token_arg(client):
    """End-to-end: force an error on a request carrying ?t=<token> and confirm
    the persisted log entry does not contain the token."""
    import json

    marker = "TOKEN-THAT-MUST-NOT-LEAK-123"

    with app_module.app.test_request_context(f"/reset/confirm?u=alice&t={marker}"):
        try:
            raise RuntimeError("kaboom")
        except RuntimeError as e:
            app_module._capture_error(e, context="redaction-test")

    log_path = app_module._error_log_path()
    body = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert marker not in body, "reset token leaked into the error log"
    # ...and the arg key is present but redacted, proving the path ran.
    entries = json.loads(body) if body else []
    matching = [e for e in entries if e.get("context") == "redaction-test"]
    assert matching and matching[0].get("args", {}).get("t") == "***redacted***"
