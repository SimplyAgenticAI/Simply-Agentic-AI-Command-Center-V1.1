"""Tests for the admin economics dashboard + tool-loop usage instrumentation (V8.8).

The tool loops (call_llm_with_tools and the streaming endpoint) call .create()
directly and previously logged no token usage — so the cost multiplier (N calls
per user message) was invisible and any margin readout was falsely optimistic.
Now every round logs, and /admin/economics reports real cost/message + per-plan
margin from the aggregated logs.
"""
import json

import app as app_module


def _isolated_admin(monkeypatch, tmp_path):
    """A client whose economics view reads ONLY tmp_path (isolated from the
    shared test data dir), with auth stubbed so moving the dirs is safe.
    Returns (client, logs_dir, data_dir)."""
    logs = tmp_path / "logs"; data = tmp_path / "data"
    logs.mkdir(); data.mkdir()
    monkeypatch.setattr(app_module, "LOGS_DIR", logs)
    monkeypatch.setattr(app_module, "DATA_DIR", str(data))
    monkeypatch.setattr(app_module, "_is_admin_user", lambda u: True)
    monkeypatch.setattr(app_module, "current_user",
                        lambda: {"username": "root", "is_admin": True})
    app_module.app.config.update(TESTING=True)
    c = app_module.app.test_client()
    with c.session_transaction() as s:
        s["user"] = "root"
    return c, logs, data


def _seed(logs, data, month, chat_cost, msgs, img_cost=0.0, imgs=0):
    ts = month + "-15T10:00:00Z"
    recs = [{"ts": ts, "model": "gpt-4o-mini", "input_tokens": 0, "output_tokens": 0,
             "total_tokens": 0, "kind": "chat", "cost_usd": chat_cost}]
    if img_cost:
        recs.append({"ts": ts, "model": "gpt-image-1", "kind": "image", "cost_usd": img_cost,
                     "input_tokens": 0, "output_tokens": 0})
    (logs / "usage_seeduser.json").write_text(json.dumps(recs))
    (data / "msg_usage_seeduser.json").write_text(
        json.dumps({"month": month, "count": msgs, "image_count": imgs}))


def test_dashboard_requires_admin(client):
    # A fresh non-admin session (no user) is redirected to login.
    resp = client.get("/admin/economics")
    assert resp.status_code in (302, 303)


def test_dashboard_computes_real_cost_per_message(monkeypatch, tmp_path):
    month = app_module._utcnow().strftime("%Y-%m")
    c, logs, data = _isolated_admin(monkeypatch, tmp_path)
    _seed(logs, data, month, chat_cost=8.00, msgs=1000, img_cost=1.40, imgs=20)
    resp = c.get("/admin/economics")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # $8.00 / 1000 msgs = $0.0080; $1.40 / 20 imgs = $0.0700
    assert "$0.0080" in body
    assert "$0.0700" in body
    assert "Founder" in body and "Teams" in body


def test_dashboard_falls_back_to_estimate_with_no_data(monkeypatch, tmp_path):
    # Empty logs/data dirs → estimate banner + (est) markers. Stub auth so moving
    # the data dirs (which orphans the session user) doesn't cause a redirect.
    monkeypatch.setattr(app_module, "_is_admin_user", lambda u: True)
    monkeypatch.setattr(app_module, "current_user",
                        lambda: {"username": "root", "is_admin": True})
    (tmp_path / "empty_logs").mkdir()
    (tmp_path / "empty_data").mkdir()
    monkeypatch.setattr(app_module, "LOGS_DIR", tmp_path / "empty_logs")
    monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path / "empty_data"))
    c = app_module.app.test_client()
    with c.session_transaction() as s:
        s["user"] = "root"
    resp = c.get("/admin/economics")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "(est)" in body
    assert "No usage recorded" in body


def test_call_llm_with_tools_logs_usage(monkeypatch):
    """Instrumentation: a tool-loop round with usage present must be logged."""
    import types
    logged = []
    monkeypatch.setattr(app_module, "_log_token_usage",
                        lambda *a, **k: logged.append((a, k)))

    class _Resp:
        def __init__(self):
            self.usage = types.SimpleNamespace(prompt_tokens=1200, completion_tokens=300)
            self.choices = [types.SimpleNamespace(
                finish_reason="stop",
                message=types.SimpleNamespace(content="hi", tool_calls=None))]

    class _OAI:
        def __init__(self):
            self.chat = types.SimpleNamespace(
                completions=types.SimpleNamespace(create=lambda **kw: _Resp()))

    monkeypatch.setattr(app_module, "get_openai_client", lambda: _OAI())
    text, log = app_module.call_llm_with_tools("sys", [{"role": "user", "content": "hi"}],
                                               username="u1", teammate="Ava")
    assert text == "hi"
    assert logged, "tool-loop round did not log token usage"
    # kind='chat' and the token counts were passed through
    a, k = logged[0]
    assert k.get("kind") == "chat"
    assert a[2] == 1200 and a[3] == 300
