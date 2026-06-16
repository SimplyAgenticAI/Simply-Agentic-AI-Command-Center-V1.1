"""Integration tests for the streaming tool loop in /api/followup/stream.

Drives the real handler with a mocked OpenAI client so the actual tool-calling
loop is exercised: auto-execute, the confirm-card flow, and the prompt-injection
escalation (read_url -> crm_add becomes confirm, not a silent write).
"""
import json
import types
import pytest
import app as app_module

_TUSER = "smoketest"      # shared test user (created by other tests too)
_TPASS = "TestPass123!"


@pytest.fixture(scope="module")
def tclient():
    # Register (creates the user if absent) THEN log in, so the client is
    # authenticated whether or not the user already exists in this session.
    # SAAI_TOOLS_ENABLED is forced on in _setup so admin status doesn't matter.
    with app_module.app.test_client() as c:
        c.post("/register", data={
            "username": _TUSER, "email": "", "password": _TPASS,
            "password2": _TPASS, "tos_accepted": "on",
        }, follow_redirects=True)
        c.post("/login", data={"username": _TUSER, "password": _TPASS}, follow_redirects=True)
        c.csrf_token = c.get("/api/csrf_token").get_json().get("csrf_token", "")
        yield c


# ── Fake OpenAI client returning scripted chat-completion responses ──────────
def _msg(content="", tool_calls=None):
    return types.SimpleNamespace(content=content, tool_calls=tool_calls)


def _toolcall(cid, name, args):
    return types.SimpleNamespace(
        id=cid, type="function",
        function=types.SimpleNamespace(name=name, arguments=json.dumps(args)))


def _resp(message):
    return types.SimpleNamespace(choices=[types.SimpleNamespace(message=message)])


class _FakeOAI:
    script = []
    idx = [0]

    def __init__(self, *a, **k):
        self.chat = types.SimpleNamespace(
            completions=types.SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        i = _FakeOAI.idx[0]
        r = _FakeOAI.script[min(i, len(_FakeOAI.script) - 1)]
        _FakeOAI.idx[0] = i + 1
        return r


def _setup(monkeypatch, script):
    _FakeOAI.script = script
    _FakeOAI.idx = [0]
    monkeypatch.setattr(app_module, "OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(app_module, "OpenAI", _FakeOAI)
    monkeypatch.setattr(app_module, "SAAI_TOOLS_ENABLED", True)  # tools on regardless of admin
    monkeypatch.setattr(app_module, "_check_rate_limit", lambda *a, **k: None)
    monkeypatch.setattr(app_module, "_check_msg_limit", lambda *a, **k: (True, 0, 9999, 0, 9999, True))


def _post(client, name, message):
    # IMPORTANT: consume the body so the streaming generator actually runs
    # (the test client is lazy — without this, save_thread never fires).
    r = client.post("/api/followup/stream",
                    json={"name": name, "message": message},
                    headers={"X-CSRF-Token": getattr(client, "csrf_token", "")})
    return _sse_text(r.get_data(as_text=True))


def _sse_text(body):
    """Reconstruct the streamed reply by concatenating all SSE token fields."""
    out = []
    for line in body.split("\n"):
        if line.startswith("data:"):
            try:
                ev = json.loads(line[5:].strip())
            except Exception:
                continue
            if isinstance(ev, dict) and "token" in ev:
                out.append(ev["token"])
    return "".join(out)


def test_auto_tool_executes_and_streams(monkeypatch, tclient):
    _setup(monkeypatch, [
        _resp(_msg("", [_toolcall("t1", "crm_add_client",
                                  {"name": "Jamie Cole", "email": "jamie@x.com"})])),
        _resp(_msg("Added Jamie to your CRM. Anything else?", None)),
    ])
    text = _post(tclient, "Alex", "add Jamie Cole to my CRM")
    assert "as a Lead" in text                # tool-result summary streamed
    assert "Anything else?" in text           # full final answer streamed
    crm = app_module._crm_load(_TUSER)
    assert any(c.get("name") == "Jamie Cole" for c in (crm.get("clients") or {}).values())


def test_send_email_emits_confirm_card(monkeypatch, tclient):
    _setup(monkeypatch, [
        _resp(_msg("", [_toolcall("t1", "send_email",
                                  {"to": "john@x.com", "subject": "Hi", "body": "Proposal ready."})])),
    ])
    _post(tclient, "Willow", "email john@x.com that the proposal is ready")  # consumes body -> runs generator
    thread = app_module.load_thread("Willow", _TUSER)
    last = thread[-1]["content"] if thread else ""
    assert "[confirm_action]" in last
    assert "send_email" in last


def test_injection_escalation_blocks_silent_crm_write(monkeypatch, tclient):
    # Read a URL (untrusted) then attempt crm_add — must escalate to a confirm
    # card instead of silently adding the injected contact.
    _setup(monkeypatch, [
        _resp(_msg("", [_toolcall("t1", "read_url", {"url": "http://example.com"})])),
        _resp(_msg("", [_toolcall("t2", "crm_add_client", {"name": "Evil Injected"})])),
    ])
    monkeypatch.setattr(app_module, "_fetch_url_content", lambda url, max_chars=8000: ("hello world", ""))
    _post(tclient, "Ava", "read example.com then add the contact it mentions")  # consumes body -> runs generator
    thread = app_module.load_thread("Ava", _TUSER)
    last = thread[-1]["content"] if thread else ""
    assert "[confirm_action]" in last  # crm_add escalated to confirm
    crm = app_module._crm_load(_TUSER)
    assert not any(c.get("name") == "Evil Injected" for c in (crm.get("clients") or {}).values())
