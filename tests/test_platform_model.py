"""Platform-key model routing (V10.0) and which model a user's chats actually
run on (V11.3): strong model under 70% of the plan's monthly chat budget,
cheap after; the Settings default model is honoured with the matching key."""
import app as app_module


def test_budgets_are_positive_and_teams_split_per_seat():
    solo = app_module._plan_chat_budget_usd("solo")
    assert 4.0 < solo < 5.0                       # 47*0.121 - 0.30 - 15*0.07
    teams = app_module._plan_chat_budget_usd("teams")
    assert abs(teams * 3 - (127 * 0.121 - 0.30 - 40 * 0.07)) < 1e-6


def test_switches_to_cheap_model_near_budget(monkeypatch):
    monkeypatch.setattr(app_module, "PLATFORM_CHAT_MODEL", "gpt-4o")
    monkeypatch.setattr(app_module, "_get_user_plan", lambda u: "solo")
    budget = app_module._plan_chat_budget_usd("solo")
    monkeypatch.setattr(app_module, "_month_chat_spend_usd", lambda u: budget * 0.2)
    assert app_module._platform_chat_model("x") == "gpt-4o"
    monkeypatch.setattr(app_module, "_month_chat_spend_usd", lambda u: budget * 0.71)
    assert app_module._platform_chat_model("x") == "gpt-4o-mini"


def test_kill_switch(monkeypatch):
    monkeypatch.setattr(app_module, "PLATFORM_CHAT_MODEL", "gpt-4o-mini")
    assert app_module._platform_chat_model("x") == "gpt-4o-mini"


def test_month_spend_counts_only_this_month_chat(monkeypatch, tmp_path):
    import json
    month = app_module._utcnow().strftime("%Y-%m")
    log = tmp_path / "u.json"
    log.write_text(json.dumps([
        {"ts": month + "-02T10:00:00Z", "kind": "chat", "cost_usd": 0.5},
        {"ts": month + "-03T10:00:00Z", "kind": "image", "cost_usd": 9},
        {"ts": "2001-01-01T00:00:00Z", "kind": "chat", "cost_usd": 9}]), encoding="utf-8")
    monkeypatch.setattr(app_module, "_usage_log_path", lambda u: log)
    app_module._MONTH_SPEND_CACHE.pop("spendtester", None)
    assert abs(app_module._month_chat_spend_usd("spendtester") - 0.5) < 1e-9


def _user(model="", openai="", claude=""):
    enc = app_module._encrypt_field
    s = {"global_default_model": model}
    if openai:
        s["openai_key"] = enc(openai)
    if claude:
        s["claude_key"] = enc(claude)
    return {"username": "m", "settings": s}


def test_settings_default_model_is_honoured_with_matching_key(monkeypatch):
    monkeypatch.setattr(app_module, "_platform_chat_model", lambda u: "gpt-4o")
    eff = app_module._effective_chat_model
    assert eff(_user("claude-sonnet-5", claude="sk-ant-" + "x" * 30)) == "claude-sonnet-5"
    assert eff(_user("claude-sonnet-5", openai="sk-" + "x" * 30)) == "gpt-4o"          # no Claude key
    assert eff(_user("claude-sonnet-5")) == "gpt-4o"                                    # included model
    assert eff(_user("gpt-4o-mini", openai="sk-" + "x" * 30)) == "gpt-4o-mini"
    # a teammate's own model still wins over the Settings default
    assert eff(_user("gpt-4o", claude="sk-ant-" + "x" * 30), {"preferred_model": "claude-opus-5"}) == "claude-opus-5"
    assert app_module._model_label("claude-sonnet-5") == "Claude Sonnet 5"
