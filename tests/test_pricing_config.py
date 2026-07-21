"""Tests for the 85%-margin pricing config (V8.10): caps, image quality default,
Teams shared pool, and the default-off tool-loop routing lever.
"""
import types

import app as app_module


# ── Caps hold ~85% at the measured cost ──────────────────────────────────────

def test_plans_hit_85_percent_at_measured_cost():
    cpm, cpi = 0.0117, 0.07  # measured $/msg, medium image $/img
    for key in ("founder", "solo", "teams"):
        price = app_module.PLANS[key]["price"]
        msgs  = app_module.MSG_LIMITS[key]
        imgs  = app_module.IMAGE_LIMITS[key]
        cost  = msgs * cpm + imgs * cpi + (0.029 * price + 0.30)
        margin = (price - cost) / price * 100
        assert margin >= 85.0, f"{key} margin {margin:.1f}% < 85%"


# ── Image quality default ────────────────────────────────────────────────────

def test_image_quality_defaults_to_medium():
    assert app_module._IMAGE_QUALITY_DEFAULT == "medium"
    assert app_module._pick_image_quality("make me a logo") == "medium"


def test_image_quality_low_for_drafts_high_on_request():
    assert app_module._pick_image_quality("quick draft of a flyer") == "low"
    assert app_module._pick_image_quality("a high quality hero image") == "high"


# ── Teams shared pool ────────────────────────────────────────────────────────

def _seed_usage(monkeypatch, per_user_counts):
    """Stub _get_msg_usage to return {count,image_count} per username."""
    def _fake(uname):
        c = per_user_counts.get(uname, 0)
        return {"month": "x", "count": c, "image_count": 0}
    monkeypatch.setattr(app_module, "_get_msg_usage", _fake)


def test_solo_user_uses_own_counter(monkeypatch):
    monkeypatch.setattr(app_module, "_user_has_own_key", lambda u: False)
    monkeypatch.setattr(app_module, "_get_team_owner", lambda u: None)
    monkeypatch.setattr(app_module, "_get_team_members", lambda u: [])
    monkeypatch.setattr(app_module, "_get_user_plan", lambda u: "solo")
    _seed_usage(monkeypatch, {"alice": 340})
    allowed, used, limit, *_ = app_module._check_msg_limit("alice", "solo")
    assert limit == app_module.MSG_LIMITS["solo"] == 350
    assert used == 340 and allowed is True


def test_team_pools_usage_against_owner_limit(monkeypatch):
    # Owner on teams + two members; usage is summed across all three and checked
    # against the teams limit — NOT each member getting their own quota.
    monkeypatch.setattr(app_module, "_user_has_own_key", lambda u: False)
    monkeypatch.setattr(app_module, "_get_team_owner",
                        lambda u: "owner" if u in ("m1", "m2") else None)
    monkeypatch.setattr(app_module, "_get_team_members",
                        lambda u: ["m1", "m2"] if u == "owner" else [])
    monkeypatch.setattr(app_module, "_get_user_plan", lambda u: "teams")
    _seed_usage(monkeypatch, {"owner": 500, "m1": 300, "m2": 250})  # 1050 total

    # A member sees the pooled total (1050) vs the teams limit (1000) → blocked.
    allowed, used, limit, *_ = app_module._check_msg_limit("m1", "solo")
    assert limit == app_module.MSG_LIMITS["teams"] == 1000
    assert used == 1050
    assert allowed is False, "shared pool exhausted → members must be blocked too"

    # The owner sees the same pooled total.
    allowed_o, used_o, limit_o, *_ = app_module._check_msg_limit("owner", "teams")
    assert used_o == 1050 and limit_o == 1000 and allowed_o is False


# ── Tool-loop routing lever (default off) ────────────────────────────────────

def test_routing_default_off_uses_strong_model_everywhere(monkeypatch):
    monkeypatch.setattr(app_module, "TOOL_LOOP_MODEL", "")  # off
    models_used = []

    class _Resp:
        def __init__(self):
            self.usage = types.SimpleNamespace(prompt_tokens=10, completion_tokens=5)
            self.choices = [types.SimpleNamespace(
                finish_reason="stop",
                message=types.SimpleNamespace(content="ok", tool_calls=None))]

    def _create(**kw):
        models_used.append(kw["model"])
        return _Resp()

    monkeypatch.setattr(app_module, "get_openai_client",
                        lambda: types.SimpleNamespace(chat=types.SimpleNamespace(
                            completions=types.SimpleNamespace(create=_create))))
    app_module.call_llm_with_tools("s", [{"role": "user", "content": "hi"}],
                                   model="gpt-4o", username="u", teammate="A")
    assert models_used == ["gpt-4o"], "routing off must keep the strong model"


def test_routing_on_keeps_first_round_strong(monkeypatch):
    """With routing on, round 0 is strong; a later round would use the cheap
    model. Here round 0 already returns final, so only the strong model runs —
    proving the FIRST call is never downgraded."""
    monkeypatch.setattr(app_module, "TOOL_LOOP_MODEL", "gpt-4o-mini")
    models_used = []

    class _Resp:
        def __init__(self):
            self.usage = types.SimpleNamespace(prompt_tokens=10, completion_tokens=5)
            self.choices = [types.SimpleNamespace(
                finish_reason="stop",
                message=types.SimpleNamespace(content="ok", tool_calls=None))]

    def _create(**kw):
        models_used.append(kw["model"])
        return _Resp()

    monkeypatch.setattr(app_module, "get_openai_client",
                        lambda: types.SimpleNamespace(chat=types.SimpleNamespace(
                            completions=types.SimpleNamespace(create=_create))))
    app_module.call_llm_with_tools("s", [{"role": "user", "content": "hi"}],
                                   model="gpt-4o", username="u", teammate="A")
    assert models_used[0] == "gpt-4o", "first call must stay on the strong model"
