"""Tests for prompt caching + the Claude model refresh (V9.6.7).

Two things were costing real money. Claude calls sent the system prompt as a
bare string, so nothing was cacheable — and the agentic tool loop re-sent the
whole persona + tool schema on every round at full input price. And the model
IDs were a generation behind: Opus 4.5 bills at $15/$75 per 1M where Opus 5 is
$5/$25 and stronger.

These cover the pure helpers: the system-block wrapper, the legacy-ID alias
map, and cache-aware cost estimation.
"""
import app as app_module


# ── _cached_system ──────────────────────────────────────────────────────────

def test_long_system_prompt_is_wrapped_with_a_cache_breakpoint():
    out = app_module._cached_system("x" * 5000)
    assert isinstance(out, list) and len(out) == 1
    assert out[0]["type"] == "text"
    assert out[0]["cache_control"] == {"type": "ephemeral"}
    assert out[0]["text"] == "x" * 5000


def test_short_system_prompt_stays_a_plain_string():
    """Below any model's minimum cacheable prefix a block would never cache,
    so don't pay the structural overhead of sending one."""
    assert app_module._cached_system("be helpful") == "be helpful"


def test_empty_system_prompt_does_not_become_an_empty_block():
    """An empty text block is rejected by the API — must stay a string."""
    assert app_module._cached_system("") == ""
    assert app_module._cached_system(None) == ""


# ── _canonical_model ────────────────────────────────────────────────────────

def test_legacy_claude_ids_resolve_to_the_current_generation():
    assert app_module._canonical_model("claude-opus-4-5") == "claude-opus-5"
    assert app_module._canonical_model("claude-sonnet-4-5") == "claude-sonnet-5"
    assert app_module._canonical_model("claude-sonnet-4-6") == "claude-sonnet-5"


def test_current_and_unknown_models_pass_through_untouched():
    for m in ("claude-opus-5", "claude-haiku-4-5", "gpt-4o", "gpt-4o-mini"):
        assert app_module._canonical_model(m) == m


def test_canonical_model_handles_blank_input():
    assert app_module._canonical_model("") == ""
    assert app_module._canonical_model(None) == ""


def test_saved_teammate_preference_on_a_retired_id_still_resolves():
    """A teammate saved before the refresh must not keep billing at the old
    (3x higher) Opus rate."""
    defn = {"preferred_model": "claude-opus-4-5"}
    assert app_module._resolve_model_for_user(defn) == "claude-opus-5"


def test_user_global_default_on_a_retired_id_still_resolves():
    u = {"settings": {"global_default_model": "claude-sonnet-4-5"}}
    assert app_module._resolve_model_for_user({}, u) == "claude-sonnet-5"


# ── cost estimation ─────────────────────────────────────────────────────────

def test_cache_reads_are_priced_far_below_fresh_input():
    """1M cached-read tokens must cost ~10% of 1M fresh input tokens."""
    fresh  = app_module._estimate_token_cost_usd("claude-opus-5", 1_000_000, 0)
    cached = app_module._estimate_token_cost_usd("claude-opus-5", 0, 0, cached_in=1_000_000)
    assert fresh == 5.00
    assert abs(cached - 0.50) < 1e-9


def test_cache_writes_cost_a_premium_over_fresh_input():
    written = app_module._estimate_token_cost_usd("claude-opus-5", 0, 0, cache_write=1_000_000)
    assert abs(written - 6.25) < 1e-9


def test_cost_estimate_is_unchanged_when_no_cache_tokens_are_reported():
    """OpenAI call sites pass no cache counts — their costing must not move."""
    assert app_module._estimate_token_cost_usd("gpt-4o", 1_000_000, 1_000_000) == 12.50


def test_current_claude_models_are_priced():
    for m in ("claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"):
        assert m in app_module._MODEL_PRICING_PER_1M


def test_legacy_models_stay_priced_for_historical_usage_logs():
    """Old log entries still name retired IDs; dropping them would silently
    reprice history at the default rate."""
    assert app_module._MODEL_PRICING_PER_1M["claude-opus-4-5"]["in"] == 15.00


def test_opus_5_is_materially_cheaper_than_the_model_it_replaces():
    old = app_module._MODEL_PRICING_PER_1M["claude-opus-4-5"]
    new = app_module._MODEL_PRICING_PER_1M["claude-opus-5"]
    assert new["in"] < old["in"] and new["out"] < old["out"]


# ── usage logging ───────────────────────────────────────────────────────────

def test_usage_log_records_cache_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "LOGS_DIR", tmp_path)
    app_module._log_token_usage("cacheuser", "claude-opus-5", 100, 50,
                                cached_in=900_000, cache_write=0)
    recs = app_module._read_token_usage("cacheuser")
    assert recs and recs[-1]["cached_input_tokens"] == 900_000
    # 900k cached reads at 10% of $5/1M = $0.45, well under the $4.50 it
    # would have cost billed as fresh input.
    assert 0.44 < recs[-1]["cost_usd"] < 0.47


def test_claude_usage_counts_reads_all_four_fields():
    class _U:
        input_tokens = 10
        output_tokens = 20
        cache_read_input_tokens = 30
        cache_creation_input_tokens = 40
    assert app_module._claude_usage_counts(_U()) == (10, 20, 30, 40)


def test_claude_usage_counts_tolerates_missing_cache_fields():
    """Older SDK versions / non-cached responses omit the cache fields."""
    class _U:
        input_tokens = 10
        output_tokens = 20
    assert app_module._claude_usage_counts(_U()) == (10, 20, 0, 0)


# ── V9.6.8: teammate prompt cache correctness ───────────────────────────────

def test_tools_on_prompt_is_not_served_a_cached_tools_off_prompt(flask_app):
    """The in-process prompt cache was keyed without tools_enabled, so a
    tools-off build handed a streaming chat a prompt missing the ACTIONS block
    for up to 30s — the teammate offered instead of acting."""
    app_module._invalidate_sys_prompt_cache()
    with flask_app.test_request_context():
        off = app_module.teammate_system_prompt({"name": "Alex"}, tools_enabled=False)
        on = app_module.teammate_system_prompt({"name": "Alex"}, tools_enabled=True)
        off_again = app_module.teammate_system_prompt({"name": "Alex"}, tools_enabled=False)
    assert "ACTIONS YOU CAN TAKE RIGHT NOW" not in off
    assert "ACTIONS YOU CAN TAKE RIGHT NOW" in on
    assert "ACTIONS YOU CAN TAKE RIGHT NOW" not in off_again


def test_cache_hit_keeps_the_image_request_status_note(flask_app):
    """The cache-hit path used to return base + rag + memory only, dropping the
    IMAGE REQUEST STATUS guard on every message after the first within the TTL."""
    app_module._invalidate_sys_prompt_cache()
    with flask_app.test_request_context():
        first = app_module.teammate_system_prompt({"name": "Alex"})
        second = app_module.teammate_system_prompt({"name": "Alex"})       # cache hit
        img = app_module.teammate_system_prompt({"name": "Alex"}, image_request_active=True)
    assert "IMAGE REQUEST STATUS" in first
    assert first == second
    assert "The system HAS classified this message" in img


def test_invalidate_clears_every_lighting_and_tools_variant(flask_app):
    app_module._invalidate_sys_prompt_cache()
    with flask_app.test_request_context():
        uname = app_module._get_session_username()
        for lm in (True, False):
            for te in (True, False):
                app_module.teammate_system_prompt({"name": "Alex"}, lighting_mode=lm, tools_enabled=te)
    app_module._invalidate_sys_prompt_cache(uname, "Alex")
    assert not any(k.startswith(f"{uname}:Alex:") for k in app_module._SYS_PROMPT_CACHE)


# ── V9.6.8: breakpoint at the end of the stable base ────────────────────────

def test_teammate_prompt_splits_into_cached_base_and_uncached_suffix(flask_app):
    """The per-message suffix changes every turn. With the breakpoint after it,
    caching only helped inside one reply's tool loop; with the breakpoint at
    the end of the base, every message in a conversation reuses the base."""
    app_module._invalidate_sys_prompt_cache()
    with flask_app.test_request_context():
        p1 = app_module.teammate_system_prompt({"name": "Alex"}, rag_context="RAG one")
        p2 = app_module.teammate_system_prompt({"name": "Alex"}, rag_context="RAG two, different")
    b1, b2 = app_module._cached_system(p1), app_module._cached_system(p2)
    assert isinstance(b1, list) and len(b1) == 2
    assert b1[0]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in b1[1]
    # Byte-identical cached span across two different messages = cache hit.
    assert b1[0]["text"] == b2[0]["text"]
    assert "RAG one" in b1[1]["text"] and "RAG two" in b2[1]["text"]
    assert b1[0]["text"] + b1[1]["text"] == p1


def test_text_appended_after_the_builder_stays_in_the_uncached_block(flask_app):
    """The streaming path appends VOICE CONVERSATION MODE after building."""
    app_module._invalidate_sys_prompt_cache()
    with flask_app.test_request_context():
        p = app_module.teammate_system_prompt({"name": "Alex"}) + "\n\nVOICE CONVERSATION MODE"
    blocks = app_module._cached_system(p)
    assert "VOICE CONVERSATION MODE" not in blocks[0]["text"]
    assert blocks[-1]["text"].endswith("VOICE CONVERSATION MODE")


def test_unregistered_long_prompt_still_caches_as_one_block():
    blocks = app_module._cached_system("unregistered " * 400)
    assert len(blocks) == 1 and blocks[0]["cache_control"] == {"type": "ephemeral"}


def test_whitespace_only_remainder_is_not_sent_as_an_empty_block():
    base = "stable base prompt " * 200
    app_module._register_cacheable_prefix(base)
    blocks = app_module._cached_system(base + "\n  \n")
    assert len(blocks) == 1 and blocks[0]["text"] == base


def test_prefix_registry_is_bounded():
    for i in range(app_module._CACHEABLE_PREFIXES_MAX + 20):
        app_module._register_cacheable_prefix(f"prefix {i} " * 300)
    assert len(app_module._CACHEABLE_PREFIXES) <= app_module._CACHEABLE_PREFIXES_MAX


# ── V9.6.8: OpenAI cached-token accounting ──────────────────────────────────

def test_openai_cached_tokens_are_split_out_of_prompt_tokens():
    import types
    u = types.SimpleNamespace(prompt_tokens=10_000, completion_tokens=200,
                              prompt_tokens_details=types.SimpleNamespace(cached_tokens=8_000))
    assert app_module._openai_usage_counts(u) == (2_000, 200, 8_000)


def test_openai_usage_without_details_reports_no_cache():
    import types
    u = types.SimpleNamespace(prompt_tokens=500, completion_tokens=50)
    assert app_module._openai_usage_counts(u) == (500, 50, 0)


def test_openai_cached_count_never_exceeds_prompt_tokens():
    import types
    u = types.SimpleNamespace(prompt_tokens=100, completion_tokens=1,
                              prompt_tokens_details=types.SimpleNamespace(cached_tokens=999))
    assert app_module._openai_usage_counts(u) == (0, 1, 100)


def test_openai_cache_reads_bill_at_half_the_input_rate():
    """OpenAI's discount is 50%, not Anthropic's 90% — must use the explicit rate."""
    assert abs(app_module._estimate_token_cost_usd("gpt-4o-mini", 0, 0, cached_in=1_000_000) - 0.075) < 1e-9
    assert abs(app_module._estimate_token_cost_usd("gpt-4o", 0, 0, cached_in=1_000_000) - 1.25) < 1e-9


def test_claude_cache_reads_still_use_the_anthropic_multiplier():
    assert abs(app_module._estimate_token_cost_usd("claude-sonnet-5", 0, 0, cached_in=1_000_000) - 0.20) < 1e-9
