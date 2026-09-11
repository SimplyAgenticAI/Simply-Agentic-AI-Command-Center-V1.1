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
