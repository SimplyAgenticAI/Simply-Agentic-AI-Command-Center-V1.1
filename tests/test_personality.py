"""Personality dials: band translation, sanitizer clamping, endpoint round-trip."""
import app as app_module


def test_personality_lines_neutral_emits_nothing():
    neutral = {t: 50 for t in app_module.PERSONALITY_TRAITS}
    assert app_module._personality_lines({"personality_dials": neutral}) == []
    assert app_module._personality_lines({}) == []
    assert app_module._personality_lines({"personality_dials": "junk"}) == []


def test_personality_lines_bands():
    lines = app_module._personality_lines(
        {"personality_dials": {"directness": 85, "humor": 5, "pushback": 70}})
    assert len(lines) == 3
    joined = " ".join(lines).lower()
    assert "hard truth" in joined            # directness strong-high
    assert "strictly professional" in joined  # humor strong-low
    assert "counterargument" in joined        # pushback high


def test_sanitizer_clamps_and_drops_junk():
    cur = {"name": "Alex", "avatar": {}}
    upd = app_module._sanitize_teammate_update(
        {"personality_dials": {"directness": 150, "humor": -5, "hax": 99, "energy": "80"}}, cur)
    p = upd["personality_dials"]
    assert p["directness"] == 100
    assert p["humor"] == 0
    assert p["energy"] == 80
    assert "hax" not in p
    upd2 = app_module._sanitize_teammate_update({"personality_dials": "nope"}, cur)
    assert "personality_dials" not in upd2


def test_prompt_contains_dials_block_only_when_tuned(flask_app):
    with flask_app.test_request_context():
        sysp = app_module.teammate_system_prompt({"name": "Alex", "personality_dials": {"humor": 95}})
        assert "PERSONALITY DIALS" in sysp
        app_module._invalidate_sys_prompt_cache()   # 30s TTL cache is keyed per teammate
        sysp2 = app_module.teammate_system_prompt({"name": "Alex"})
        assert "PERSONALITY DIALS" not in sysp2


def test_personality_endpoint_roundtrip(flask_app):
    with flask_app.test_client() as c:
        c.post("/register", data={"username": "smoketest", "email": "",
                                  "password": "TestPass123!", "password2": "TestPass123!",
                                  "tos_accepted": "on"}, follow_redirects=True)
        c.post("/login", data={"username": "smoketest", "password": "TestPass123!"},
               follow_redirects=True)
        tok = c.get("/api/csrf_token").get_json()["csrf_token"]
        r = c.post("/api/teammate/Alex",
                   json={"personality_dials": {"humor": 90, "directness": 120}},
                   headers={"X-CSRF-Token": tok})
        assert r.status_code == 200 and r.get_json()["ok"]
        reg = app_module.load_registry("smoketest")
        p = reg["installed"]["Alex"]["personality_dials"]
        assert p["humor"] == 90
        assert p["directness"] == 100   # clamped


