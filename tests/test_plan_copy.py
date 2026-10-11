"""Plan feature copy must match the limits the app actually enforces, and must
not advertise screens that were removed (V9.9.8)."""
import re

import app as app_module

REMOVED = ("Lead Lab", "Social Studio", "Offer Builder", "Site Analyzer", "Market Scanner",
           "Intent Signals", "Prospect Dossier", "Growth Playbook", "Response Vault", "Prompt Library")


def _num(text):
    return int(re.sub(r"[^0-9]", "", text))


def test_plan_limits_match_enforced_limits():
    for key, plan in app_module.PLANS.items():
        feats = plan["features"]
        msg = [f for f in feats if "AI messages per month" in f]
        leads = [f for f in feats if "lead searches per day" in f]
        assert msg and _num(msg[0].split("AI messages")[0]) == app_module.MSG_LIMITS[key], key
        assert leads and _num(leads[0]) == app_module.LEAD_LAB_LIMITS[key], key


def test_plans_do_not_mention_removed_screens():
    for plan in app_module.PLANS.values():
        for f in plan["features"]:
            assert not any(r in f for r in REMOVED), f


def test_teams_inherits_solo_lead_line_wording():
    # "Everything in Solo" — Teams states its own, bigger allowance
    assert any("10 lead searches" in f for f in app_module.PLANS["teams"]["features"])
