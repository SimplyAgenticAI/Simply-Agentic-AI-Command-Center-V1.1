"""V14.0: a paid Founder checkout claims exactly one founder seat (before, no
code path ever claimed one, so "seats left" never moved).
(File must sort after test_client_crud — conftest's auth_client wants to be
the first registration.)"""
import app as app_module


def test_founder_checkout_claims_one_seat_once():
    before = app_module._load_founder_seats().get("claimed", 0)
    left_before = app_module._founder_seats_remaining()
    app_module._generate_seat_for_stripe("f@example.com", "cus_1", "cs_founder_1", plan="founder")
    app_module._generate_seat_for_stripe("f@example.com", "cus_1", "cs_founder_1", plan="founder")  # webhook retry
    assert app_module._load_founder_seats()["claimed"] == before + 1
    assert app_module._founder_seats_remaining() == left_before - 1


def test_solo_checkout_does_not_claim_founder_seat():
    before = app_module._load_founder_seats().get("claimed", 0)
    app_module._generate_seat_for_stripe("s@example.com", "cus_2", "cs_solo_1", plan="solo")
    assert app_module._load_founder_seats().get("claimed", 0) == before
