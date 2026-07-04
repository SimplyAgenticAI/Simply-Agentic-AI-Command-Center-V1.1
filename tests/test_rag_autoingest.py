"""Tests for Phase 3 RAG auto-ingest of the operator's business context."""
import app as app_module


def test_rag_upsert_empty_returns_zero():
    assert app_module._rag_upsert_doc("u", "doc", "label", "") == 0
    assert app_module._rag_upsert_doc("u", "doc", "label", "   ") == 0


def test_autoingest_returns_int_and_never_raises():
    # Without an OpenAI key, embeddings fail gracefully -> 0 chunks, no exception.
    n = app_module._rag_autoingest_operator("rag_autoingest_user")
    assert isinstance(n, int)
    assert n >= 0


def test_sync_business_endpoint_requires_auth():
    # Unauthenticated POST is rejected — 403 (CSRF guard fires first) or 401.
    with app_module.app.test_client() as c:
        resp = c.post("/api/rag/sync_business")
        assert resp.status_code in (401, 403)
        assert resp.status_code != 200


def test_autoingest_maybe_debounces_per_user():
    # First call starts a re-ingest; an immediate second call is inside the gap
    # window and must be skipped. A different user is unaffected.
    u1, u2 = "rag_gate_user1", "rag_gate_user2"
    app_module._RAG_AUTOSYNC_TS.pop(u1, None)
    app_module._RAG_AUTOSYNC_TS.pop(u2, None)
    assert app_module._rag_autoingest_maybe(u1) is True
    assert app_module._rag_autoingest_maybe(u1) is False
    assert app_module._rag_autoingest_maybe(u2) is True


def test_crm_save_never_breaks_on_autosync(tmp_path):
    # _crm_save triggers the debounced hook; it must never raise.
    uname = "rag_gate_crmsave"
    crm = app_module._crm_load(uname)
    app_module._crm_save(uname, crm)
