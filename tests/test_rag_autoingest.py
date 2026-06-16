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
