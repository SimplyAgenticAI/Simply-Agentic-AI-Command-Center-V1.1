"""Regression tests for teammate image-context coherence:
- The system prompt should surface a ranked, described history of recently
  generated images so the LLM can resolve vague references ('that', 'the
  previous one') without guessing from raw thread markers.
- Feedback about a generated image ('I love how you did that') should be
  recorded as a teammate preference.
- Thread truncation should not silently drop references to generated images.
"""
from flask import session

import app as app_module


def test_image_history_block_in_system_prompt(flask_app):
    uname = "smoketest_img_history"
    teammate = "Luna"

    state = app_module.load_image_state(teammate, uname)
    state = app_module._append_image_history(
        state, {"id": "img1", "relpath": "ai_images/img1.png"},
        mode="new", prompt="A sunshine over a forest scattered with red and white mushrooms",
    )
    state = app_module._append_image_history(
        state, {"id": "img2", "relpath": "ai_images/img2.png"},
        mode="new", prompt="A self-portrait of Luna as a glowing futuristic AI figure",
    )
    app_module.save_image_state(teammate, state, uname)

    with flask_app.test_request_context():
        session["user"] = {"username": uname}
        prompt = app_module.teammate_system_prompt({"name": teammate, "job_title": "Creative Director"})

    assert "RECENT IMAGES YOU GENERATED" in prompt
    assert "MOST RECENT" in prompt
    assert "PREVIOUS" in prompt
    assert "self-portrait of Luna" in prompt
    assert "sunshine over a forest" in prompt
    # The most recently generated image must be ranked ahead of the older one.
    assert prompt.index("self-portrait of Luna") < prompt.index("sunshine over a forest")


def test_image_feedback_recorded_as_preference():
    uname = "smoketest_img_feedback"
    teammate = "Luna"

    app_module.save_teammate_memory(uname, teammate, {
        "facts": [], "style_notes": [], "preferences": [], "open_loops": [],
    })
    state = app_module.load_image_state(teammate, uname)
    state = app_module._append_image_history(
        state, {"id": "img1", "relpath": "ai_images/img1.png"},
        mode="new", prompt="A self-portrait of Luna as a glowing futuristic AI figure",
    )
    app_module.save_image_state(teammate, state, uname)

    app_module._maybe_record_image_feedback(uname, teammate, "I love how you did that")

    mem = app_module.load_teammate_memory(uname, teammate)
    prefs = mem.get("preferences") or []
    assert any("I love how you did that" in p for p in prefs)
    assert any("self-portrait of Luna" in p for p in prefs)


def test_image_feedback_ignores_unrelated_messages():
    uname = "smoketest_img_feedback_neg"
    teammate = "Luna"

    app_module.save_teammate_memory(uname, teammate, {
        "facts": [], "style_notes": [], "preferences": [], "open_loops": [],
    })

    app_module._maybe_record_image_feedback(uname, teammate, "What's our follow-up plan for next week?")

    mem = app_module.load_teammate_memory(uname, teammate)
    assert mem.get("preferences") == []


def test_start_new_chat_archives_and_resets_image_state(flask_app):
    teammate = "Luna"
    uname = "smoketest_newchat"

    data = app_module.load_users()
    data.setdefault("users", {})[uname] = {"username": uname, "password_hash": "", "is_admin": False}
    app_module.save_users(data)

    with flask_app.test_client() as c:
        csrf_token = c.get("/api/csrf_token").get_json()["csrf_token"]
        with c.session_transaction() as sess:
            sess["user"] = uname

        save_thread = app_module.save_thread
        save_thread(teammate, [
            {"role": "user", "content": "Make a self-portrait of yourself"},
            {"role": "assistant", "content": "[Image generated #1] /uploads/ai_images/img1.png\n[refined_prompt] A glowing AI figure"},
        ], uname)

        state = app_module.load_image_state(teammate, uname)
        state["current_image_id"] = "img1"
        state["current_image_url"] = "/uploads/ai_images/img1.png"
        state = app_module._append_image_history(
            state, {"id": "img1", "relpath": "ai_images/img1.png"},
            mode="new", prompt="A glowing AI figure",
        )
        app_module.save_image_state(teammate, state, uname)

        resp = c.post(f"/api/thread/{teammate}/new_chat", headers={"X-CSRF-Token": csrf_token})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["ok"] is True
        assert body["archived"] is True

    # Thread is cleared.
    assert app_module.load_thread(teammate, uname) == []

    # Image context pointers/history reset.
    new_state = app_module.load_image_state(teammate, uname)
    assert new_state["current_image_id"] == ""
    assert new_state["current_image_url"] == ""
    assert new_state["history"] == []

    # The old conversation was archived as a restorable branch.
    branches = app_module._load_branches(teammate)
    archived = list((branches.get("branches") or {}).values())
    assert len(archived) == 1
    assert archived[0]["msg_count"] == 2


def test_truncate_preserves_image_markers():
    thread = []
    for i in range(10):
        thread.append({"role": "user", "content": f"message {i}"})
        thread.append({"role": "assistant", "content": f"reply {i}"})
    thread.insert(2, {"role": "assistant", "content": "[Image generated #1] /uploads/ai_images/img1.png\n[refined_prompt] A sunshine over a forest with mushrooms"})

    truncated = app_module._truncate_thread_with_note(thread, max_messages=4)

    note = truncated[0]["content"]
    assert "[Image generated #1]" in note
    assert "/uploads/ai_images/img1.png" in note
