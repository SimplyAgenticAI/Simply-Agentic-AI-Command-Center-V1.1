# Session Patch Notes — 2026-05-28 (continued)

## Commit: 1a707ea — Cosmic canvas in all tool modals + fix image mode always-edit bug

---

### Feature: Cosmic Neural-Web in All Tool Windows

The cosmic neural-web particle animation (previously only on the main round table interface) now renders inside every tool modal — Lead Lab, Social Studio, Offer Builder, Visual Creator, Content Planner, CRM, and any other window that uses `#modalWin`.

**How it works:**
- Added `<canvas id="saToolCanvas">` as first child of `#modalWin`
- CSS: `position:absolute;inset:0;z-index:0;pointer-events:none` — sits behind all modal content
- `#modalBar` and `#modalScroll` are flex children, naturally above the absolutely-positioned canvas
- New JS: `window._saToolCanvasStart()` / `window._saToolCanvasStop()` control the animation loop
- `applyModalPos()` calls `_saToolCanvasStart()` when any modal opens
- `hideModal()` calls `_saToolCanvasStop()` when modal closes (stops the rAF loop to save GPU)
- Same particle colors/behavior as the main canvas — 70 nodes, max distance 170, cyan/purple/violet palette

---

### Bug Fix: Image Generation Always Defaulting to "Edit" Mode

**Root cause:**
In both `/api/followup` and `/api/followup/stream`, `classify_image_request_mode()` was called with:
```python
source_rec = latest_uploaded_image or _latest_image_record_from_state(name, uname)
mode = classify_image_request_mode(msg2, name, has_reference_image=bool(source_rec), ...)
```

If the user had EVER generated an image in a previous conversation, `_latest_image_record_from_state` returned a record, making `source_rec` truthy, and `has_reference_image=True`. Inside `classify_image_request_mode`, `has_reference_image=True` unconditionally returns `"edit"` regardless of the prompt text. This caused every new image request (e.g. "Create me a graphic of a frog...") to show `[Editing image]` instead of `[Generating image]`.

**Fix:**
```python
mode = classify_image_request_mode(msg2, name, has_reference_image=bool(latest_uploaded_image), ...)
```

`has_reference_image` is now only `True` when the user actually attached an image in the CURRENT message. `source_rec` (which may include old state images) is still passed to `build_image_request_prompt` for editing/variation context, but no longer influences mode classification for fresh requests.

Fixed in both the non-streaming endpoint (line ~7942) and the streaming endpoint (line ~48832).
