# Session Patch Notes — 2026-05-28

## Commit: c406055 — 10 Teammate UX Improvements

---

### Bug Fix: Image Analysis

**Root cause 1:** System prompt only described image *generation* capability, not image *analysis*. Teammates defaulted to "I can't see images, please send one."
- Added `vision_analysis_rules` block to every teammate's system prompt: "You CAN see and analyze images attached to messages. NEVER ask the user to send or re-send an image they already attached."

**Root cause 2:** Attachment text `(image included for vision models when supported)` was ambiguous — the word "when supported" made models unsure if the image was actually included.
- Changed to `(image attached — visible to you in this message — analyze it directly)`

---

### Improvement 1: Image Context on Follow-ups

When user sends an image in turn 1 and asks a follow-up in turn 2 (no new file attached), the image used to disappear from context. Now:
- Both `api_followup_stream` and `_api_followup_impl` check `load_image_state(name, uname)["last_uploaded_image_id"]`
- If no new file_ids and a previous upload exists: re-reads the binary from disk, re-encodes to base64, re-attaches to the current message
- Generated DALL-E images are NOT re-attached (only user uploads via `last_uploaded_image_id`)

---

### Improvement 2: Conversation Starters

When a DM thread is empty (new conversation), show 3 quick-start prompt chips below the "No messages yet" card. Each teammate has role-specific starters:
- Alex: strategy prompts
- Willow: copy/language prompts
- Luna: creative/content prompts
- etc.
Clicking a chip fills the message field and focuses it.

---

### Improvement 3: Regenerate Button

Every assistant message bubble now has a `↩ Redo` button in the action row. On click:
- Finds the preceding user message (`msgs[msgIdx - 1]`)
- Fills followMsg field with it
- Calls `sendFollow()` for a fresh response

---

### Improvement 4: Thumbs Up / Down

Every assistant message bubble now has 👍 and 👎 buttons. Each click:
- POSTs to new `/api/teammate/feedback` route
- Writes a style note to the teammate's long-term memory (`style_notes` array)
- e.g. "User liked this response style: [first 160 chars]" or "User disliked..."
- Deduplicates before saving. Memory is shown to teammate in every future system prompt.

---

### Improvement 5: Be Brief / Go Deep Toggle

Above the DM message textarea: three small toggle buttons — **Brief**, **Auto** (default), **Deep**.
- Tracks `window._saLengthMode`
- In `sendFollow`, appends instruction to the message before sending:
  - Brief: `[Keep your reply concise — 2 to 4 sentences max.]`
  - Deep: `[Give a thorough, detailed reply — cover all angles fully.]`
- Visual state: active button highlights in cyan/purple/green

---

### Improvement 6: Round Table Per-Teammate Streaming

The Round Table fanout now uses `/api/followup/stream` instead of `/api/followup` for each teammate. Effects:
- Each teammate's response streams token-by-token into `renderGroupReplies` in real time
- `outputs[n]` updates incrementally — you see words appearing as they generate
- Teammates still run sequentially (one completes before the next starts) but each one streams visually
- `setSeatLive(n, "done")` fires as soon as that teammate finishes, before moving to next

---

### Improvement 7: Pinned Messages

Every assistant message bubble has a `📌 Pin` button. Pinning a message:
- POSTs to `/api/thread/pin` (toggle action)
- Stored in `thread_pins_{user}_{teammate}.json` (max 50 pins)
- Button updates to `📌 Unpin` and highlights yellow when pinned

When `renderThread` runs, `_renderPinnedBanner()` is called async:
- Fetches `/api/thread/pins?name=...`
- Inserts a gold banner at the top of the thread showing the first 3 pinned messages (truncated to 120 chars each)
- Clicking a pinned item shows the full text in a toast

---

### Improvement 8: Voice Dictation

New `🎤 Dictate` button in the DM header (right side, next to Brief/Auto/Deep toggles).
- Uses `window.SpeechRecognition` / `window.webkitSpeechRecognition` (Web Speech API)
- Continuous: false, interim results: true — shows live transcription in the text field
- While active: button shows `🔴 Stop` in red
- On end: cleans up interim placeholders, final text stays in field
- Distinct from the existing Voice Mode (🎙) — dictation populates the text field, voice mode is full voice interaction

---

### Improvement 9: Auto-Memory Extraction

After every 5 DM messages sent (tracked via `window._saMsgCountSinceExtract`), a background fetch fires to `/api/teammate/extract_memory`:
- Loads the teammate's thread (last 20 messages)
- Calls `_extract_memory_from_thread()` (existing LLM-based extractor)
- Merges extracted facts/style/preferences/open_loops into teammate long-term memory
- Non-blocking (`.catch(()=>{})`) — never interrupts the UI

---

### New Backend Routes

- `POST /api/teammate/feedback` — thumbs up/down → writes to `style_notes` in teammate memory
- `POST /api/thread/pin` — toggle pin for a message (body: `{name, text, action}`)
- `GET /api/thread/pins` — list pins for a teammate (query: `?name=...`)
- `POST /api/teammate/extract_memory` — trigger background memory extraction for a teammate

### New Storage

- `thread_pins_{user}_{teammate}.json` — list of pinned message texts (max 50, stored in DATA_DIR)
