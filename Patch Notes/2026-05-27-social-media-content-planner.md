# Session Patch Notes — 2026-05-27 (continued)

## Commit: 4e894f5 — Social Media Content Planner

### What was built

Full Social Media Content Planner under **Manage → 📅 Content Planner**.

---

### UI

**Full-screen modal** (same pattern as Visual Creator):
- Header: title + platform connection pills + Calendar / Queue toggle + Import CSV + New Post + Close
- **Calendar view** — month grid, prev/next navigation, today highlighted, colored platform dots per day, click a day to pre-fill date in composer
- **Queue view** — posts sorted by date, grouped by status (Scheduled, Drafts, Published, Failed), platform color dots, Edit / Publish buttons
- **Composer panel** (right side) — slides open when creating or editing a post

**Composer fields:**
- Caption textarea with live character count
- **✦ Draft with AI** panel — enter a topic, pick a teammate (Luna/Alex/Sunshine) + tone (Engaging/Professional/Casual/Educational/Promotional), calls `/api/social/draft_ai`
- Platform checkboxes: 𝔣 Facebook · ◎ Instagram · ▶ YouTube · ♪ TikTok (each color-coded)
- Schedule date & time (datetime-local input)
- Media URL field (image/video, required for Instagram)
- **Save as Draft** / **Schedule** / **Publish Now** action buttons
- **Delete Post** (only shown when editing existing)
- Status feedback line below buttons

**Platform connection pills** (in header):
- Each pill shows connected name / page name when connected
- Inline **Connect** button (opens OAuth in popup window)
- Inline **✕** button to disconnect

---

### Python backend

**New env vars** (set on Render):
- `META_APP_ID` — Facebook App ID for OAuth
- `META_APP_SECRET` — Facebook App Secret
- `TIKTOK_CLIENT_KEY` — TikTok Developer App client key
- `TIKTOK_CLIENT_SECRET` — TikTok Developer App client secret

**Storage** (per user, in DATA_DIR):
- `social_posts_{username}.json` — list of post dicts
- `social_conns_{username}.json` — OAuth tokens + page info per platform

**Routes added:**
- `GET /api/social/posts` — list all posts
- `POST /api/social/posts` — create / update post
- `DELETE /api/social/posts/<id>` — delete a post
- `POST /api/social/publish/<id>` — publish now
- `POST /api/social/import_csv` — bulk CSV import
- `GET /api/social/connections` — connection status
- `POST /api/social/disconnect/<platform>` — revoke connection
- `POST /api/social/draft_ai` — AI teammate drafts caption
- `GET /social/connect/facebook` — start Facebook OAuth
- `GET /social/callback/facebook` — Facebook callback (also auto-connects Instagram Business)
- `GET /social/connect/youtube` — start YouTube OAuth (reuses Google creds)
- `GET /social/callback/youtube` — YouTube callback
- `GET /social/connect/tiktok` — start TikTok OAuth
- `GET /social/callback/tiktok` — TikTok callback

**Publishing:**
- Facebook: actual API post to Page feed or photos endpoint
- Instagram: media container → media_publish (requires Business account linked to FB Page)
- YouTube / TikTok: queued only (video upload not supported via API in this flow)

**CSV import columns:** `caption, platforms, scheduled_at, media_url`
- platforms: semicolon-separated (facebook;instagram)

---

### Setup checklist (for owner)

**Facebook/Instagram:**
1. Create Meta Developer App → add Facebook Login + Instagram Basic Display
2. Request permissions: pages_manage_posts, pages_read_engagement, instagram_content_publish, pages_show_list
3. Add redirect URI: `{PUBLIC_BASE_URL}/social/callback/facebook`
4. Set META_APP_ID + META_APP_SECRET on Render

**YouTube:** Already works via existing GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET

**TikTok:**
1. Create app at developers.tiktok.com
2. Add redirect URI: `{PUBLIC_BASE_URL}/social/callback/tiktok`
3. Set TIKTOK_CLIENT_KEY + TIKTOK_CLIENT_SECRET on Render
