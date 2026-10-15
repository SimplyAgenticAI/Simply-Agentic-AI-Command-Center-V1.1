# Live click-through — V10.0 → V11.7 (~20 minutes)

Do this on the **live Render site**, not locally. Anything that looks wrong: note the step
number and what you saw, and send it over. Steps build on each other, so go in order.

## A. New customer (private / incognito window, ~6 min)
1. [ ] **Signup** — Pricing → pick a plan → Stripe checkout (test mode or real card, cancel after) → you get an access code → Register.
2. [ ] **Pricing page** lists AI messages / month and lead searches / day for each plan. No mention of Lead Lab, Social Studio, Offer Builder.
3. [ ] **First-run questions** appear (business, ideal customer, where). Answer e.g. *roofers / Austin, TX* → "Finding real roofers…" → a result like "Added 9 real roofers to your Contacts".
4. [ ] **Draft my first hellos** → Today opens → *New leads to welcome* shows them and drafts start writing.
5. [ ] Top-right **Model:** label shows **GPT-4o** (included AI), not the old default text.

## B. Your own account (~10 min)
6. [ ] Page loads noticeably faster on the second visit (scripts are cached now).
7. [ ] **Today** → bottom → **🤖 Teammate jobs** → *Run now* on **Draft follow-ups** → within a minute, **✨ Ready for you** shows drafts. Open one with **Review**, edit a word, **✓ Send** → it arrives, and the contact's *last contact* updates.
8. [ ] **Send to all teammates** a question with trade-offs (e.g. "should I raise my prices?") → 7 *different* angles + a **🧭 Team answer** card on top.
9. [ ] Ask a teammate: "change the session objective to *Close 3 clients this month*" → the top bar changes **without refreshing**.
10. [ ] Ask a teammate: "put *call Bob* on my calendar tomorrow at 2pm" with the Calendar open → it appears live.
11. [ ] In chat, mention a real contact by name ("prep me for my call with *Sarah Jones*") → the reply uses their real stage / notes.
12. [ ] Ask "find 5 dentists in Austin" → lead table card → **➕ Add** one → it's in Contacts.
13. [ ] **Contacts** → on a contact card, **+ Task** and **✦ Draft** both open their dialogs.
14. [ ] **Contacts → Email Broadcast** → Audience **Pipeline stage** shows a dropdown with counts → **Dry run** → send to 3–4 contacts → progress shows "Next email in ~Xs", emails arrive about a minute apart, **no unsubscribe footer**. Your own contact: if listed as unsubscribed, **Resubscribe** works.
15. [ ] **Settings** → pick a different model → Save → top-right label updates immediately (or a note says which key is needed).
16. [ ] **Video Editor** → upload a short talking video → **📝 Get transcript** → transcript window with Timestamps / Copy / .txt / Save. **⚡ Make my shorts** with the week-plan box ticked → drafts show in the Content Planner across next week.
17. [ ] **More** menu: no "Ask a teammate" section; **💡 Ideas** opens the ideas list; **⭐ Saved** has Replies / Prompts / Playbooks tabs.

## C. Phone (~3 min)
18. [ ] Open a teammate chat on your phone → ask for 3 leads → **➕ Add** works (it used to do nothing on phones).
19. [ ] Today on the phone: long emails don't overflow; Ready for you buttons work.

## D. Admin checks (after a day of normal use)
20. [ ] `/api/admin/restarts` → **last_24h** should be a handful, not dozens. If it's dozens, Render's dashboard *Start Command* still says `--max-requests 500` — change it to match the Procfile (`--max-requests 5000 --max-requests-jitter 500`).
21. [ ] Off-site backups: after setting the Render env vars below, open `/admin/backups` → **Run backup now** → "Last off-site upload: ✓ worked".
22. [ ] `/admin/errors` — anything new and repeated? Send it over.
23. [ ] `/admin/economics` — cost per message still inside the plan budgets.

### Off-site backup setup (Backblaze B2, ~10 min, pennies/month)
1. backblaze.com → B2 Cloud Storage → create a **private** bucket (e.g. `simply-agentic-backups`).
2. App Keys → *Add a New Application Key* with access to that bucket. Copy the **keyID** and **applicationKey**.
3. Note the bucket's **Endpoint** (looks like `s3.us-west-004.backblazeb2.com`).
4. Render → your service → Environment → add:
   - `BACKUP_S3_BUCKET` = your bucket name
   - `BACKUP_S3_ENDPOINT` = `https://` + the endpoint
   - `BACKUP_S3_REGION` = the middle part, e.g. `us-west-004`
   - `AWS_ACCESS_KEY_ID` = keyID
   - `AWS_SECRET_ACCESS_KEY` = applicationKey
5. Save (Render redeploys) → do step 21.
