# Session Patch Notes — 2026-05-28 (continued)

## Commit: 898a9a0 — Fix CRM Clients — Edit scroll-into-view + branded delete dialog

### Problems

1. **Edit button didn't work visually** — `crmOpenClientEditor()` set `display:block` on the editor panel but the modal didn't scroll down to show it. The panel was rendering below the fold of the modal with no way to see it.

2. **Delete dialog was native browser `confirm()`** — appeared at the top of the screen, used browser chrome styling, didn't match the app's dark glassmorphism brand.

### Fixes

**Edit button scroll-into-view** (`crmOpenClientEditor`):
- Added `setTimeout(()=>ed.scrollIntoView({behavior:'smooth', block:'nearest'}), 50)` after `display:block`
- 50ms delay gives the browser time to paint the element before scrolling

**Branded delete overlay** (`crmDeleteClient`):
- Removed `confirm('Delete this client?')` entirely
- Replaced with `await new Promise(resolve => ...)` that injects a custom overlay:
  - `position:fixed;inset:0` fullscreen backdrop — `rgba(0,0,0,.75)` dim
  - Centered glass card: `rgba(8,13,33,.97)` bg, `backdrop-filter:blur(22px)`, red border accent
  - Shows trash icon, "Delete Contact?" title, contact name highlighted
  - Cancel button (muted gray) + Delete button (red-tinted glass)
  - Clicking backdrop = cancel
  - Resolves promise true/false, then proceeds or aborts the DELETE fetch
