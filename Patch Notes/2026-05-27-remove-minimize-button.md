# Session Patch Notes — 2026-05-27

## Commit: 24cdf04 — Remove Minimize/Restore Buttons

### What was changed

Removed the non-functional Minimize and Restore buttons from all feature windows (the draggable `#modalWin`). Only the **Close** button remains.

### Files changed

**`app.py`** — 71 lines removed, 1 inserted:

**HTML (~line 16116):**
- Removed `<button id="minModal">Minimize</button>`
- Removed `<button id="restoreModal">Restore</button>`
- Kept `<button id="closeModal">Close</button>`

**CSS (~line 13644):**
- Removed `.modal.minimized { height: auto !important; ... }`
- Removed `.modal.minimized .modalBodyWrap { display:none; }`

**JS — removed all references:**
- `let modalMinimized = false;` declaration
- `$("minModal").onclick` full handler block (including toolDock logic)
- `$("restoreModal").onclick` handler
- All `modalMinimized = false/true` assignments in `showModal`, `showEditModal`, `showManageModal`, `showCreateModal`, `showFrameworkModal`
- All `$("minModal").style.display` / `$("restoreModal").style.display` resets in every show function
- `if(modalMinimized) return` guards in drag and resize pointerdown handlers
- `t.id === "minModal" || t.id === "restoreModal"` check in drag pointerdown filter
- The `modalMinimizedEl.classList.remove("minimized")` block in the CRM/Manage re-open path
- The `minBtn` / `restBtn` display resets in the toolDock `toolDockOpen` function
