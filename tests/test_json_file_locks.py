"""Regression tests for the per-path JSON lock registry (V7.9).

The old eviction popped the oldest entry once the 500-key cap was hit, whether
or not a thread was inside it. The next caller for that path then built a fresh
Lock, so two threads could occupy the critical section for the same file at
once — mutual exclusion disappearing silently, which is the worst failure mode
for a lock.
"""
import threading
import time

import app as app_module


def test_same_path_returns_the_same_lock():
    p = app_module.DATA / "lock_identity_probe.json"
    with app_module._JSON_FILE_LOCKS_LOCK:
        app_module._JSON_FILE_LOCKS.pop(str(p.resolve()), None)
    seen = []
    with app_module._json_file_lock(p):
        seen.append(app_module._JSON_FILE_LOCKS[str(p.resolve())][0])
    with app_module._json_file_lock(p):
        seen.append(app_module._JSON_FILE_LOCKS[str(p.resolve())][0])
    assert seen[0] is seen[1]


def test_entry_is_not_evicted_while_held(monkeypatch):
    """Cap pressure must never reclaim an entry a thread is sitting inside."""
    monkeypatch.setattr(app_module, "_JSON_FILE_LOCKS_MAX", 1)
    held = app_module.DATA / "held.json"
    key = str(held.resolve())
    inside = threading.Event()
    release = threading.Event()

    def hold():
        with app_module._json_file_lock(held):
            inside.set()
            release.wait(5)

    t = threading.Thread(target=hold, daemon=True)
    t.start()
    assert inside.wait(5)
    # Churn other paths to push the registry well past the cap.
    for i in range(20):
        with app_module._json_file_lock(app_module.DATA / f"churn_{i}.json"):
            pass
    assert key in app_module._JSON_FILE_LOCKS, "held entry was evicted under cap pressure"
    release.set()
    t.join(5)


def test_mutual_exclusion_holds_under_cap_pressure(monkeypatch):
    """The property that actually matters: never two threads in at once."""
    monkeypatch.setattr(app_module, "_JSON_FILE_LOCKS_MAX", 1)
    target = app_module.DATA / "contended.json"
    concurrent = 0
    overlaps = []
    counter_lock = threading.Lock()

    def worker(n):
        nonlocal concurrent
        for _ in range(25):
            # Churn a unique path so the cap is under constant pressure.
            with app_module._json_file_lock(app_module.DATA / f"noise_{n}.json"):
                pass
            with app_module._json_file_lock(target):
                with counter_lock:
                    concurrent += 1
                    if concurrent > 1:
                        overlaps.append(concurrent)
                # Stay inside long enough that a mistakenly-handed-out second
                # lock produces a visible overlap rather than a rare one.
                time.sleep(0.002)
                with counter_lock:
                    concurrent -= 1

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert not overlaps, f"two threads inside the same file lock: {overlaps}"


def test_registry_reclaims_unused_entries(monkeypatch):
    """The cap must still do its job once entries fall out of use."""
    # Start from a clean registry — other tests in the suite leave idle entries
    # in this global dict, and this test asserts on its absolute size.
    with app_module._JSON_FILE_LOCKS_LOCK:
        app_module._JSON_FILE_LOCKS.clear()
    monkeypatch.setattr(app_module, "_JSON_FILE_LOCKS_MAX", 5)
    for i in range(60):
        with app_module._json_file_lock(app_module.DATA / f"reclaim_{i}.json"):
            pass
    assert len(app_module._JSON_FILE_LOCKS) <= 20


def test_refcount_returns_to_zero():
    p = app_module.DATA / "refcount_probe.json"
    key = str(p.resolve())
    with app_module._json_file_lock(p):
        assert app_module._JSON_FILE_LOCKS[key][1] == 1
    entry = app_module._JSON_FILE_LOCKS.get(key)
    assert entry is None or entry[1] == 0


def test_refcount_unwinds_on_exception():
    p = app_module.DATA / "refcount_exc.json"
    key = str(p.resolve())
    try:
        with app_module._json_file_lock(p):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    entry = app_module._JSON_FILE_LOCKS.get(key)
    assert entry is None or entry[1] == 0
    # The lock must be free for the next caller, not stuck held.
    with app_module._json_file_lock(p):
        pass
