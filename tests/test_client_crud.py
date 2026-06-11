"""End-to-end test of the /api/clients CRUD flow, including the atomic
read-modify-write path (_update_clients / update_json) added to fix
lost-update races under concurrent requests.
"""
import threading


def _csrf_headers(client):
    return {"X-CSRF-Token": client.csrf_token}


def test_client_crud_lifecycle(auth_client):
    c = auth_client
    headers = _csrf_headers(c)

    # No clients yet
    resp = c.get("/api/clients")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["clients"] == []

    # Create
    resp = c.post("/api/clients", json={"name": "Acme Co", "company": "Acme"}, headers=headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    client_id = body["client"]["id"]
    assert body["client"]["name"] == "Acme Co"
    # First client auto-activates
    assert body["active_client_id"] == client_id

    # List shows it
    resp = c.get("/api/clients")
    body = resp.get_json()
    assert len(body["clients"]) == 1
    assert body["clients"][0]["id"] == client_id

    # Active client matches
    resp = c.get("/api/clients/active")
    body = resp.get_json()
    assert body["client"]["id"] == client_id

    # Update
    resp = c.post(f"/api/clients/{client_id}", json={"notes": "VIP account"}, headers=headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["client"]["notes"] == "VIP account"
    assert body["client"]["name"] == "Acme Co"  # untouched fields preserved

    # Update non-existent client -> 404
    resp = c.post("/api/clients/does-not-exist", json={"notes": "x"}, headers=headers)
    assert resp.status_code == 404

    # Set active to nonexistent -> 404
    resp = c.post("/api/clients/active", json={"client_id": "does-not-exist"}, headers=headers)
    assert resp.status_code == 404

    # Delete
    resp = c.delete(f"/api/clients/{client_id}", headers=headers)
    assert resp.status_code == 200

    resp = c.get("/api/clients")
    body = resp.get_json()
    assert body["clients"] == []

    # Active client cleared after delete
    resp = c.get("/api/clients/active")
    body = resp.get_json()
    assert body["client"] == {}


def test_concurrent_client_creation_keeps_all(auth_client):
    """20 concurrent creates should all persist — regression test for the
    lost-update race fixed by _update_clients(). Exercises the same
    _update_clients() helper the /api/clients endpoints call; the Flask test
    client itself isn't thread-safe, so we drive the helper directly."""
    import app as app_module

    username = "smoketest_concurrent"

    def _create(i):
        def _mutate(data):
            cid = f"c_{i}"
            data["clients"][cid] = {"id": cid, "name": f"Client {i}"}
            if not (data.get("active_client_id") or "").strip():
                data["active_client_id"] = cid
            return data
        app_module._update_clients(username, _mutate)

    threads = [threading.Thread(target=_create, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    data = app_module._load_clients(username)
    assert len(data["clients"]) == 20
