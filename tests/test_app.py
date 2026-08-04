def test_register_new_user_succeeds(client):
    resp = client.post("/api/register", json={
        "name": "Jane Doe",
        "email": "jane@example.com",
        "password": "secret123",
        "phone": "5551234567",
        "place": "Springfield",
        "role": "user",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["user"]["email"] == "jane@example.com"
    assert data["user"]["role"] == "user"


def test_register_missing_fields_fails(client):
    resp = client.post("/api/register", json={"name": "Incomplete"})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_register_duplicate_email_fails(client, regular_user):
    resp = client.post("/api/register", json=regular_user)
    assert resp.status_code == 400
    assert "already registered" in resp.get_json()["error"]


def test_login_with_correct_credentials_succeeds(client, regular_user):
    resp = client.post("/api/login", json={
        "email": regular_user["email"],
        "password": regular_user["password"],
        "role": "user",
    })
    assert resp.status_code == 200
    assert resp.get_json()["user"]["email"] == regular_user["email"]


def test_login_with_wrong_password_fails(client, regular_user):
    resp = client.post("/api/login", json={
        "email": regular_user["email"],
        "password": "wrong-password",
        "role": "user",
    })
    assert resp.status_code == 400


def test_me_when_logged_out_returns_none(client):
    resp = client.get("/api/me")
    assert resp.status_code == 200
    assert resp.get_json()["user"] is None


def test_me_when_logged_in_returns_user(client, regular_user):
    client.post("/api/login", json={
        "email": regular_user["email"],
        "password": regular_user["password"],
        "role": "user",
    })
    resp = client.get("/api/me")
    assert resp.get_json()["user"]["email"] == regular_user["email"]


def test_admin_can_create_service_and_slot(client, admin_user):
    client.post("/api/login", json={
        "email": admin_user["email"],
        "password": admin_user["password"],
        "role": "admin",
    })

    service_resp = client.post("/api/admin/services", json={
        "name": "General Checkup",
        "type": "clinic",
        "address": "123 Main St",
    })
    assert service_resp.status_code == 201
    service_id = service_resp.get_json()["service"]["id"]

    slot_resp = client.post(f"/api/admin/services/{service_id}/slots", json={
        "time": "2030-01-01T10:00:00",
    })
    assert slot_resp.status_code == 201
    assert slot_resp.get_json()["slot"]["status"] == "available"


def test_non_admin_cannot_create_service(client, regular_user):
    client.post("/api/login", json={
        "email": regular_user["email"],
        "password": regular_user["password"],
        "role": "user",
    })
    resp = client.post("/api/admin/services", json={
        "name": "General Checkup",
        "type": "clinic",
        "address": "123 Main St",
    })
    assert resp.status_code == 403


def test_user_can_search_and_book_slot(client, admin_user, regular_user):
    client.post("/api/login", json={
        "email": admin_user["email"], "password": admin_user["password"], "role": "admin",
    })
    service_id = client.post("/api/admin/services", json={
        "name": "Dental Checkup", "type": "dental", "address": "456 Oak Ave",
    }).get_json()["service"]["id"]
    client.post(f"/api/admin/services/{service_id}/slots", json={"time": "2030-01-01T09:00:00"})
    client.post("/api/logout")

    client.post("/api/login", json={
        "email": regular_user["email"], "password": regular_user["password"], "role": "user",
    })
    search_resp = client.get("/api/search/slots?service_type=dental")
    assert search_resp.status_code == 200
    slots = search_resp.get_json()["slots"]
    assert len(slots) == 1

    book_resp = client.post("/api/bookings", json={"slot_id": slots[0]["id"]})
    assert book_resp.status_code == 200
    assert book_resp.get_json()["slot"]["booked"] is True

    bookings_resp = client.get("/api/bookings")
    assert len(bookings_resp.get_json()["bookings"]) == 1
