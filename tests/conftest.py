import os
import sys
import tempfile
import pytest

TEST_DB_PATH = os.path.join(tempfile.gettempdir(), "swiftmeet_test.db")
os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH}"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app as flask_app, db  # noqa: E402


@pytest.fixture()
def app():
    flask_app.config.update(TESTING=True)
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_user(client):
    payload = {
        "name": "Admin One",
        "email": "admin@example.com",
        "password": "adminpass123",
        "phone": "1234567890",
        "place": "Test City",
        "role": "admin",
    }
    client.post("/api/register", json=payload)
    client.post("/api/logout")
    return payload


@pytest.fixture()
def regular_user(client):
    payload = {
        "name": "Test User",
        "email": "user@example.com",
        "password": "userpass123",
        "phone": "9876543210",
        "place": "Test City",
        "role": "user",
    }
    client.post("/api/register", json=payload)
    client.post("/api/logout")
    return payload
