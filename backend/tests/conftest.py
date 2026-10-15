import pytest
from fastapi.testclient import TestClient

from backend import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.db")
    main.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def create_user(client):
    def register(username="testuser", phone="5551234567", password="password123"):
        response = client.post(
            "/register",
            json={"username": username, "phone": phone, "password": password},
        )
        assert response.status_code == 201
        return {"username": username, "phone": phone, "password": password}

    return register


@pytest.fixture
def auth_headers(client, create_user):
    user = create_user()
    response = client.post(
        "/login",
        json={"username_or_phone": user["username"], "password": user["password"]},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
