import sqlite3

from backend import main


def test_register_stores_a_hashed_password(client):
    response = client.post(
        "/register",
        json={
            "username": "newuser",
            "phone": "5551234567",
            "password": "password123",
        },
    )

    assert response.status_code == 201
    with sqlite3.connect(main.DB_PATH) as connection:
        password_hash = connection.execute(
            "SELECT hashed_password FROM users WHERE username = ?", ("newuser",)
        ).fetchone()[0]
    assert password_hash.startswith("pbkdf2_sha256$")
    assert password_hash != "password123"


def test_register_rejects_duplicate_username_or_phone(client, create_user):
    user = create_user()

    duplicate_username = client.post(
        "/register",
        json={
            "username": user["username"],
            "phone": "5559876543",
            "password": "password123",
        },
    )
    duplicate_phone = client.post(
        "/register",
        json={
            "username": "anotheruser",
            "phone": user["phone"],
            "password": "password123",
        },
    )

    assert duplicate_username.status_code == 409
    assert duplicate_phone.status_code == 409


def test_login_accepts_username_or_phone_and_rejects_bad_password(
    client, create_user
):
    user = create_user()

    username_login = client.post(
        "/login",
        json={"username_or_phone": user["username"], "password": user["password"]},
    )
    phone_login = client.post(
        "/login",
        json={"username_or_phone": user["phone"], "password": user["password"]},
    )
    bad_password = client.post(
        "/login",
        json={"username_or_phone": user["username"], "password": "wrong-password"},
    )

    assert username_login.status_code == 200
    assert username_login.json()["token_type"] == "bearer"
    assert username_login.json()["access_token"]
    assert phone_login.status_code == 200
    assert bad_password.status_code == 401


def test_logout_revokes_bearer_token(client, auth_headers):
    logout = client.post("/logout", headers=auth_headers)
    create_post = client.post(
        "/posts",
        json={"title": "After logout", "content": "This should fail."},
        headers=auth_headers,
    )

    assert logout.status_code == 200
    assert create_post.status_code == 401
