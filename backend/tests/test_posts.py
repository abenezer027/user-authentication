def test_post_crud_and_public_read(client, auth_headers):
    created = client.post(
        "/posts",
        json={"title": "First post", "content": "Hello blog"},
        headers=auth_headers,
    )

    assert created.status_code == 201
    post = created.json()
    assert post["title"] == "First post"
    assert post["author"] == "testuser"

    listed = client.get("/posts")
    fetched = client.get(f"/posts/{post['id']}")
    assert listed.status_code == 200
    assert listed.json()[0]["id"] == post["id"]
    assert fetched.status_code == 200
    assert fetched.json()["content"] == "Hello blog"

    updated = client.put(
        f"/posts/{post['id']}",
        json={"title": "Updated post", "content": "Updated content"},
        headers=auth_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["title"] == "Updated post"

    deleted = client.delete(f"/posts/{post['id']}", headers=auth_headers)
    missing = client.get(f"/posts/{post['id']}")
    assert deleted.status_code == 204
    assert missing.status_code == 404


def test_post_writes_require_authentication(client):
    response = client.post(
        "/posts", json={"title": "Unauthorized", "content": "No token"}
    )

    assert response.status_code == 401


def test_users_can_only_modify_their_own_posts(client, auth_headers, create_user):
    post = client.post(
        "/posts",
        json={"title": "Owner post", "content": "Only the owner can edit this."},
        headers=auth_headers,
    ).json()
    other_user = create_user(
        username="otheruser", phone="5557654321", password="password123"
    )
    login = client.post(
        "/login",
        json={
            "username_or_phone": other_user["username"],
            "password": other_user["password"],
        },
    )
    other_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    update = client.put(
        f"/posts/{post['id']}",
        json={"title": "Hijacked", "content": "Not the owner."},
        headers=other_headers,
    )
    delete = client.delete(f"/posts/{post['id']}", headers=other_headers)

    assert update.status_code == 404
    assert delete.status_code == 404
