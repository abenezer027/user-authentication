# User Authentication and Blog API

## Run locally

From this directory, install the dependencies and start the API:

```powershell
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) to try the endpoints in Swagger UI. The SQLite database (`users.db`) is created in this directory automatically.

## Try the authentication and post flow

1. Call `POST /register` with a username, phone number, and password.
2. Call `POST /login` with `username_or_phone` and password. Copy the returned `access_token`.
3. In Swagger UI, click **Authorize** and provide the access token as a bearer token.
4. Create posts with `POST /posts`; list and read posts with `GET /posts` and `GET /posts/{post_id}`.
5. Update or delete your own posts with `PUT /posts/{post_id}` or `DELETE /posts/{post_id}`.
6. Call `POST /logout` to invalidate the token.

Creating, updating, deleting posts, and logging out require authentication. Posts can be listed and read without logging in; only their author can update or delete them.

## Run tests

From this directory, install the development dependencies and run the endpoint tests:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```
