import hashlib
import hmac
import secrets
import sqlite3
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Iterator

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(
    title="Simple User Auth and Blog API",
    description="Register and log in users, then manage blog posts using a bearer token.",
    version="1.0.0",
)

DB_PATH = Path(__file__).with_name("users.db")
PASSWORD_HASH_ITERATIONS = 600_000
security = HTTPBearer(auto_error=False, scheme_name="BearerAuth")


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    with closing(sqlite3.connect(DB_PATH)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            yield connection


def init_db() -> None:
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS blog_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )


init_db()


class RegisterModel(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(..., min_length=3, max_length=20)
    phone: str = Field(..., min_length=7, max_length=20, description="Mobile phone number")
    password: str = Field(..., min_length=6)


class LoginModel(BaseModel):
    username_or_phone: str = Field(..., description="Log in with a username or phone number")
    password: str


class MessageResponse(BaseModel):
    message: str


class PublicUser(BaseModel):
    username: str
    phone: str


class LoginResponse(MessageResponse):
    access_token: str
    token_type: str
    user: PublicUser


class PostInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1)


class UserIdentity(BaseModel):
    id: int
    username: str


class PostResponse(BaseModel):
    id: int
    title: str
    content: str
    author: str
    created_at: datetime
    updated_at: datetime


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    algorithm, iterations, salt_hex, expected_hex = encoded_hash.split("$", 3)
    if algorithm != "pbkdf2_sha256":
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
    )
    return hmac.compare_digest(actual.hex(), expected_hex)


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(security)
    ],
) -> UserIdentity:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with get_db() as connection:
        user = connection.execute(
            """
            SELECT users.id, users.username
            FROM auth_tokens
            JOIN users ON users.id = auth_tokens.user_id
            WHERE auth_tokens.token = ?
            """,
            (credentials.credentials,),
        ).fetchone()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return UserIdentity(id=user["id"], username=user["username"])


def post_with_author(post: sqlite3.Row) -> PostResponse:
    return PostResponse(
        id=post["id"],
        title=post["title"],
        content=post["content"],
        author=post["author"],
        created_at=post["created_at"],
        updated_at=post["updated_at"],
    )


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: RegisterModel) -> MessageResponse:
    try:
        with get_db() as connection:
            connection.execute(
                "INSERT INTO users (username, phone, hashed_password) VALUES (?, ?, ?)",
                (user_data.username, user_data.phone, hash_password(user_data.password)),
            )
    except sqlite3.IntegrityError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or phone number already registered.",
        ) from error

    return MessageResponse(message="User registered successfully.")


@app.post("/login", response_model=LoginResponse)
def login(login_data: LoginModel) -> LoginResponse:
    with get_db() as connection:
        user = connection.execute(
            """
            SELECT id, username, phone, hashed_password
            FROM users
            WHERE username = ? OR phone = ?
            """,
            (login_data.username_or_phone, login_data.username_or_phone),
        ).fetchone()

    if user is None or not verify_password(login_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username/phone or password.",
        )

    token = secrets.token_urlsafe(32)
    with get_db() as connection:
        connection.execute(
            "INSERT INTO auth_tokens (token, user_id) VALUES (?, ?)",
            (token, user["id"]),
        )

    return LoginResponse(
        message="Login successful.",
        access_token=token,
        token_type="bearer",
        user=PublicUser(username=user["username"], phone=user["phone"]),
    )


@app.post("/logout", response_model=MessageResponse)
def logout(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(security)
    ],
    _current_user: Annotated[UserIdentity, Depends(get_current_user)],
) -> MessageResponse:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    with get_db() as connection:
        connection.execute(
            "DELETE FROM auth_tokens WHERE token = ?", (credentials.credentials,)
        )
    return MessageResponse(message="Logged out successfully.")


@app.get("/posts", response_model=list[PostResponse])
def list_posts() -> list[PostResponse]:
    with get_db() as connection:
        posts = connection.execute(
            """
            SELECT blog_posts.*, users.username AS author
            FROM blog_posts
            JOIN users ON users.id = blog_posts.user_id
            ORDER BY blog_posts.id DESC
            """
        ).fetchall()
    return [post_with_author(post) for post in posts]


@app.post("/posts", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
def create_post(
    post_data: PostInput,
    current_user: Annotated[UserIdentity, Depends(get_current_user)],
) -> PostResponse:
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as connection:
        cursor = connection.execute(
            """
            INSERT INTO blog_posts (user_id, title, content, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (current_user.id, post_data.title, post_data.content, now, now),
        )
        post = connection.execute(
            """
            SELECT blog_posts.*, users.username AS author
            FROM blog_posts
            JOIN users ON users.id = blog_posts.user_id
            WHERE blog_posts.id = ?
            """,
            (cursor.lastrowid,),
        ).fetchone()
    return post_with_author(post)


@app.get("/posts/{post_id}", response_model=PostResponse)
def get_post(post_id: int) -> PostResponse:
    with get_db() as connection:
        post = connection.execute(
            """
            SELECT blog_posts.*, users.username AS author
            FROM blog_posts
            JOIN users ON users.id = blog_posts.user_id
            WHERE blog_posts.id = ?
            """,
            (post_id,),
        ).fetchone()
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found.")
    return post_with_author(post)


@app.put("/posts/{post_id}", response_model=PostResponse)
def update_post(
    post_id: int,
    post_data: PostInput,
    current_user: Annotated[UserIdentity, Depends(get_current_user)],
) -> PostResponse:
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as connection:
        updated = connection.execute(
            """
            UPDATE blog_posts
            SET title = ?, content = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (post_data.title, post_data.content, now, post_id, current_user.id),
        )
        if updated.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Post not found."
            )
        post = connection.execute(
            """
            SELECT blog_posts.*, users.username AS author
            FROM blog_posts
            JOIN users ON users.id = blog_posts.user_id
            WHERE blog_posts.id = ?
            """,
            (post_id,),
        ).fetchone()
    return post_with_author(post)


@app.delete("/posts/{post_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_post(
    post_id: int,
    current_user: Annotated[UserIdentity, Depends(get_current_user)],
) -> None:
    with get_db() as connection:
        deleted = connection.execute(
            "DELETE FROM blog_posts WHERE id = ? AND user_id = ?",
            (post_id, current_user.id),
        )
        if deleted.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Post not found."
            )
