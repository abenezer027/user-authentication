import sqlite3
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from passlib.context import CryptContext

app = FastAPI(title="Simple Auth API")

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Initialize SQLite database
DB_NAME = "users.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                phone TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """)
        conn.commit()

init_db()

# Pydantic Schemas for Request Validation
class RegisterModel(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    phone: str = Field(..., description="Mobile phone number")
    password: str = Field(..., min_length=6)

class LoginModel(BaseModel):
    username_or_phone: str = Field(..., description="Can login with username OR phone")
    password: str

# Helper functions
def get_user(username_or_phone: str):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, phone, hashed_password FROM users WHERE username = ? OR phone = ?", 
            (username_or_phone, username_or_phone)
        )
        return cursor.fetchone()

# --- ROUTES ---

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user_data: RegisterModel):
    hashed_pwd = pwd_context.hash(user_data.password)
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, phone, hashed_password) VALUES (?, ?, ?)",
                (user_data.username, user_data.phone, hashed_pwd)
            )
            conn.commit()
        return {"message": "User registered successfully!"}
        
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400, 
            detail="Username or phone number already registered."
        )

@app.post("/login")
def login(login_data: LoginModel):
    user = get_user(login_data.username_or_phone)
    
    # If user doesn't exist, or password hash doesn't match
    if not user or not pwd_context.verify(login_data.password, user[2]):
        raise HTTPException(
            status_code=401, 
            detail="Invalid username/phone or password."
        )
        
    return {
        "message": "Login successful!",
        "user": {
            "username": user[0],
            "phone": user[1]
        }
    }
