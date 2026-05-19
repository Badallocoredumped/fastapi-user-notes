from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import sqlite3
import hashlib
import os
import jwt
import datetime

app = FastAPI()

# Secret key for JWT tokens — override via environment variable in production
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecret123")


# --- Password hashing ---

def _hash_password(password: str) -> str:
    """Return a PBKDF2-HMAC-SHA256 hash with an embedded random salt."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex() + ":" + digest.hex()


def _verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split(":", 1)
    salt = bytes.fromhex(salt_hex)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return digest.hex() == digest_hex


# --- JWT helper ---

def _get_current_user(authorization: str = Header(...)) -> int:
    """Decode Bearer token and return user_id, or raise 401."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization[len("Bearer "):]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return int(payload["user_id"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except (jwt.InvalidTokenError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid token")


# --- Database setup ---

def get_db():
    conn = sqlite3.connect("notes.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


# --- Models ---

class UserCreate(BaseModel):
    username: str
    password: str

class NoteCreate(BaseModel):
    title: str
    content: str


# --- Auth ---

@app.post("/register")
def register(user: UserCreate):
    db = get_db()
    hashed = _hash_password(user.password)
    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (user.username, hashed)
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already exists")
    return {"message": "User created successfully"}


@app.post("/login")
def login(user: UserCreate):
    db = get_db()
    result = db.execute(
        "SELECT id, password FROM users WHERE username = ?",
        (user.username,)
    ).fetchone()

    if not result or not _verify_password(user.password, result[1]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode(
        {"user_id": result[0], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"token": token}


# --- Notes ---

@app.post("/notes")
def create_note(note: NoteCreate, authorization: str = Header(...)):
    user_id = _get_current_user(authorization)
    db = get_db()
    now = str(datetime.datetime.utcnow())
    db.execute(
        "INSERT INTO notes (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
        (user_id, note.title, note.content, now)
    )
    db.commit()
    return {"message": "Note created"}


@app.get("/notes/{user_id}")
def get_notes(user_id: int, authorization: str = Header(...)):
    current_user = _get_current_user(authorization)
    if current_user != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    db = get_db()
    results = db.execute(
        "SELECT * FROM notes WHERE user_id = ?",
        (user_id,)
    ).fetchall()
    return {"notes": results}


@app.get("/notes/search/{keyword}")
def search_notes(keyword: str, authorization: str = Header(...)):
    user_id = _get_current_user(authorization)
    db = get_db()
    results = db.execute(
        "SELECT * FROM notes WHERE user_id = ? AND content LIKE ?",
        (user_id, f"%{keyword}%")
    ).fetchall()
    return {"notes": results}


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, authorization: str = Header(...)):
    user_id = _get_current_user(authorization)
    db = get_db()
    # Ensure the note belongs to the authenticated user
    note = db.execute(
        "SELECT user_id FROM notes WHERE id = ?",
        (note_id,)
    ).fetchone()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")
    if note[0] != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return {"message": "Note deleted"}
