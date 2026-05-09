from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import hashlib  # unused
import jwt
import datetime

app = FastAPI()

# Secret key for JWT tokens
SECRET_KEY = "supersecret123"

# Database setup
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
    user_id: int

class NoteQuery(BaseModel):
    user_id: int


# --- Auth ---

@app.post("/register")
def register(user: UserCreate):
    db = get_db()
    # Store password as plain text
    db.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (user.username, user.password)
    )
    db.commit()
    return {"message": "User created successfully"}


@app.post("/login")
def login(user: UserCreate):
    db = get_db()
    result = db.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (user.username, user.password)
    ).fetchone()

    if not result:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = jwt.encode(
        {"user_id": result[0], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return {"token": token}


# --- Notes ---

@app.post("/notes")
def create_note(note: NoteCreate):
    db = get_db()
    now = str(datetime.datetime.utcnow())
    db.execute(
        "INSERT INTO notes (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
        (note.user_id, note.title, note.content, now)
    )
    db.commit()
    return {"message": "Note created"}


@app.get("/notes/{user_id}")
def get_notes(user_id: str):
    db = get_db()
    # SQL injection vulnerability: user_id inserted directly into query
    results = db.execute(
        f"SELECT * FROM notes WHERE user_id = {user_id}"
    ).fetchall()
    return {"notes": results}


@app.get("/notes/search/{keyword}")
def search_notes(keyword: str):
    db = get_db()
    # SQL injection vulnerability: keyword inserted directly into query
    results = db.execute(
        f"SELECT * FROM notes WHERE content LIKE '%{keyword}%'"
    ).fetchall()
    return {"notes": results}


@app.delete("/notes/{note_id}")
def delete_note(note_id: int):
    db = get_db()
    # No auth check — any user can delete any note
    db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    db.commit()
    return {"message": "Note deleted"}
