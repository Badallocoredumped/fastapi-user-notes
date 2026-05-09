# fastapi-user-notes

A simple REST API for managing personal notes, built with FastAPI and SQLite.

## Features

- User registration and login with JWT authentication
- Create, retrieve, and delete notes
- Search notes by keyword

## Setup

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create a new user |
| POST | `/login` | Login and get a JWT token |
| POST | `/notes` | Create a new note |
| GET | `/notes/{user_id}` | Get all notes for a user |
| GET | `/notes/search/{keyword}` | Search notes by keyword |
| DELETE | `/notes/{note_id}` | Delete a note |

## Tech Stack

- [FastAPI](https://fastapi.tiangolo.com/)
- [SQLite](https://www.sqlite.org/)
- [PyJWT](https://pyjwt.readthedocs.io/)
