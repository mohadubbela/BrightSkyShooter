from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg
import psycopg.rows

import sqlite3
import os
import time

load_dotenv()

# ---------------- CONFIG ----------------

APP_SECRET = os.environ["APP_SECRET"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

DB_HOST = os.environ["DB_HOST"]
DB_NAME = os.environ.get("DB_NAME", "postgres")
DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DB_PORT = os.environ.get("DB_PORT", "5432")

PAGE_SIZE = 100

app = Flask(__name__, static_folder="static")
app.secret_key = APP_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Strict"
)

limiter = Limiter(key_func=get_remote_address, app=app)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "https://brightskyshooter.onrender.com"
            ]
        }
    }
)

# ---------------- POSTGRES ----------------

def get_pg():
    return psycopg.connect(
        os.environ["DATABASE_URL"],
        row_factory=psycopg.rows.dict_row
    )

# ---------------- PASSWORD DB (SQLite kept) ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PASSWORD_DB = os.path.join(BASE_DIR, "data", "passwords.db")

os.makedirs(os.path.dirname(PASSWORD_DB), exist_ok=True)

def init_password_db():
    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL,
        expires INTEGER
    )
    """)

    conn.commit()
    conn.close()

init_password_db()

# ---------------- AUTH ----------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "unauthorized"}), 403
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify({"error": "unauthorized"}), 403
        return f(*args, **kwargs)
    return wrapper

# ---------------- LOGIN ----------------

@limiter.limit("5 per minute")
@app.route("/api/admin_login", methods=["POST"])
def admin_login():
    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"success": False}), 400

    if data["password"] == ADMIN_PASSWORD:
        session["admin_authenticated"] = True
        return jsonify({"success": True})

    return jsonify({"success": False}), 401


@limiter.limit("5 per minute")
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"success": False}), 400

    pw = data["password"]

    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()
    cur.execute("SELECT password_hash, expires FROM passwords")
    rows = cur.fetchall()
    conn.close()

    for h, exp in rows:
        if check_password_hash(h, pw):

            if exp and time.time() > exp:
                return jsonify({"success": False, "error": "expired"}), 401

            session["authenticated"] = True
            return jsonify({"success": True})

    return jsonify({"success": False}), 401

# ---------------- PASSWORD CRUD ----------------

@app.route("/api/passwords")
@admin_required
def get_passwords():
    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, expires FROM passwords")
    rows = cur.fetchall()
    conn.close()

    return jsonify([
        {"id": r[0], "expires": r[2]} for r in rows
    ])


@app.route("/api/add_password", methods=["POST"])
@admin_required
def add_password():
    data = request.get_json()

    pw = data["password"]
    minutes = data.get("minutes")

    expires = int(time.time()) + int(minutes) * 3600 if minutes else None

    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO passwords (password_hash, expires) VALUES (?, ?)",
        (generate_password_hash(pw), expires)
    )

    conn.commit()
    conn.close()

    return jsonify({"success": True})


@app.route("/api/remove_password", methods=["POST"])
@admin_required
def remove_password():
    data = request.get_json()

    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM passwords WHERE id=?", (data["id"],))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

# ---------------- HELPERS ----------------

@app.route("/api/db_test")
def db_test():
    try:
        print("🔌 Attempting DB connection...")

        conn = get_pg()
        cur = conn.cursor()

        cur.execute("SELECT 1")
        result = cur.fetchone()

        conn.close()

        print("✅ DB connection successful")

        return jsonify({
            "success": True,
            "message": "Database connected successfully",
            "result": result
        })

    except Exception as e:
        import traceback

        print("🔥 DB CONNECTION FAILED:")
        print(repr(e))
        traceback.print_exc()

        return jsonify({
            "success": False,
            "error": str(e),
            "type": type(e).__name__
        }), 500

def clean(r):
    return {k: (v if v is not None else "") for k, v in r.items()}

# ---------------- SEARCH (POSTGRES) ----------------

@app.route("/api/search")
@login_required
def search():
    try:
        print("➡️ SEARCH HIT")

        print("SESSION:", dict(session))  # ✅ SAFE (inside request)

        q = request.args.get("q", "").strip()
        offset = int(request.args.get("offset", 0))

        print("q =", q)
        print("offset =", offset)

        conn = get_pg()
        print("DB CONNECTED")

        cur = conn.cursor()
        cur.execute("SELECT 1")
        print("QUERY OK")

        return jsonify({"ok": True})

    except Exception as e:
        import traceback
        traceback.print_exc()

        return jsonify({
            "error": str(e),
            "type": type(e).__name__
        }), 500

# ---------------- CONTACT ----------------

@app.route("/api/contact/<id>")
@login_required
def contact(id):

    conn = get_pg()
    cur = conn.cursor()

    cur.execute("SELECT * FROM contacts WHERE id = %s", (id,))
    row = cur.fetchone()

    conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404

    return jsonify(clean(row))

# ---------------- HOME ----------------

@app.route("/")
def home():
    return app.send_static_file("index.html")


@app.route("/admin")
def admin():
    return app.send_static_file("admin.html")

# ---------------- START ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
