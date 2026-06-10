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
DATABASE_URL = os.environ["DATABASE_URL"]   # Must be set

PAGE_SIZE = 100

app = Flask(__name__, static_folder="static")
app.secret_key = APP_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Strict"
)

limiter = Limiter(key_func=get_remote_address, app=app)

CORS(app, resources={r"/api/*": {"origins": ["*"]}})

# ---------------- DATABASE ----------------

def get_db():
    return psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)

# ---------------- PASSWORD DB (local) ----------------

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
            return jsonify({"error": "unauthorized", "message": "Please log in"}), 401
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

# ---------------- SEARCH ----------------

@limiter.limit("20 per minute")
@app.route("/api/search")
@login_required
def search():
    conn = None
    try:
        q = request.args.get("q", "").strip()
        offset = max(int(request.args.get("offset", 0)), 0)
        like = f"%{q}%"

        conn = get_db()
        cur = conn.cursor()

        if q:
            cur.execute("""
                SELECT COUNT(*) as count FROM contacts
                WHERE "Email" ILIKE %s OR "FirstName" ILIKE %s OR "LastName" ILIKE %s 
                   OR "Phone" ILIKE %s OR "Main_Address__c" ILIKE %s
            """, (like, like, like, like, like))
            total = cur.fetchone()["count"]

            cur.execute("""
                SELECT id, "Email", "FirstName", "LastName", "Phone", "Birthdate", "Main_Address__c"
                FROM contacts
                WHERE "Email" ILIKE %s OR "FirstName" ILIKE %s OR "LastName" ILIKE %s 
                   OR "Phone" ILIKE %s OR "Main_Address__c" ILIKE %s
                LIMIT %s OFFSET %s
            """, (like, like, like, like, like, PAGE_SIZE, offset))
        else:
            cur.execute("SELECT COUNT(*) as count FROM contacts")
            total = cur.fetchone()["count"]
            cur.execute("""
                SELECT id, "Email", "FirstName", "LastName", "Phone", "Birthdate", "Main_Address__c"
                FROM contacts LIMIT %s OFFSET %s
            """, (PAGE_SIZE, offset))

        rows = cur.fetchall()

        return jsonify({
            "results": [{k: (v if v is not None else "") for k, v in r.items()} for r in rows],
            "total": total,
            "offset": offset,
            "page_size": PAGE_SIZE
        })

    except Exception as e:
        print("Search error:", e)
        return jsonify({"error": "Database error"}), 500
    finally:
        if conn:
            conn.close()

# ---------------- CONTACT DETAILS ----------------

@app.route("/api/contact/<id>")
@login_required
def contact(id):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM contacts WHERE id = %s', (id,))
        row = cur.fetchone()

        if not row:
            return jsonify({"error": "not found"}), 404

        return jsonify({k: (v if v is not None else "") for k, v in row.items()})

    except Exception as e:
        print("Contact error:", e)
        return jsonify({"error": "Database error"}), 500
    finally:
        if conn:
            conn.close()

# ---------------- STATIC ----------------

@app.route("/")
def home():
    return app.send_static_file("index.html")

@app.route("/admin")
def admin():
    return app.send_static_file("admin.html")

# ---------------- START ----------------

if __name__ == "__main__":
    print("🚀 BrightSky Intelligence - Remote Database Mode")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
