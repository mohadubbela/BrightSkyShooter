from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3
import os
import time

# Use psycopg for remote (modern)
import psycopg
import psycopg.rows

load_dotenv()



# ---------------- CONFIG FROM .ENV ----------------

APP_SECRET = os.environ["APP_SECRET"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

# Hybrid control
DB_LOCAL = os.environ.get("DB_LOCAL", "true").lower() in ["true", "1", "yes"]
DB_FILE = os.environ.get("DB_FILE")
DATABASE_URL = os.environ.get("DATABASE_URL")

# DB_HOST = os.environ["DB_HOST"]
# DB_NAME = os.environ.get("DB_NAME", "postgres")
# DB_USER = os.environ["DB_USER"]
# DB_PASSWORD = os.environ["DB_PASSWORD"]
# DB_PORT = os.environ.get("DB_PORT", "5432")

PAGE_SIZE = int(os.environ.get("PAGE_SIZE", 100))

if DB_LOCAL and not DB_FILE:
    raise ValueError("DB_FILE must be set when DB_LOCAL=true")
if not DB_LOCAL and not DATABASE_URL:
    raise ValueError("DATABASE_URL must be set when DB_LOCAL=false")

app = Flask(__name__, static_folder="static")

@app.before_request
def require_auth_for_api():
    if request.path.startswith('/api/') and not request.path.startswith(('/api/login', '/api/admin')):
        if not session.get("authenticated"):
            return jsonify({"error": "unauthorized", "message": "Please log in"}), 401
        
app.secret_key = APP_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE="Strict"
)

limiter = Limiter(key_func=get_remote_address, app=app)

CORS(app, resources={r"/api/*": {"origins": ["*"]}})

# ---------------- DATABASE CONNECTION ----------------

def get_db():
    if DB_LOCAL:
        # Local SQLite
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn, True  # (conn, is_sqlite)
    else:
        # Remote PostgreSQL
        conn = psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)
        return conn, False


# ---------------- PASSWORD DB (always local) ----------------

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
        # Stronger check
        if not session.get("authenticated"):
            return jsonify({
                "error": "unauthorized",
                "message": "Authentication required. Please log in."
            }), 401  
            
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

# ---------------- HELPERS ----------------

def clean(row, is_sqlite):
    if is_sqlite:
        return {k: (row[k] if row[k] is not None else "") for k in row.keys()}
    else:
        return {k: (v if v is not None else "") for k, v in row.items()}

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

        conn, is_sqlite = get_db()

        if q:
            if is_sqlite:
                cur = conn.cursor()
                cur.execute("""
                    SELECT COUNT(*) as count FROM contacts
                    WHERE Email LIKE ? OR FirstName LIKE ? OR LastName LIKE ? 
                       OR Phone LIKE ? OR Main_Address__c LIKE ?
                """, (like, like, like, like, like))
                total = cur.fetchone()[0]

                cur.execute("""
                    SELECT id, Email, FirstName, LastName, Phone, Birthdate, Main_Address__c
                    FROM contacts
                    WHERE Email LIKE ? OR FirstName LIKE ? OR LastName LIKE ? 
                       OR Phone LIKE ? OR Main_Address__c LIKE ?
                    LIMIT ? OFFSET ?
                """, (like, like, like, like, like, PAGE_SIZE, offset))
            else:
                cur = conn.cursor()
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
            if is_sqlite:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) as count FROM contacts")
                total = cur.fetchone()[0]
                cur.execute("""
                    SELECT id, Email, FirstName, LastName, Phone, Birthdate, Main_Address__c
                    FROM contacts LIMIT ? OFFSET ?
                """, (PAGE_SIZE, offset))
            else:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) as count FROM contacts")
                total = cur.fetchone()["count"]
                cur.execute("""
                    SELECT id, "Email", "FirstName", "LastName", "Phone", "Birthdate", "Main_Address__c"
                    FROM contacts LIMIT %s OFFSET %s
                """, (PAGE_SIZE, offset))

        rows = cur.fetchall()

        return jsonify({
            "results": [clean(r, is_sqlite) for r in rows],
            "total": total,
            "offset": offset,
            "page_size": PAGE_SIZE
        })

    except Exception as e:
        import traceback
        print("🔥 SEARCH ERROR:", repr(e))
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

    finally:
        if conn:
            conn.close()



# ---------------- CONTACT DETAILS ----------------

@app.route("/api/contact/<id>")
@login_required
def contact(id):
    conn = None
    try:
        conn, is_sqlite = get_db()

        if is_sqlite:
            cur = conn.cursor()
            cur.execute("SELECT * FROM contacts WHERE id = ?", (id,))
        else:
            cur = conn.cursor()
            cur.execute('SELECT * FROM contacts WHERE id = %s', (id,))

        row = cur.fetchone()
        if not row:
            return jsonify({"error": "not found"}), 404

        return jsonify(clean(row, is_sqlite))

    except Exception as e:
        print("🔥 CONTACT ERROR:", repr(e))
        return jsonify({"error": str(e)}), 500
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
    print(f"🚀 BrightSky Intelligence started | DB_LOCAL = {DB_LOCAL}")
    if DB_LOCAL:
        print(f"   📁 Using Local SQLite: {DB_FILE}")
    else:
        print(f"   🌐 Using Remote Database")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
