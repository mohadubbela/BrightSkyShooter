from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from dotenv import load_dotenv
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

import sqlite3
import re
import os
import time

load_dotenv()

APP_SECRET = os.environ["APP_SECRET"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


app = Flask(__name__, static_folder="static")
app.secret_key = APP_SECRET


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,  # True when using HTTPS
    SESSION_COOKIE_SAMESITE="Strict"
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app
)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "https://subcommittee-buy-quickly-latin.trycloudflare.com/"
            ]
        }
    }
)

# ---------------- CONFIG ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_FILE = os.path.join(BASE_DIR, "data", "contacts.db")
PASSWORD_DB = os.path.join(BASE_DIR, "data", "passwords.db")
PAGE_SIZE = 100

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "unauthorized"}), 403
        return f(*args, **kwargs)
    return wrapper



# ---------------- PASSWORD DATABASE ----------------

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


# ---------------- ADMIN LOGIN ----------------

@limiter.limit("5 per minute")
@app.route("/api/admin_login", methods=["POST"])
def admin_login():

    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"success": False, "error": "Missing password"}), 400

    if data["password"] == ADMIN_PASSWORD:
        session["admin_authenticated"] = True
        return jsonify({"success": True})

    return jsonify({"success": False, "error": "Incorrect admin password"}), 401

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify({"error": "unauthorized"}), 403
        return f(*args, **kwargs)
    return wrapper


# ---------------- USER LOGIN ----------------

@limiter.limit("5 per minute")
@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({"success": False, "error": "Missing password"}), 400

    pw = data["password"]

    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()

    cur.execute(
        "SELECT password_hash, expires FROM passwords"
    )

    rows = cur.fetchall()

    match = None

    for password_hash, expires in rows:
        if check_password_hash(password_hash, pw):
            match = expires
            break

    conn.close()

    if match is None:
        return jsonify({"success": False, "error": "Incorrect password"}), 401

    expires = match


    if expires and time.time() > expires:
        return jsonify({"success": False, "error": "Password expired"}), 401

    session["authenticated"] = True

    return jsonify({"success": True})


def is_authenticated():
    return session.get("authenticated", False)


# ---------------- ADMIN PASSWORD MANAGEMENT ----------------

@app.route("/api/passwords")
@admin_required
def get_passwords():

    if not session.get("admin_authenticated"):
        return jsonify({"error": "unauthorized"}), 403

    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash, expires FROM passwords")
    rows = cur.fetchall()

    data = []

    for id, password_hash, e in rows:

        if e:
            remaining = int((e - time.time()) / 3600)
            expires = f"{remaining} hours"
        else:
            expires = "Never"

        data.append({
            "id": id,
            "label": f"Password #{id}",
            "expires": expires
        })

    return jsonify(data)

# ---------------- ADD PASSWORD ----------------
@app.route("/api/add_password", methods=["POST"])
@admin_required
def add_password():

    if not session.get("admin_authenticated"):
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json()

    pw = data["password"]
    minutes = data.get("minutes")

    expires = None

    if minutes:
        expires = int(time.time()) + int(minutes) * 3600

    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()

    hashed = generate_password_hash(pw)

    cur.execute(
        "INSERT INTO passwords (password_hash, expires) VALUES (?, ?)",
        (hashed, expires)
    )

    conn.commit()
    conn.close()

    return jsonify({"success": True})

# ---------------- REMOVE PASSWORD ----------------

@app.route("/api/remove_password", methods=["POST"])
@admin_required
def remove_password():

    data = request.get_json()

    if not data or "id" not in data:
        return jsonify({"error": "Missing id"}), 400

    pw_id = data["id"]


    conn = sqlite3.connect(PASSWORD_DB)
    cur = conn.cursor()

    cur.execute("DELETE FROM passwords WHERE id=?", (pw_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

# ---------------- CLEAN HTML ----------------

def clean_html(text):

    if not text:
        return ""

    text = re.sub(r"<br\s*/?>", ", ", text)
    text = re.sub(r"<.*?>", "", text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ---------------- CONTACT DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")

    return conn


def init_search_index():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    cur.execute("""
    CREATE VIRTUAL TABLE IF NOT EXISTS contacts_fts
    USING fts5(
        Id,
        Name,
        LastName,
        FirstName,
        Email,
        Phone,
        Main_Address__c
    )
    """)

    cur.execute("SELECT count(*) FROM contacts_fts")
    count = cur.fetchone()[0]

    if count == 0:
        print("Building search index...")

        cur.execute("""
        INSERT INTO contacts_fts
        SELECT
            Id,
            Name,
            LastName,
            FirstName,
            Email,
            Phone,
            Main_Address__c
        FROM contacts
        """)

        conn.commit()
        print("Search index ready.")

    conn.close()

init_search_index()

# ---------------- HOMEPAGE ----------------

@app.route("/")
def home():
    return app.send_static_file("index.html")


@app.route("/admin")
def admin_page():
    return app.send_static_file("admin.html")



# ---------------- SEARCH API ----------------

@limiter.limit("20 per minute")
@app.route("/api/search")
@login_required
def search():

    try:

        q = request.args.get("q", "").strip()

        if not q:
            return jsonify({"error": "Search required"}), 400

        offset = max(int(request.args.get("offset", 0)), 0)

        conn = get_db()
        cur = conn.cursor()

        if q:

            # First try full-text search (FTS)
            cur.execute(
                "SELECT COUNT(*) FROM contacts_fts WHERE contacts_fts MATCH ?",
                (q,)
            )
            total = cur.fetchone()[0]

            cur.execute("""
            SELECT
                c.Id,
                c.Name,
                c.LastName,
                c.FirstName,
                c.Email,
                c.Phone,
                c.Birthdate,
                c.Main_Address__c
            FROM contacts c
            JOIN contacts_fts fts ON c.Id = fts.Id
            WHERE contacts_fts MATCH ?
            LIMIT ? OFFSET ?
            """, (q, PAGE_SIZE, offset))

            # If FTS found nothing, try a fallback substring search against the address
            if total == 0:
                like_q = f"%{q}%"
                cur.execute(
                    "SELECT COUNT(*) FROM contacts WHERE Main_Address__c LIKE ? COLLATE NOCASE",
                    (like_q,)
                )
                total = cur.fetchone()[0]

                cur.execute("""
                SELECT
                    Id,
                    Name,
                    LastName,
                    FirstName,
                    Email,
                    Phone,
                    Birthdate,
                    Main_Address__c
                FROM contacts
                WHERE Main_Address__c LIKE ? COLLATE NOCASE
                LIMIT ? OFFSET ?
                """, (like_q, PAGE_SIZE, offset))

        else:

            cur.execute("SELECT COUNT(*) FROM contacts")
            total = cur.fetchone()[0]

            cur.execute("""
            SELECT
                Id,
                Name,
                LastName,
                FirstName,
                Email,
                Phone,
                Birthdate,
                Main_Address__c
            FROM contacts
            LIMIT ? OFFSET ?
            """, (PAGE_SIZE, offset))

        rows = cur.fetchall()

        results = []

        for r in rows:

            results.append({
                "id": r["Id"],
                "name": r["Name"] or "",
                "lastname": r["LastName"] or "",
                "firstname": r["FirstName"] or "",
                "email": r["Email"] or "",
                "phone": r["Phone"] or "",
                "birthdate": r["Birthdate"] or "",
                "address": clean_html(r["Main_Address__c"])
            })

        conn.close()

        return jsonify({
            "results": results,
            "total": total,
            "offset": offset,
            "page_size": PAGE_SIZE
        })

    except Exception as e:
        print("Search error:", e)
        return jsonify({"error": "Search failed"}), 500
    
# ---------------- CONTACT DETAILS ----------------

@app.route("/api/contact/<id>")
@login_required
def contact(id):

    try:

        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT * FROM contacts WHERE Id = ?", (id,))
        row = cur.fetchone()

        if not row:
            return jsonify({"error": "Not found"}), 404

        data = dict(row)

        conn.close()

        return jsonify(data)

    except Exception as e:

        return jsonify({"error": str(e)}), 500


# ---------------- START SERVER ----------------



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))