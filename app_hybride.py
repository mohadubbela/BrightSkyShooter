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
import psycopg
import psycopg.rows
import logging
import re

load_dotenv()

# ================= SECURITY LOGGING =================
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ================= CONFIG =================
APP_SECRET = os.environ.get("APP_SECRET")
if not APP_SECRET or len(APP_SECRET) < 32:
    raise ValueError("APP_SECRET must be at least 32 characters long")

DB_LOCAL = os.environ.get("DB_LOCAL", "true").lower() in ["true", "1", "yes"]
DB_FILE = os.environ.get("DB_FILE")
DATABASE_URL = os.environ.get("DATABASE_URL")

if DB_LOCAL and not DB_FILE:
    raise ValueError("DB_FILE must be set when DB_LOCAL=true")
if not DB_LOCAL and not DATABASE_URL:
    raise ValueError("DATABASE_URL must be set when DB_LOCAL=false")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise ValueError("ADMIN_PASSWORD environment variable not set")

PAGE_SIZE = int(os.environ.get("PAGE_SIZE", 100))
MAX_EXPIRY_MINUTES = 525600  # 1 year
MIN_PASSWORD_LENGTH = 8

app = Flask(__name__, static_folder="static")
app.secret_key = APP_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    SESSION_COOKIE_SAMESITE="Lax",          # Better compatibility
    PERMANENT_SESSION_LIFETIME=3600,        # 1 hour timeout
    SESSION_REFRESH_EACH_REQUEST=True
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Improved CORS
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5000").split(",")
CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type"],
    methods=["GET", "POST", "OPTIONS"]
)

# ================= INPUT VALIDATION =================
def validate_password_input(password):
    if not isinstance(password, str):
        return False, "Password must be a string"
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > 256:
        return False, "Password must be at most 256 characters"
    return True, None

def validate_expiry_minutes(minutes):
    if minutes is None or minutes == "":
        return True, None
    try:
        minutes = int(minutes)
    except (ValueError, TypeError):
        return False, "Expiry minutes must be an integer"
    if minutes <= 0:
        return False, "Expiry minutes must be positive"
    if minutes > MAX_EXPIRY_MINUTES:
        return False, f"Expiry minutes cannot exceed {MAX_EXPIRY_MINUTES}"
    return True, minutes

def validate_id_input(id_value):
    """Validate ID - supports both numeric and Salesforce-style alphanumeric IDs (15/18 chars)"""
    if not id_value or not isinstance(id_value, (str, int)):
        return False, "Invalid ID format"
    
    id_str = str(id_value).strip()
    if not id_str:
        return False, "ID cannot be empty"
    
    # Salesforce ID format (15 or 18 alphanumeric characters)
    if len(id_str) in (15, 18) and id_str.isalnum():
        return True, id_str
    
    # Fallback: numeric ID
    try:
        int_id = int(id_str)
        if int_id <= 0:
            return False, "ID must be positive"
        return True, int_id
    except (ValueError, TypeError):
        return False, "Invalid ID format"

def sanitize_search_term(term, max_length=100):
    if not isinstance(term, str):
        return None
    term = term.strip()
    if len(term) > max_length:
        return term[:max_length]
    if len(term) == 0:
        return None
    return term

# ================= DATABASE =================
def get_db():
    if DB_LOCAL:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn, True
    else:
        try:
            conn = psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)
            return conn, False
        except psycopg.Error as e:
            logger.error(f"Database connection failed: {type(e).__name__}")
            raise

# ================= PASSWORD DB (always local) =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PASSWORD_DB = os.path.join(BASE_DIR, "data", "passwords.db")
os.makedirs(os.path.dirname(PASSWORD_DB), exist_ok=True)

def init_password_db():
    try:
        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT NOT NULL,
                expires INTEGER,
                created_at INTEGER NOT NULL,
                created_ip TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_expires ON passwords(expires)")
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Password DB initialization failed: {e}")
        raise

init_password_db()

# ================= AUTH DECORATORS =================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "unauthorized", "message": "Please log in"}), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_authenticated"):
            logger.warning(f"Unauthorized admin access attempt from {get_remote_address()}")
            return jsonify({"error": "unauthorized", "message": "Admin access required"}), 403
        return f(*args, **kwargs)
    return wrapper

# ================= LOGIN ENDPOINTS =================
@limiter.limit("5 per minute")
@app.route("/api/admin_login", methods=["POST"])
def admin_login():
    try:
        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"success": False, "error": "Missing password"}), 400

        password = data.get("password", "")
        if password == ADMIN_PASSWORD:
            session.permanent = True
            session["admin_authenticated"] = True
            logger.info(f"Admin login successful from {get_remote_address()}")
            return jsonify({"success": True})

        logger.warning(f"Failed admin login attempt from {get_remote_address()}")
        return jsonify({"success": False}), 401
    except Exception as e:
        logger.error(f"Admin login error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"success": False}), 400

        pw = data["password"]
        current_time = time.time()

        # ✅ Allow admin password directly
        if pw == ADMIN_PASSWORD:
            session.permanent = True
            session["authenticated"] = True
            session["admin_authenticated"] = True  # optional but useful distinction
            return jsonify({"success": True})

        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute(
            "SELECT password_hash, expires FROM passwords WHERE expires IS NULL OR expires > ?",
            (int(current_time),)
        )
        rows = cur.fetchall()
        conn.close()

        for h, exp in rows:
            if check_password_hash(h, pw):
                if exp and current_time > exp:
                    return jsonify({"success": False, "error": "expired"}), 401

                session.permanent = True
                session["authenticated"] = True
                return jsonify({"success": True})

        return jsonify({"success": False}), 401

    except Exception as e:
        logger.error(f"Login error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500

# ================= ADMIN PASSWORD MANAGEMENT =================
@limiter.limit("10 per minute")
@app.route("/api/passwords")
@admin_required
def get_passwords():
    try:
        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute("SELECT id, expires, created_at FROM passwords ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        return jsonify([{"id": r[0], "expires": r[1], "created_at": r[2]} for r in rows])
    except Exception as e:
        logger.error(f"Get passwords error: {e}")
        return jsonify({"error": "Database error"}), 500

@limiter.limit("10 per minute")
@app.route("/api/add_password", methods=["POST"])
@admin_required
def add_password():
    try:
        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"error": "Missing password field"}), 400

        pw = data["password"]
        valid, error_msg = validate_password_input(pw)
        if not valid:
            return jsonify({"error": error_msg}), 400

        minutes = data.get("minutes")
        valid, minutes_int = validate_expiry_minutes(minutes)
        if not valid:
            return jsonify({"error": minutes_int}), 400

        expires = int(time.time()) + minutes_int * 60 if minutes_int else None
        created_at = int(time.time())
        created_ip = get_remote_address()

        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO passwords (password_hash, expires, created_at, created_ip) VALUES (?, ?, ?, ?)",
            (generate_password_hash(pw), expires, created_at, created_ip)
        )
        conn.commit()
        new_id = cur.lastrowid
        conn.close()

        logger.info(f"New password added by admin from {created_ip}")
        return jsonify({"success": True, "id": new_id})
    except Exception as e:
        logger.error(f"Add password error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500

@limiter.limit("10 per minute")
@app.route("/api/remove_password", methods=["POST"])
@admin_required
def remove_password():
    try:
        data = request.get_json()
        if not data or "id" not in data:
            return jsonify({"error": "Missing id field"}), 400

        valid, id_value = validate_id_input(data["id"])
        if not valid:
            return jsonify({"error": id_value}), 400

        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute("SELECT id FROM passwords WHERE id = ?", (id_value,))
        if not cur.fetchone():
            conn.close()
            return jsonify({"error": "Password not found"}), 404

        cur.execute("DELETE FROM passwords WHERE id = ?", (id_value,))
        conn.commit()
        conn.close()

        logger.info(f"Password ID {id_value} removed by admin from {get_remote_address()}")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"Remove password error: {e}")
        return jsonify({"error": "Database error"}), 500

# ================= SEARCH (Hybrid + Smart Routing v2) =================

ZIP_RE = re.compile(r"^[0-9]{4}[A-Za-z]{2}$")
NUMBER_RE = re.compile(r"^\d+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def detect_token_type(term: str):
    if ZIP_RE.match(term):
        return "zip"
    if DATE_RE.match(term):
        return "date"
    if NUMBER_RE.match(term):
        return "number"
    if term.replace(" ", "").isalpha():
        return "name"
    return "text"


def looks_like_address(q: str):
    return any(c.isdigit() for c in q) and any(c.isalpha() for c in q)


def clean_row(r, is_sqlite):
    if is_sqlite:
        return {k: (r[k] if r[k] is not None else "") for k in r.keys()}
    return {k: (v if v is not None else "") for k, v in r.items()}


@limiter.limit("20 per minute")
@app.route("/api/search")
@login_required
def search():
    conn = None
    try:
        q = request.args.get("q", "").strip()
        offset = max(int(request.args.get("offset", 0)), 0)

        if offset < 0 or offset > 1_000_000:
            return jsonify({"error": "Invalid offset"}), 400

        conn, is_sqlite = get_db()
        cur = conn.cursor()

        # =========================
        # 0. EMPTY QUERY (browse)
        # =========================
        if not q:
            if is_sqlite:
                cur.execute("SELECT COUNT(*) FROM contacts")
                total = cur.fetchone()[0]

                cur.execute("""
                    SELECT id, Name, FirstName, LastName, Email, Phone, Birthdate, Main_Address__c
                    FROM contacts
                    ORDER BY FirstName ASC, LastName ASC
                    LIMIT ? OFFSET ?
                """, (PAGE_SIZE, offset))
            else:
                cur.execute("SELECT COUNT(*) as count FROM contacts")
                total = cur.fetchone()["count"]

                cur.execute("""
                    SELECT id, "Name", "FirstName", "LastName", "Email", "Phone", "Birthdate", "Main_Address__c"
                    FROM contacts
                    ORDER BY "FirstName" ASC, "LastName" ASC
                    LIMIT %s OFFSET %s
                """, (PAGE_SIZE, offset))

            rows = cur.fetchall()
            return jsonify({
                "results": [clean_row(r, is_sqlite) for r in rows],
                "total": total,
                "offset": offset,
                "page_size": PAGE_SIZE
            })

        # =========================
        # 1. DIRECT DATE SEARCH (2025-01-13)
        # =========================
        if DATE_RE.match(q):
            if is_sqlite:
                cur.execute("""
                    SELECT * FROM contacts
                    WHERE Birthdate = ?
                    LIMIT 200
                """, (q,))
            else:
                cur.execute("""
                    SELECT * FROM contacts
                    WHERE "Birthdate" = %s
                    LIMIT 200
                """, (q,))

            rows = cur.fetchall()
            return jsonify({
                "results": [clean_row(r, is_sqlite) for r in rows],
                "total": len(rows),
                "offset": offset,
                "page_size": PAGE_SIZE
            })

        # =========================
        # 2. ADDRESS MODE (IMPORTANT FIX)
        # =========================
        if looks_like_address(q):
            like = f"%{q}%"

            if is_sqlite:
                cur.execute("""
                    SELECT * FROM contacts
                    WHERE Main_Address__c LIKE ?
                    LIMIT 200
                """, (like,))
            else:
                cur.execute("""
                    SELECT * FROM contacts
                    WHERE "Main_Address__c" ILIKE %s
                    LIMIT 200
                """, (like,))

            rows = cur.fetchall()
            return jsonify({
                "results": [clean_row(r, is_sqlite) for r in rows],
                "total": len(rows),
                "offset": offset,
                "page_size": PAGE_SIZE
            })

        # =========================
        # 3. TOKENIZE NORMAL SEARCH
        # =========================
        raw_terms = q.split()
        terms = [sanitize_search_term(t) for t in raw_terms]
        terms = [t for t in terms if t]

        if not terms:
            return jsonify({"results": [], "total": 0, "offset": offset, "page_size": PAGE_SIZE})

        if len(terms) > 10:
            return jsonify({"error": "Too many search terms (max 10)"}), 400

        names, numbers, zips, others = [], [], [], []

        for t in terms:
            t_type = detect_token_type(t)
            if t_type == "zip":
                zips.append(t)
            elif t_type == "number":
                numbers.append(t)
            elif t_type == "name":
                names.append(t)
            else:
                others.append(t)

        where_parts = []
        params = []

        # =========================
        # 4. NAME SEARCH (high priority)
        # =========================
        for t in names:
            like = f"%{t}%"
            if is_sqlite:
                where_parts.append("(FirstName LIKE ? OR LastName LIKE ? OR Name LIKE ?)")
                params.extend([like, like, like])
            else:
                where_parts.append('("FirstName" ILIKE %s OR "LastName" ILIKE %s OR "Name" ILIKE %s)')
                params.extend([like, like, like])

        # =========================
        # 5. ZIP SEARCH (exact-ish)
        # =========================
        for z in zips:
            like = f"%{z}%"
            if is_sqlite:
                where_parts.append("Main_Address__c LIKE ?")
                params.append(like)
            else:
                where_parts.append('"Main_Address__c" ILIKE %s')
                params.append(like)

        # =========================
        # 6. HOUSE NUMBER SEARCH (FIXED)
        # =========================
        for n in numbers:
            like1 = f"% {n} %"
            like2 = f"%{n}%"

            if is_sqlite:
                where_parts.append("(Main_Address__c LIKE ? OR Main_Address__c LIKE ?)")
                params.extend([like1, like2])
            else:
                where_parts.append('("Main_Address__c" ILIKE %s OR "Main_Address__c" ILIKE %s)')
                params.extend([like1, like2])

        # =========================
        # 7. FUZZY FALLBACK
        # =========================
        for t in others:
            like = f"%{t}%"
            if is_sqlite:
                where_parts.append("""
                    (Name LIKE ? OR FirstName LIKE ? OR LastName LIKE ?
                     OR Email LIKE ? OR Phone LIKE ? OR Main_Address__c LIKE ?)
                """)
                params.extend([like] * 6)
            else:
                where_parts.append("""
                    ("Name" ILIKE %s OR "FirstName" ILIKE %s OR "LastName" ILIKE %s
                     OR "Email" ILIKE %s OR "Phone" ILIKE %s OR "Main_Address__c" ILIKE %s)
                """)
                params.extend([like] * 6)

        where_clause = " AND ".join(where_parts) if where_parts else "1=1"

        # =========================
        # 8. COUNT
        # =========================
        if is_sqlite:
            cur.execute(f"SELECT COUNT(*) FROM contacts WHERE {where_clause}", params)
            total = cur.fetchone()[0]
        else:
            cur.execute(f"SELECT COUNT(*) as count FROM contacts WHERE {where_clause}", params)
            total = cur.fetchone()["count"]

        # =========================
        # 9. FETCH
        # =========================
        if is_sqlite:
            cur.execute(f"""
                SELECT * FROM contacts
                WHERE {where_clause}
                ORDER BY FirstName ASC, LastName ASC
                LIMIT ? OFFSET ?
            """, params + [PAGE_SIZE, offset])
        else:
            cur.execute(f"""
                SELECT * FROM contacts
                WHERE {where_clause}
                ORDER BY "FirstName" ASC, "LastName" ASC
                LIMIT %s OFFSET %s
            """, params + [PAGE_SIZE, offset])

        rows = cur.fetchall()

        return jsonify({
            "results": [clean_row(r, is_sqlite) for r in rows],
            "total": total,
            "offset": offset,
            "page_size": PAGE_SIZE
        })

    except Exception as e:
        logger.error(f"Search error: {type(e).__name__}: {str(e)}")
        return jsonify({"error": "Search failed"}), 500

    finally:
        if conn:
            conn.close()

# ================= CONTACT DETAILS =================
@app.route("/api/contact/<id>")
@login_required
def contact(id):
    """Get contact details with support for Salesforce-style IDs"""
    conn = None
    try:
        # Validate ID (now supports alphanumeric Salesforce IDs)
        valid, id_value = validate_id_input(id)
        if not valid:
            logger.warning(f"Invalid contact ID attempted: {id}")
            return jsonify({"error": "Invalid contact ID"}), 400

        conn, is_sqlite = get_db()
        cur = conn.cursor()

        if is_sqlite:
            cur.execute("SELECT * FROM contacts WHERE id = ?", (id_value,))
        else:
            cur.execute('SELECT * FROM contacts WHERE id = %s', (id_value,))

        row = cur.fetchone()
        if not row:
            logger.warning(f"Contact not found with ID: {id_value}")
            return jsonify({"error": "not found"}), 404

        # Clean the result
        if is_sqlite:
            result = {k: (row[k] if row[k] is not None else "") for k in row.keys()}
        else:
            result = {k: (v if v is not None else "") for k, v in row.items()}

        return jsonify(result)

    except Exception as e:
        logger.error(f"Contact error for ID {id}: {type(e).__name__} - {str(e)}")
        return jsonify({"error": "Database error"}), 500
    finally:
        if conn:
            conn.close()

# ================= HEALTH & STATIC =================
@app.route("/api/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/")
def home():
    return app.send_static_file("index.html")

@app.route("/admin")
@admin_required
def admin():
    return app.send_static_file("admin.html")

# ================= ERROR HANDLERS =================
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded"}), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ================= STARTUP =================
if __name__ == "__main__":
    print(f"🚀 BrightSky Intelligence started | DB_LOCAL = {DB_LOCAL} | Secure Mode")
    if DB_LOCAL:
        print(f"   Local SQLite: {DB_FILE}")
    else:
        print(f"   Remote Database")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
