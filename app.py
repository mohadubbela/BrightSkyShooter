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

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

# SECURITY FIX #1: Admin password should be hashed, not stored in plaintext
# Store the hash of the admin password instead
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
if not ADMIN_PASSWORD_HASH:
    raise ValueError("ADMIN_PASSWORD_HASH environment variable not set (use generate_password_hash() to create)")

PAGE_SIZE = 100
MAX_EXPIRY_MINUTES = 525600  # 1 year
MIN_PASSWORD_LENGTH = 8

app = Flask(__name__, static_folder="static")
app.secret_key = APP_SECRET

# SECURITY FIX #2: Enable SECURE flag for production (HTTPS only)
# Also set proper session timeout
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",  # True in production
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour session timeout
    SESSION_REFRESH_EACH_REQUEST=True
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Global rate limit
    storage_uri="memory://"
)

# SECURITY FIX #3: Restrict CORS to specific origins in production
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(",")
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})

# ================= INPUT VALIDATION =================

def validate_password_input(password):
    """Validate password strength"""
    if not isinstance(password, str):
        return False, "Password must be a string"
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > 256:
        return False, "Password must be at most 256 characters"
    return True, None

def validate_expiry_minutes(minutes):
    """Validate expiry time input"""
    if minutes is None:
        return True, None
    try:
        minutes = int(minutes)
    except (ValueError, TypeError):
        return False, "Expiry minutes must be an integer"
    
    if minutes <= 0:
        return False, "Expiry minutes must be positive"
    if minutes > MAX_EXPIRY_MINUTES:
        return False, f"Expiry minutes cannot exceed {MAX_EXPIRY_MINUTES}"
    return True, None

def validate_id_input(id_value):
    """Validate that id is a valid integer"""
    try:
        int_id = int(id_value)
        if int_id <= 0:
            return False, "ID must be a positive integer"
        return True, int_id
    except (ValueError, TypeError):
        return False, "Invalid ID format"

def sanitize_search_term(term, max_length=100):
    """Sanitize search terms to prevent resource exhaustion"""
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
    """Get database connection with proper error handling"""
    try:
        return psycopg.connect(DATABASE_URL, row_factory=psycopg.rows.dict_row)
    except psycopg.Error as e:
        logger.error(f"Database connection failed: {type(e).__name__}")
        raise

# ================= PASSWORD DB =================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PASSWORD_DB = os.path.join(BASE_DIR, "data", "passwords.db")

os.makedirs(os.path.dirname(PASSWORD_DB), exist_ok=True)

def init_password_db():
    """Initialize password database with proper schema"""
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
        # SECURITY FIX #4: Add index for faster queries
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_expires ON passwords(expires)
        """)
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Password DB initialization failed: {e}")
        raise

init_password_db()

# ================= AUTH DECORATORS =================

def login_required(f):
    """Require authenticated user session"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "unauthorized", "message": "Please log in"}), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    """Require admin authenticated session"""
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
    """Admin login with hashed password comparison"""
    try:
        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"success": False, "error": "Missing password"}), 400
        
        password = data.get("password", "")
        
        # SECURITY FIX #5: Use check_password_hash instead of plaintext comparison
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session.permanent = True
            session["admin_authenticated"] = True
            logger.info(f"Admin login successful from {get_remote_address()}")
            return jsonify({"success": True})
        
        logger.warning(f"Failed admin login attempt from {get_remote_address()}")
        return jsonify({"success": False}), 401
    except Exception as e:
        logger.error(f"Admin login error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500


@limiter.limit("5 per minute")
@app.route("/api/login", methods=["POST"])
def login():
    """User login with password validation"""
    try:
        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"success": False}), 400

        pw = data["password"]
        current_time = time.time()
        
        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute("SELECT password_hash, expires FROM passwords WHERE expires IS NULL OR expires > ?", (int(current_time),))
        rows = cur.fetchall()
        conn.close()

        for h, exp in rows:
            if check_password_hash(h, pw):
                # SECURITY FIX #6: Verify expiry before creating session
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

@limiter.limit("10 per minute")  # SECURITY FIX #7: Add rate limiting
@app.route("/api/passwords")
@admin_required
def get_passwords():
    """Get all passwords (admin only)"""
    try:
        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        cur.execute("SELECT id, expires, created_at FROM passwords ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        
        return jsonify([{
            "id": r[0], 
            "expires": r[1],
            "created_at": r[2]
        } for r in rows])
    except sqlite3.Error as e:
        logger.error(f"Get passwords error: {e}")
        return jsonify({"error": "Database error"}), 500


@limiter.limit("10 per minute")  # SECURITY FIX #7: Add rate limiting
@app.route("/api/add_password", methods=["POST"])
@admin_required
def add_password():
    """Add a new access password with validation"""
    try:
        data = request.get_json()
        
        # SECURITY FIX #8: Validate all inputs
        if not data or "password" not in data:
            return jsonify({"error": "Missing password field"}), 400
        
        pw = data["password"]
        valid, error_msg = validate_password_input(pw)
        if not valid:
            return jsonify({"error": error_msg}), 400
        
        minutes = data.get("minutes")
        valid, error_msg = validate_expiry_minutes(minutes)
        if not valid:
            return jsonify({"error": error_msg}), 400
        
        # SECURITY FIX #9: Fix expiry calculation (was *3600, should be *60)
        expires = int(time.time()) + minutes * 60 if minutes else None
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
    except sqlite3.Error as e:
        logger.error(f"Add password error: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logger.error(f"Add password error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500


@limiter.limit("10 per minute")  # SECURITY FIX #7: Add rate limiting
@app.route("/api/remove_password", methods=["POST"])
@admin_required
def remove_password():
    """Remove a password by ID with validation"""
    try:
        data = request.get_json()
        
        # SECURITY FIX #10: Validate ID input
        if not data or "id" not in data:
            return jsonify({"error": "Missing id field"}), 400
        
        valid, id_value = validate_id_input(data["id"])
        if not valid:
            return jsonify({"error": id_value}), 400
        
        conn = sqlite3.connect(PASSWORD_DB)
        cur = conn.cursor()
        
        # Verify password exists before deletion
        cur.execute("SELECT id FROM passwords WHERE id = ?", (id_value,))
        if not cur.fetchone():
            conn.close()
            return jsonify({"error": "Password not found"}), 404
        
        cur.execute("DELETE FROM passwords WHERE id = ?", (id_value,))
        conn.commit()
        conn.close()
        
        logger.info(f"Password ID {id_value} removed by admin from {get_remote_address()}")
        return jsonify({"success": True})
    except sqlite3.Error as e:
        logger.error(f"Remove password error: {e}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logger.error(f"Remove password error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500

# ================= SEARCH ENDPOINT =================

@limiter.limit("20 per minute")
@app.route("/api/search")
@login_required
def search():
    """Search contacts with improved security and validation"""
    conn = None
    try:
        q = request.args.get("q", "").strip()
        offset = max(int(request.args.get("offset", 0)), 0)

        # SECURITY FIX #11: Validate offset to prevent resource exhaustion
        if offset < 0 or offset > 1000000:
            return jsonify({"error": "Invalid offset"}), 400

        conn = get_db()
        cur = conn.cursor()

        if not q:
            # No search query → return simple alphabetical paginated list
            cur.execute("SELECT COUNT(*) as count FROM contacts")
            total = cur.fetchone()["count"]

            cur.execute("""
                SELECT id, "Email", "FirstName", "LastName", "Phone", "Birthdate", 
                       "Main_Address__c"
                FROM contacts 
                ORDER BY "FirstName" ASC, "LastName" ASC
                LIMIT %s OFFSET %s
            """, (PAGE_SIZE, offset))

        else:
            # SECURITY FIX #12: Sanitize search terms to prevent resource exhaustion
            terms = []
            for term in q.split():
                sanitized = sanitize_search_term(term)
                if sanitized:
                    terms.append(sanitized)
            
            if not terms:
                return jsonify({
                    "results": [], 
                    "total": 0, 
                    "offset": offset, 
                    "page_size": PAGE_SIZE
                })

            # SECURITY FIX #13: Limit number of search terms
            if len(terms) > 10:
                return jsonify({"error": "Too many search terms (max 10)"}), 400

            # Build WHERE conditions - each term must appear somewhere (AND logic)
            conditions = []
            params = []
            for term in terms:
                like = f"%{term}%"
                conditions.append("""
                    ("FirstName" ILIKE %s OR "LastName" ILIKE %s 
                     OR "Email" ILIKE %s OR "Phone" ILIKE %s OR "Main_Address__c" ILIKE %s)
                """)
                params.extend([like] * 5)

            where_clause = " AND ".join(conditions)

            # Count total matching records
            cur.execute(f"""
                SELECT COUNT(*) as count FROM contacts
                WHERE {where_clause}
            """, params)
            total = cur.fetchone()["count"]

            # Main search query with improved relevance scoring
            cur.execute(f"""
                SELECT id, "Email", "FirstName", "LastName", "Phone", "Birthdate", 
                       "Main_Address__c"
                FROM contacts
                WHERE {where_clause}
                ORDER BY 
                    CASE 
                        WHEN "FirstName" ILIKE %s OR "LastName" ILIKE %s THEN 200
                        WHEN ("FirstName" || ' ' || "LastName") ILIKE %s THEN 150
                        WHEN "Email" ILIKE %s THEN 100
                        WHEN "Main_Address__c" ILIKE %s THEN 60
                        ELSE 10
                    END DESC,
                    "FirstName" ASC, 
                    "LastName" ASC,
                    id ASC
                LIMIT %s OFFSET %s
            """, 
            params + [
                f"%{terms[0]}%", f"%{terms[0]}%",
                f"%{q}%",
                f"%{q}%",
                f"%{q}%",
                PAGE_SIZE, offset
            ])

        rows = cur.fetchall()

        return jsonify({
            "results": [{k: (v if v is not None else "") for k, v in r.items()} for r in rows],
            "total": total,
            "offset": offset,
            "page_size": PAGE_SIZE
        })

    except ValueError as e:
        logger.warning(f"Invalid search parameters: {e}")
        return jsonify({"error": "Invalid parameters"}), 400
    except psycopg.Error as e:
        logger.error(f"Search database error: {type(e).__name__}")
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logger.error(f"Search error: {type(e).__name__}: {str(e)}")
        # SECURITY FIX #14: Don't expose detailed error messages
        return jsonify({"error": "Search failed"}), 500
    finally:
        if conn:
            conn.close()

# ================= CONTACT DETAILS ENDPOINT =================

@app.route("/api/contact/<id>")
@login_required
def contact(id):
    """Get contact details with input validation"""
    conn = None
    try:
        # SECURITY FIX #15: Validate contact ID
        valid, id_value = validate_id_input(id)
        if not valid:
            return jsonify({"error": "Invalid contact ID"}), 400
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM contacts WHERE id = %s', (id_value,))
        row = cur.fetchone()

        if not row:
            return jsonify({"error": "not found"}), 404

        return jsonify({k: (v if v is not None else "") for k, v in row.items()})

    except ValueError:
        return jsonify({"error": "Invalid contact ID"}), 400
    except psycopg.Error as e:
        logger.error(f"Contact database error: {type(e).__name__}")
        # SECURITY FIX #16: Don't expose detailed error messages
        return jsonify({"error": "Database error"}), 500
    except Exception as e:
        logger.error(f"Contact error: {type(e).__name__}")
        return jsonify({"error": "Internal server error"}), 500
    finally:
        if conn:
            conn.close()

# ================= HEALTH CHECK ENDPOINT =================

@app.route("/api/health")
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok"}), 200

# ================= STATIC FILES =================

@app.route("/")
def home():
    return app.send_static_file("index.html")

@app.route("/admin")
@admin_required
def admin():
    """Admin panel - requires authentication"""
    return app.send_static_file("admin.html")

# ================= ERROR HANDLERS =================

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    return jsonify({"error": "Rate limit exceeded"}), 429

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ================= STARTUP =================

if __name__ == "__main__":
    # Security check
    if os.environ.get("FLASK_ENV") == "production":
        if not app.config["SESSION_COOKIE_SECURE"]:
            raise ValueError("FLASK_ENV=production requires HTTPS (SESSION_COOKIE_SECURE must be True)")
    
    print("🚀 BrightSky Intelligence - Secure Mode")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
