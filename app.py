"""
In.dl V2 — Backend
All backend logic in a single file as required.
Organized into sections for maintainability.
"""

from flask import Flask, request, jsonify, send_file, send_from_directory, abort
from flask_cors import CORS
import yt_dlp
import os
import shutil
import uuid
import time
import threading
import re
import psycopg2
from psycopg2.extras import RealDictCursor
import jwt
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from supabase import create_client, Client
from collections import defaultdict
from urllib.parse import urlparse
import hashlib

# ==========================================================
# SECTION 1: CONFIGURATION
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Secret Key
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
COOKIE_FILE = os.path.join(BASE_DIR, "cookies.txt")

def get_secret_key():
    """Retrieve secret key from env, file, or generate new one."""
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, 'r') as f:
                return f.read().strip()
        except Exception:
            pass
    return secrets.token_hex(32)

app.config['SECRET_KEY'] = get_secret_key()

# Folders
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# FFmpeg Detection
if os.path.exists(os.path.join(BASE_DIR, "ffmpeg")):
    FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg")
elif shutil.which("ffmpeg"):
    FFMPEG_PATH = shutil.which("ffmpeg")
else:
    FFMPEG_PATH = None

# Concurrency
MAX_CONCURRENT_DOWNLOADS = int(os.environ.get('MAX_WORKERS', 2))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS)
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
job_status = {}
job_ownership = {}  # job_id -> uid or ip

# Database & Supabase
DATABASE_URL = os.environ.get('DATABASE_URL')
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

# Admin Configuration (from environment, not hardcoded)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

supabase_client: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)

supabase_admin: Client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    supabase_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# ==========================================================
# SECTION 2: RATE LIMITING
# ==========================================================

class RateLimiter:
    """Simple in-memory rate limiter by key (IP or UID)."""

    def __init__(self):
        self._store = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key, max_requests, window_seconds):
        now = time.time()
        with self._lock:
            hits = self._store[key]
            # Remove expired entries
            hits[:] = [t for t in hits if now - t < window_seconds]
            if len(hits) >= max_requests:
                return False
            hits.append(now)
            return True

    def cleanup(self):
        """Periodic cleanup of old entries."""
        now = time.time()
        with self._lock:
            keys_to_delete = []
            for key, hits in self._store.items():
                hits[:] = [t for t in hits if now - t < 3600]
                if not hits:
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self._store[key]

rate_limiter = RateLimiter()

# Rate limit constants
INFO_RATE_LIMIT = 20      # requests per window
INFO_RATE_WINDOW = 60     # seconds
DOWNLOAD_RATE_LIMIT = 10  # requests per window
DOWNLOAD_RATE_WINDOW = 60 # seconds
CONTACT_RATE_LIMIT = 3    # requests per window
CONTACT_RATE_WINDOW = 300 # seconds


# ==========================================================
# SECTION 3: DATABASE HELPERS
# ==========================================================

def get_db_connection():
    """Get database connection. PostgreSQL only in production."""
    if not DATABASE_URL:
        import sqlite3
        conn = sqlite3.connect("users.db", timeout=10)
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn, "postgres"

def _ph(db_type):
    """Parameter placeholder for SQL queries."""
    return "%s" if db_type == "postgres" else "?"

def init_db():
    """Initialize database tables and seed admin user."""
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    if db_type == "postgres":
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            tokens INTEGER DEFAULT 15,
            last_reset TIMESTAMP,
            is_admin INTEGER DEFAULT 0,
            plan TEXT DEFAULT 'Free',
            referral_code TEXT UNIQUE,
            referred_by TEXT,
            supabase_uid TEXT UNIQUE,
            auth_provider TEXT DEFAULT 'legacy',
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT NOW(),
            downloads_count INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS guests (
            ip TEXT PRIMARY KEY,
            tokens INTEGER DEFAULT 5,
            last_reset TIMESTAMP,
            supabase_uid TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS payment_requests (
            id SERIAL PRIMARY KEY,
            user_id INTEGER,
            username TEXT,
            plan_name TEXT,
            screenshot_path TEXT,
            status TEXT DEFAULT 'pending',
            timestamp TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            timestamp TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            name TEXT,
            email TEXT,
            message TEXT,
            timestamp TIMESTAMP
        )""")
        conn.commit()
    else:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            tokens INTEGER DEFAULT 15,
            last_reset DATETIME,
            is_admin INTEGER DEFAULT 0,
            plan TEXT DEFAULT 'Free',
            referral_code TEXT UNIQUE,
            referred_by TEXT,
            supabase_uid TEXT UNIQUE,
            auth_provider TEXT DEFAULT 'legacy',
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            downloads_count INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS guests (
            ip TEXT PRIMARY KEY,
            tokens INTEGER DEFAULT 5,
            last_reset DATETIME,
            supabase_uid TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS payment_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            plan_name TEXT,
            screenshot_path TEXT,
            status TEXT DEFAULT 'pending',
            timestamp DATETIME
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            message TEXT,
            timestamp DATETIME
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            timestamp DATETIME
        )""")
        conn.commit()

    # Add missing columns safely
    try:
        if db_type == "postgres":
            for col_def in [
                "ADD COLUMN IF NOT EXISTS referral_code TEXT UNIQUE",
                "ADD COLUMN IF NOT EXISTS referred_by TEXT",
                "ADD COLUMN IF NOT EXISTS email TEXT",
                "ADD COLUMN IF NOT EXISTS supabase_uid TEXT UNIQUE",
                "ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'legacy'",
                "ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'",
                "ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()",
                "ADD COLUMN IF NOT EXISTS downloads_count INTEGER DEFAULT 0"
            ]:
                try:
                    c.execute(f"ALTER TABLE users {col_def}")
                except Exception:
                    pass
            # Add supabase_uid column to guests
            try:
                c.execute("ALTER TABLE guests ADD COLUMN IF NOT EXISTS supabase_uid TEXT")
            except Exception:
                pass
        else:
            c.execute("PRAGMA table_info(users)")
            cols = [info[1] for info in c.fetchall()]
            col_map = {
                "referral_code": "ALTER TABLE users ADD COLUMN referral_code TEXT UNIQUE",
                "referred_by": "ALTER TABLE users ADD COLUMN referred_by TEXT",
                "email": "ALTER TABLE users ADD COLUMN email TEXT",
                "supabase_uid": "ALTER TABLE users ADD COLUMN supabase_uid TEXT UNIQUE",
                "auth_provider": "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'legacy'",
                "status": "ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'",
                "created_at": "ALTER TABLE users ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
                "downloads_count": "ALTER TABLE users ADD COLUMN downloads_count INTEGER DEFAULT 0"
            }
            for col_name, sql in col_map.items():
                if col_name not in cols:
                    try:
                        c.execute(sql)
                    except Exception:
                        pass
        conn.commit()
    except Exception:
        pass

    # Seed admin user from environment variables (NOT hardcoded)
    if ADMIN_USERNAME and ADMIN_PASSWORD:
        try:
            c.execute(f"SELECT * FROM users WHERE username={ph}", (ADMIN_USERNAME,))
            if not c.fetchone():
                hashed = generate_password_hash(ADMIN_PASSWORD)
                c.execute(
                    f"""INSERT INTO users (username, password, tokens, last_reset, is_admin, plan)
                    VALUES ({ph}, {ph}, 999999, {ph}, 1, 'God Mode')""",
                    (ADMIN_USERNAME, hashed, datetime.now())
                )
                conn.commit()
        except Exception:
            pass
    conn.close()

init_db()


# ==========================================================
# SECTION 4: AUTH HELPERS
# ==========================================================

def get_user_from_token(req):
    """Extract user_id from JWT or Supabase token."""
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1]

    # Try legacy JWT first
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded.get('user_id')
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, Exception):
        pass

    # Try Supabase token verification
    if supabase_admin:
        try:
            user_response = supabase_admin.auth.get_user(token)
            if user_response and user_response.user:
                sb_uid = user_response.user.id
                is_anonymous = getattr(user_response.user, 'is_anonymous', False)

                # Map Supabase UID to local user
                conn, db_type = get_db_connection()
                c = conn.cursor()
                ph = _ph(db_type)
                c.execute(f"SELECT id FROM users WHERE supabase_uid={ph}", (sb_uid,))
                row = c.fetchone()
                if row:
                    conn.close()
                    return row['id'] if isinstance(row, dict) else row[0]
                conn.close()

                # Anonymous users get handled by guest credit system
                if is_anonymous:
                    return None  # Treated as guest with UID

                return None
        except Exception:
            pass

    return None


def get_supabase_uid(req):
    """Get Supabase UID from auth token."""
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header.split(" ", 1)[1]

    if supabase_admin:
        try:
            user_response = supabase_admin.auth.get_user(token)
            if user_response and user_response.user:
                return user_response.user.id
        except Exception:
            pass

    return None


def is_admin_request(req):
    """Check if request comes from an admin user."""
    user_id = get_user_from_token(req)
    if not user_id:
        return False
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"SELECT is_admin FROM users WHERE id={ph}", (user_id,))
    row = c.fetchone()
    conn.close()
    return row and row['is_admin'] == 1


def is_banned(ip):
    """Check if IP is banned."""
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"SELECT * FROM banned_ips WHERE ip={ph}", (ip,))
    banned = c.fetchone()
    conn.close()
    return banned is not None


# ==========================================================
# SECTION 5: CREDIT SYSTEM
# ==========================================================

def check_tokens(ip, user_id=None):
    """Check and auto-reset token balance."""
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    now = datetime.now()

    if user_id:
        c.execute(f"SELECT tokens, last_reset, plan FROM users WHERE id={ph}", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return 0, False
        tokens = row['tokens']
        last_reset = row['last_reset']
        plan = row['plan']
    else:
        c.execute(f"SELECT tokens, last_reset FROM guests WHERE ip={ph}", (ip,))
        row = c.fetchone()
        if not row:
            c.execute(
                f"INSERT INTO guests (ip, tokens, last_reset) VALUES ({ph}, 5, {ph})",
                (ip, now)
            )
            conn.commit()
            conn.close()
            return 5, False
        tokens = row['tokens']
        last_reset = row['last_reset']
        plan = "Guest"

    # Parse last_reset
    if isinstance(last_reset, str):
        try:
            last_reset = datetime.strptime(last_reset.split('.')[0], "%Y-%m-%d %H:%M:%S")
        except Exception:
            last_reset = datetime.min

    # Auto-reset if more than 12 hours
    if last_reset and (now - last_reset > timedelta(hours=12)):
        if user_id:
            default_tokens = 15
            c.execute(
                f"UPDATE users SET tokens={ph}, last_reset={ph} WHERE id={ph}",
                (default_tokens, now, user_id)
            )
        else:
            default_tokens = 5
            c.execute(
                f"UPDATE guests SET tokens={ph}, last_reset={ph} WHERE ip={ph}",
                (default_tokens, now, ip)
            )
        conn.commit()
        tokens = default_tokens

    # God Mode = unlimited
    if plan == "God Mode":
        tokens = 999999

    conn.close()
    return tokens, False


def consume_token(ip, user_id=None):
    """Consume one token (credit) from user or guest."""
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    if user_id:
        c.execute(f"UPDATE users SET tokens = tokens - 1, downloads_count = downloads_count + 1 WHERE id={ph}", (user_id,))
    else:
        c.execute(f"UPDATE guests SET tokens = tokens - 1 WHERE ip={ph}", (ip,))

    conn.commit()
    conn.close()


def refund_token(ip, user_id=None):
    """Refund a token on download failure."""
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    if user_id:
        c.execute(f"UPDATE users SET tokens = tokens + 1, downloads_count = downloads_count - 1 WHERE id={ph}", (user_id,))
    else:
        c.execute(f"UPDATE guests SET tokens = tokens + 1 WHERE ip={ph}", (ip,))

    conn.commit()
    conn.close()


# ==========================================================
# SECTION 6: URL VALIDATION
# ==========================================================

INSTAGRAM_PATTERNS = [
    re.compile(r'https?://(www\.)?instagram\.com/(p|reel|reels|stories|tv)/', re.IGNORECASE),
    re.compile(r'https?://(www\.)?instagram\.com/[\w.]+/?$', re.IGNORECASE),
    re.compile(r'https?://instagr\.am/', re.IGNORECASE)
]

def validate_url(url):
    """Validate and sanitize download URL."""
    if not url or not isinstance(url, str):
        return None, "URL is required"

    url = url.strip()

    if len(url) > 2048:
        return None, "URL too long"

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return None, "Invalid URL scheme"
        if not parsed.netloc:
            return None, "Invalid URL"
    except Exception:
        return None, "Invalid URL format"

    # Check against supported patterns
    supported = any(pattern.search(url) for pattern in INSTAGRAM_PATTERNS)
    if not supported:
        return None, "Unsupported URL. Please use an Instagram link."

    return url, None


# ==========================================================
# SECTION 7: MEDIA DETECTION & DOWNLOAD ENGINE
# ==========================================================

def format_bytes(size):
    """Format bytes to human-readable string."""
    if not size:
        return "N/A"
    power = 2 ** 10
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power and n < 4:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"


def safe_float(val):
    """Safely convert to float."""
    try:
        return float(val) if val else 0.0
    except (ValueError, TypeError):
        return 0.0


def detect_media_type(info):
    """Detect Instagram media type from yt-dlp info dict."""
    url = info.get('webpage_url', '')
    title = info.get('title', '').lower()

    if '/reel/' in url or '/reels/' in url:
        return 'reel'
    if '/stories/' in url:
        return 'story'
    if info.get('entries'):
        return 'carousel'
    if info.get('_type') == 'playlist':
        return 'carousel'

    # Check if it's an image (no video formats)
    formats = info.get('formats', [])
    has_video = any(f.get('vcodec', 'none') != 'none' for f in formats)
    if not has_video and formats:
        return 'image'

    if '/p/' in url:
        return 'post'

    return 'video'


def get_video_formats(url):
    """Extract video info and available formats using yt-dlp."""
    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "extract_flat": "in_playlist",
        "http_headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"
        },
        "cookiefile": COOKIE_FILE if os.path.exists(COOKIE_FILE) else None,
        "ffmpeg_location": FFMPEG_PATH
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)

            formats_list = []
            is_insta = 'instagram' in info.get('webpage_url_domain', info.get('extractor', 'youtube'))
            duration = safe_float(info.get('duration'))
            media_type = detect_media_type(info)

            # Audio option (only for video/reel)
            if media_type in ('video', 'reel', 'post') and duration > 0:
                mp3_size = (128 * 1000 * duration) / 8
                formats_list.append({
                    "id": "mp3-128",
                    "type": "audio",
                    "quality": "128kbps",
                    "ext": "mp3",
                    "size": format_bytes(mp3_size)
                })

            if is_insta:
                f_size = safe_float(info.get('filesize') or info.get('filesize_approx'))
                formats_list.insert(0, {
                    "id": "best",
                    "type": "video",
                    "quality": "HD (Best)",
                    "ext": "mp4",
                    "size": format_bytes(f_size)
                })
            else:
                seen_res = set()
                for f in info.get('formats', []):
                    h = f.get('height')
                    if not h or h in seen_res or h < 144:
                        continue
                    seen_res.add(h)
                    if not FFMPEG_PATH and f.get('acodec') == 'none':
                        continue
                    f_size = safe_float(f.get('filesize') or f.get('filesize_approx'))
                    if f_size == 0 and duration > 0:
                        tbr = safe_float(f.get('tbr'))
                        if tbr > 0:
                            f_size = (tbr * 1000 * duration) / 8
                    formats_list.append({
                        "id": f"video-{h}",
                        "type": "video",
                        "quality": f"{h}p",
                        "ext": "mp4",
                        "size": format_bytes(f_size),
                        "height": h
                    })
                formats_list.sort(key=lambda x: x.get('height', 0), reverse=True)

            return {
                "title": info.get("title", "Instagram Media"),
                "thumbnail": info.get("thumbnail", ""),
                "duration": info.get("duration_string", ""),
                "author": info.get("uploader", ""),
                "platform": "Instagram" if is_insta else info.get("extractor", ""),
                "media_type": media_type,
                "formats": formats_list
            }
    except yt_dlp.utils.DownloadError as e:
        error_msg = str(e)
        if "Private" in error_msg or "login" in error_msg.lower():
            return {"error": True, "message": "This content is private or requires login."}
        if "not found" in error_msg.lower() or "404" in error_msg:
            return {"error": True, "message": "Content not found. The URL may be invalid or deleted."}
        return {"error": True, "message": "Failed to extract media info."}
    except Exception:
        return None


def process_download(job_id, url, fmt_id, user_id=None, ip=None):
    """Process download job with semaphore-based concurrency control."""
    with download_semaphore:
        job_status[job_id]["status"] = "downloading"

        def progress_hook(d):
            if d["status"] == "downloading":
                raw_percent = d.get("_percent_str", "0%")
                clean_percent = re.sub(r'\x1b\[[0-9;]*m', '', raw_percent).strip()
                job_status[job_id].update({
                    "percent": clean_percent.replace("%", ""),
                    "speed": d.get("_speed_str", "N/A"),
                    "status": "downloading"
                })
            elif d["status"] == "finished":
                job_status[job_id].update({
                    "status": "processing",
                    "percent": "99",
                    "message": "Processing media..."
                })

        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, f"{job_id}_%(title)s.%(ext)s"),
            "progress_hooks": [progress_hook],
            "quiet": True,
            "concurrent_fragment_downloads": 10,
            "buffersize": 1024 * 1024,
            "http_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            },
            "cookiefile": COOKIE_FILE if os.path.exists(COOKIE_FILE) else None,
            "ffmpeg_location": FFMPEG_PATH,
            "socket_timeout": 30
        }

        # Format selection
        if "mp3" in str(fmt_id):
            ydl_opts["format"] = "bestaudio/best"
            if FFMPEG_PATH:
                ydl_opts["postprocessors"] = [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3"}]
        elif fmt_id == "best":
            ydl_opts["format"] = "best"
        elif "video" in str(fmt_id):
            height = str(fmt_id).replace("video-", "")
            if FFMPEG_PATH:
                ydl_opts["format"] = (
                    f"best[height<={height}]/"
                    f"bestvideo[height<={height}]+bestaudio/"
                    f"best[height<={height}]"
                )
                ydl_opts["merge_output_format"] = "mp4"
            else:
                ydl_opts["format"] = f"best[height<={height}]"
        else:
            ydl_opts["format"] = "best"

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.extract_info(url, download=True)

                # Find the downloaded file
                for f in os.listdir(DOWNLOAD_FOLDER):
                    if f.startswith(job_id):
                        filepath = os.path.join(DOWNLOAD_FOLDER, f)
                        job_status[job_id].update({
                            "status": "completed",
                            "file": filepath,
                            "filename": f,
                            "percent": "100"
                        })
                        return

                raise Exception("Downloaded file not found")
        except Exception as e:
            job_status[job_id].update({
                "status": "error",
                "message": "Download failed. The media may be unavailable.",
                "error": str(e)
            })
            # Refund the credit on failure
            try:
                refund_token(ip, user_id)
            except Exception:
                pass


# ==========================================================
# SECTION 8: API ROUTES — Static & Pages
# ==========================================================

@app.route('/')
def index():
    return send_file('index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files, with fallback to index.html for SPA-like routing."""
    full_path = os.path.join(BASE_DIR, path)

    # Security: prevent path traversal
    real_path = os.path.realpath(full_path)
    real_base = os.path.realpath(BASE_DIR)
    if not real_path.startswith(real_base):
        abort(403)

    if os.path.exists(full_path) and os.path.isfile(full_path):
        return send_from_directory(BASE_DIR, path)

    # Serve 404 page if it exists
    four_oh_four = os.path.join(BASE_DIR, '404.html')
    if os.path.exists(four_oh_four):
        return send_file(four_oh_four), 404

    return send_file('index.html')


# ==========================================================
# SECTION 9: API ROUTES — Auth
# ==========================================================

@app.route("/api/auth/legacy-login", methods=["POST"])
@app.route("/api/login", methods=["POST"])
def login():
    """Legacy username/password login — returns JWT."""
    data = request.json or {}
    username = (data.get("username") or "").lower().strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"SELECT id, password FROM users WHERE username={ph}", (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        token = jwt.encode(
            {'user_id': user['id'], 'exp': datetime.utcnow() + timedelta(hours=24)},
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        return jsonify({"message": "Login success", "token": token}), 200

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/api/auth/legacy-register", methods=["POST"])
@app.route("/api/register", methods=["POST"])
def register():
    """Legacy username/password registration."""
    data = request.json or {}
    username = (data.get("username") or "").lower().strip()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip()

    # Input validation
    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    if len(username) < 3 or len(username) > 30:
        return jsonify({"message": "Username must be 3-30 characters"}), 400

    if not re.match(r'^[a-z0-9_]+$', username):
        return jsonify({"message": "Username: only letters, numbers, underscore"}), 400

    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters"}), 400

    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({"message": "Invalid email format"}), 400

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    ref_code = (username[:4] + secrets.token_hex(2)).upper()
    used_ref = (data.get("referral_code") or "").strip().upper()
    bonus = 0

    try:
        # Check referral
        if used_ref:
            c.execute(f"SELECT id FROM users WHERE referral_code={ph}", (used_ref,))
            referrer = c.fetchone()
            if referrer:
                referrer_id = referrer['id'] if isinstance(referrer, dict) else referrer[0]
                c.execute(f"UPDATE users SET tokens = tokens + 10 WHERE id={ph}", (referrer_id,))
                bonus = 10

        c.execute(
            f"""INSERT INTO users
            (username, email, password, tokens, last_reset, is_admin, plan, referral_code, referred_by)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, 0, 'Free', {ph}, {ph})""",
            (
                username,
                email,
                generate_password_hash(password),
                15 + bonus,
                datetime.now(),
                ref_code,
                used_ref if bonus > 0 else None
            )
        )
        conn.commit()
        return jsonify({
            "message": f"Registered!{' You got +10 credits!' if bonus else ''}",
            "referral_code": ref_code
        }), 201
    except Exception as e:
        error_str = str(e)
        if "UNIQUE constraint" in error_str or "duplicate key" in error_str:
            return jsonify({"message": "Username already taken"}), 409
        return jsonify({"message": "Registration failed"}), 500
    finally:
        conn.close()


@app.route("/api/status", methods=["GET"])
def get_status():
    """Get current user state, credits, and system settings."""
    user_id = get_user_from_token(request)
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    # System settings
    try:
        c.execute(f"SELECT value FROM settings WHERE key={ph}", ('maintenance',))
        m_row = c.fetchone()
        c.execute(f"SELECT value FROM settings WHERE key={ph}", ('announcement',))
        a_row = c.fetchone()
    except Exception:
        m_row, a_row = None, None

    maintenance = m_row['value'] if m_row else 'false'
    announcement = a_row['value'] if a_row else ''

    # User info
    username, is_admin, plan, referral_code = "", False, "Guest", ""
    if user_id:
        c.execute(
            f"SELECT username, is_admin, plan, referral_code FROM users WHERE id={ph}",
            (user_id,)
        )
        row = c.fetchone()
        if row:
            username = row['username']
            is_admin = (row['is_admin'] == 1)
            plan = row['plan']
            referral_code = row.get('referral_code', '') or ''

    conn.close()
    tokens, _ = check_tokens(request.remote_addr, user_id)

    return jsonify({
        "tokens": tokens,
        "is_logged_in": user_id is not None,
        "is_admin": is_admin,
        "username": username,
        "plan": plan,
        "referral_code": referral_code,
        "maintenance": maintenance == 'true',
        "announcement": announcement,
        "supabase_url": SUPABASE_URL,
        "supabase_key": SUPABASE_KEY
    })


# ==========================================================
# SECTION 10: API ROUTES — Download
# ==========================================================

@app.route("/api/info", methods=["POST", "OPTIONS"])
def api_info():
    """Analyze URL and return available formats."""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    ip = request.remote_addr

    # Rate limit
    if not rate_limiter.is_allowed(f"info:{ip}", INFO_RATE_LIMIT, INFO_RATE_WINDOW):
        return jsonify({"error": True, "message": "Too many requests. Please slow down."}), 429

    data = request.json or {}
    url = data.get("url", "")

    # Validate URL
    validated_url, error = validate_url(url)
    if error:
        return jsonify({"error": True, "message": error}), 400

    result = get_video_formats(validated_url)

    if result is None:
        return jsonify({"error": True, "message": "Failed to analyze URL"}), 400

    if result.get("error"):
        return jsonify(result), 400

    return jsonify(result)


@app.route("/api/download", methods=["POST", "OPTIONS"])
def api_download():
    """Start download job."""
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    ip = request.remote_addr

    # Check ban
    if is_banned(ip):
        return jsonify({"error": "BANNED", "message": "Your IP has been banned."}), 403

    # Rate limit
    if not rate_limiter.is_allowed(f"dl:{ip}", DOWNLOAD_RATE_LIMIT, DOWNLOAD_RATE_WINDOW):
        return jsonify({"error": "RATE_LIMITED", "message": "Too many requests. Please wait."}), 429

    # Check maintenance
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"SELECT value FROM settings WHERE key={ph}", ('maintenance',))
    m = c.fetchone()
    conn.close()
    if m and m['value'] == 'true' and not is_admin_request(request):
        return jsonify({"error": "MAINTENANCE", "message": "Server is under maintenance."}), 503

    user_id = get_user_from_token(request)
    tokens_left, _ = check_tokens(ip, user_id)

    if tokens_left <= 0:
        msg = "Daily limit reached (15/15). Upgrade for more!" if user_id else "Guest limit reached (5/5). Sign in for more!"
        return jsonify({"error": "LIMIT_REACHED", "message": msg}), 403

    data = request.json or {}
    url = data.get("url", "")
    fmt_id = data.get("format_id", "best")

    # Validate URL
    validated_url, error = validate_url(url)
    if error:
        return jsonify({"error": "INVALID_URL", "message": error}), 400

    # Consume credit (will refund on failure)
    consume_token(ip, user_id)

    job_id = str(uuid.uuid4())
    job_status[job_id] = {"status": "queued", "percent": "0"}
    job_ownership[job_id] = user_id or ip

    executor.submit(process_download, job_id, validated_url, fmt_id, user_id, ip)

    return jsonify({"job_id": job_id})


@app.route("/api/progress/<job_id>")
def api_progress(job_id):
    """Check download progress."""
    job = job_status.get(job_id)
    if not job:
        return jsonify({"status": "unknown"}), 404
    return jsonify(job)


@app.route("/api/file/<job_id>")
def api_file(job_id):
    """Download completed file."""
    job = job_status.get(job_id)
    if not job or job.get("status") != "completed":
        return jsonify({"error": "File not ready or not found"}), 404

    filepath = job.get("file")
    if not filepath or not os.path.exists(filepath):
        return jsonify({"error": "File has been cleaned up"}), 410

    return send_file(filepath, as_attachment=True, download_name=job.get("filename", "download"))


# ==========================================================
# SECTION 11: API ROUTES — Payment
# ==========================================================

@app.route("/api/payment/request", methods=["POST"])
def pay_req():
    """Submit payment screenshot for admin approval."""
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"error": "Login required"}), 401

    file = request.files.get("screenshot")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    # Validate file type
    allowed_types = {'image/png', 'image/jpeg', 'image/jpg', 'image/webp'}
    if file.content_type not in allowed_types:
        return jsonify({"error": "Only PNG, JPEG, WebP images allowed"}), 400

    # Validate file size (max 5MB)
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    if file_size > 5 * 1024 * 1024:
        return jsonify({"error": "File too large (max 5MB)"}), 400

    filename = secure_filename(f"{user_id}_{int(time.time())}_{file.filename}")
    screenshot_url = ""

    if supabase_client:
        try:
            file_bytes = file.read()
            supabase_client.storage.from_('screenshots').upload(
                filename, file_bytes, {"content-type": file.content_type}
            )
            screenshot_url = supabase_client.storage.from_('screenshots').get_public_url(filename)
        except Exception:
            return jsonify({"error": "Failed to save screenshot. Contact admin."}), 500
    else:
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        screenshot_url = f"/uploads/{filename}"

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"SELECT username FROM users WHERE id={ph}", (user_id,))
    row = c.fetchone()
    username = row['username'] if row else 'unknown'

    plan_name = request.form.get("plan_name", "Unknown")
    c.execute(
        f"""INSERT INTO payment_requests
        (user_id, username, plan_name, screenshot_path, status, timestamp)
        VALUES ({ph}, {ph}, {ph}, {ph}, 'pending', {ph})""",
        (user_id, username, plan_name, screenshot_url, datetime.now())
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Submitted successfully! Awaiting admin approval."})


@app.route("/uploads/<filename>")
def serve_upload(filename):
    """Serve uploaded files (admin only)."""
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403
    safe_name = secure_filename(filename)
    return send_from_directory(UPLOAD_FOLDER, safe_name)


# ==========================================================
# SECTION 12: API ROUTES — Contact
# ==========================================================

@app.route("/api/contact", methods=["POST"])
def contact_submit():
    """Handle contact form submission."""
    ip = request.remote_addr

    # Rate limit contact form
    if not rate_limiter.is_allowed(f"contact:{ip}", CONTACT_RATE_LIMIT, CONTACT_RATE_WINDOW):
        return jsonify({"message": "Too many messages. Please wait."}), 429

    data = request.json or {}
    name = (data.get("name") or "").strip()[:100]
    email = (data.get("email") or "").strip()[:200]
    message = (data.get("message") or "").strip()[:2000]

    if not message:
        return jsonify({"message": "Message cannot be empty"}), 400

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(
        f"INSERT INTO messages (name, email, message, timestamp) VALUES ({ph}, {ph}, {ph}, {ph})",
        (name, email, message, datetime.now())
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "Message sent successfully"})


# ==========================================================
# SECTION 13: ADMIN API ROUTES
# ==========================================================

@app.route("/api/admin/messages", methods=["GET"])
def get_messages():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn, db_type = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM messages ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])


@app.route("/api/admin/message/<int:msg_id>", methods=["DELETE"])
def delete_message(msg_id):
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"DELETE FROM messages WHERE id={ph}", (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})


@app.route("/api/admin/settings", methods=["GET", "POST"])
def manage_settings():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    if request.method == "POST":
        data = request.json or {}
        if db_type == "postgres":
            if "maintenance" in data:
                c.execute(
                    "INSERT INTO settings (key, value) VALUES ('maintenance', %s) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    (str(data['maintenance']).lower(),)
                )
            if "announcement" in data:
                ann_text = str(data['announcement'])[:500]
                c.execute(
                    "INSERT INTO settings (key, value) VALUES ('announcement', %s) "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                    (ann_text,)
                )
        else:
            if "maintenance" in data:
                c.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance', ?)",
                    (str(data['maintenance']).lower(),)
                )
            if "announcement" in data:
                ann_text = str(data['announcement'])[:500]
                c.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('announcement', ?)",
                    (ann_text,)
                )
        conn.commit()

    c.execute(f"SELECT value FROM settings WHERE key={ph}", ('maintenance',))
    m = c.fetchone()
    c.execute(f"SELECT value FROM settings WHERE key={ph}", ('announcement',))
    a = c.fetchone()
    conn.close()

    return jsonify({
        "maintenance": (m['value'] == 'true') if m else False,
        "announcement": a['value'] if a else ""
    })


@app.route("/api/admin/ban", methods=["GET", "POST", "DELETE"])
def manage_bans():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    if request.method == "GET":
        c.execute("SELECT * FROM banned_ips")
        bans = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify(bans)

    if request.method == "POST":
        data = request.json or {}
        ip = (data.get("ip") or "").strip()
        if ip:
            if db_type == "postgres":
                c.execute(
                    "INSERT INTO banned_ips (ip, reason, timestamp) VALUES (%s, 'Admin Ban', %s) "
                    "ON CONFLICT (ip) DO UPDATE SET timestamp = EXCLUDED.timestamp",
                    (ip, datetime.now())
                )
            else:
                c.execute(
                    "INSERT OR REPLACE INTO banned_ips (ip, reason, timestamp) VALUES (?, 'Admin Ban', ?)",
                    (ip, datetime.now())
                )
        conn.commit()

    if request.method == "DELETE":
        data = request.json or {}
        ip = (data.get("ip") or "").strip()
        if ip:
            c.execute(f"DELETE FROM banned_ips WHERE ip={ph}", (ip,))
            conn.commit()

    conn.close()
    return jsonify({"message": "Updated"})


@app.route("/api/admin/requests", methods=["GET"])
def get_requests():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn, db_type = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM payment_requests WHERE status='pending' ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()
    return jsonify({"requests": [dict(row) for row in rows]})


@app.route("/api/admin/approve", methods=["POST"])
def approve_request():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json or {}
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)

    c.execute(
        f"SELECT user_id, plan_name FROM payment_requests WHERE id={ph}",
        (data.get("request_id"),)
    )
    req = c.fetchone()
    if not req:
        conn.close()
        return jsonify({"error": "Not found"}), 404

    if data.get("action") == "approve":
        tokens = 999999 if "God" in req['plan_name'] else 50
        c.execute(
            f"UPDATE users SET tokens = tokens + {ph}, plan = {ph} WHERE id={ph}",
            (tokens, req['plan_name'], req['user_id'])
        )
        c.execute(
            f"UPDATE payment_requests SET status='approved' WHERE id={ph}",
            (data.get("request_id"),)
        )
    else:
        c.execute(
            f"UPDATE payment_requests SET status='rejected' WHERE id={ph}",
            (data.get("request_id"),)
        )

    conn.commit()
    conn.close()
    return jsonify({"message": "Processed"})


@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn, db_type = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, email, tokens, is_admin, plan, downloads_count FROM users")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({"users": users})


@app.route("/api/admin/credits", methods=["POST"])
def admin_add_credits():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json or {}
    amount = int(data.get("amount", 0))
    user_id = data.get("user_id")

    if not user_id or amount <= 0 or amount > 999999:
        return jsonify({"error": "Invalid amount"}), 400

    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"UPDATE users SET tokens = tokens + {ph} WHERE id={ph}", (amount, user_id))
    conn.commit()
    conn.close()

    return jsonify({"message": f"Added {amount} credits"})


@app.route("/api/admin/promote", methods=["POST"])
def promote():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json or {}
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(
        f"UPDATE users SET is_admin = {ph} WHERE id = {ph}",
        (1 if data.get("is_admin") else 0, data.get("user_id"))
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Updated"})


@app.route("/api/admin/user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"DELETE FROM users WHERE id = {ph}", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})


@app.route("/api/admin/reset-password", methods=["POST"])
def admin_reset_pass():
    if not is_admin_request(request):
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json or {}
    password = data.get("password", "")
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    hashed = generate_password_hash(password)
    conn, db_type = get_db_connection()
    c = conn.cursor()
    ph = _ph(db_type)
    c.execute(f"UPDATE users SET password = {ph} WHERE id = {ph}", (hashed, data.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Password reset successfully"})


# ==========================================================
# SECTION 14: ERROR HANDLERS
# ==========================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Endpoint not found"}), 404
    four_oh_four = os.path.join(BASE_DIR, '404.html')
    if os.path.exists(four_oh_four):
        return send_file(four_oh_four), 404
    return "Page not found", 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({"error": "Internal server error"}), 500
    five_hundred = os.path.join(BASE_DIR, '500.html')
    if os.path.exists(five_hundred):
        return send_file(five_hundred), 500
    return "Server error", 500


# ==========================================================
# SECTION 15: BACKGROUND TASKS — Cleanup
# ==========================================================

def cleanup_files():
    """Periodically clean up old download and upload files."""
    while True:
        now = time.time()
        for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
            try:
                for f in os.listdir(folder):
                    f_path = os.path.join(folder, f)
                    if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 3600:
                        os.remove(f_path)
            except Exception:
                pass

        # Clean old job_status entries (older than 2 hours)
        expired_jobs = []
        for job_id, status in list(job_status.items()):
            if status.get('status') in ('completed', 'error'):
                expired_jobs.append(job_id)

        # Only clean up if we have too many
        if len(expired_jobs) > 100:
            for job_id in expired_jobs[:50]:
                job_status.pop(job_id, None)
                job_ownership.pop(job_id, None)

        # Rate limiter cleanup
        rate_limiter.cleanup()

        time.sleep(600)


threading.Thread(target=cleanup_files, daemon=True).start()


# ==========================================================
# SECTION 16: ENTRY POINT
# ==========================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
