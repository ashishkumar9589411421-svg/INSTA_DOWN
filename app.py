from flask import Flask, request, jsonify, send_file, send_from_directory, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import yt_dlp
import os
import shutil
import uuid
import time
import threading
import re
import psycopg2
import psycopg2.extras
from psycopg2.extras import RealDictCursor
import jwt 
import secrets
import hashlib
import json
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
import redis
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# -------------------------
# CONFIGURATION & INIT
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Redis for caching (optional, falls back to dict)
try:
    redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True, socket_connect_timeout=2)
    redis_client.ping()
    CACHE_ENABLED = True
except:
    CACHE_ENABLED = False
    redis_client = None
    print("Redis not available, using memory cache")

memory_cache = {}
def cache_get(key):
    if CACHE_ENABLED:
        return redis_client.get(key)
    return memory_cache.get(key)

def cache_set(key, value, ex=3600):
    if CACHE_ENABLED:
        redis_client.setex(key, ex, value)
    else:
        memory_cache[key] = value

# Secrets & Keys
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
def get_secret_key():
    if os.environ.get('SECRET_KEY'): 
        return os.environ.get('SECRET_KEY')
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'r') as f: 
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w') as f:
        f.write(key)
    return key

app.config['SECRET_KEY'] = get_secret_key()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Folders
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# FFmpeg Check
FFMPEG_PATH = shutil.which("ffmpeg") or os.path.join(BASE_DIR, "ffmpeg.exe" if os.name == 'nt' else "ffmpeg")

# Threading
MAX_CONCURRENT_DOWNLOADS = int(os.environ.get('MAX_WORKERS', 3))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS)
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
job_status = {}
active_downloads = {}

# Email Config (Mock - replace with real SMTP for production)
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')

# -------------------------
# DATABASE ENGINE
# -------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    if not DATABASE_URL:
        import sqlite3
        conn = sqlite3.connect(os.path.join(BASE_DIR, "users.db"), timeout=20, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn, "postgres"

def init_db():
    conn, db_type = get_db_connection()
    c = conn.cursor()
    
    # Users table - enhanced
    if db_type == "postgres":
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, 
                username TEXT UNIQUE, 
                email TEXT UNIQUE,
                password TEXT, 
                tokens INTEGER DEFAULT 15, 
                last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                daily_checkin TIMESTAMP,
                is_admin INTEGER DEFAULT 0, 
                plan TEXT DEFAULT 'Free', 
                referral_code TEXT UNIQUE, 
                referred_by INTEGER REFERENCES users(id),
                avatar TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_expires TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id SERIAL PRIMARY KEY,
                session_id TEXT UNIQUE,
                fingerprint TEXT,
                ip_address TEXT,
                tokens INTEGER DEFAULT 5,
                last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS download_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                guest_session TEXT,
                url TEXT,
                title TEXT,
                thumbnail TEXT,
                format_type TEXT,
                file_size TEXT,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                platform TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                id SERIAL PRIMARY KEY, 
                user_id INTEGER REFERENCES users(id),
                plan_name TEXT, 
                screenshot_path TEXT, 
                amount INTEGER,
                status TEXT DEFAULT 'pending', 
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                guest_session TEXT,
                subject TEXT,
                message TEXT,
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                title TEXT,
                message TEXT,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, 
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY, 
                reason TEXT, 
                banned_by INTEGER,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id SERIAL PRIMARY KEY,
                date DATE UNIQUE,
                total_downloads INTEGER DEFAULT 0,
                unique_users INTEGER DEFAULT 0,
                new_signups INTEGER DEFAULT 0,
                revenue INTEGER DEFAULT 0
            )
        """)
        
    else:
        # SQLite equivalents
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                email TEXT UNIQUE,
                password TEXT,
                tokens INTEGER DEFAULT 15,
                last_reset DATETIME DEFAULT CURRENT_TIMESTAMP,
                daily_checkin DATETIME,
                is_admin INTEGER DEFAULT 0,
                plan TEXT DEFAULT 'Free',
                referral_code TEXT UNIQUE,
                referred_by INTEGER,
                avatar TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_expires DATETIME
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                fingerprint TEXT,
                ip_address TEXT,
                tokens INTEGER DEFAULT 5,
                last_reset DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS download_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                guest_session TEXT,
                url TEXT,
                title TEXT,
                thumbnail TEXT,
                format_type TEXT,
                file_size TEXT,
                downloaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                platform TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                plan_name TEXT,
                screenshot_path TEXT,
                amount INTEGER,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                processed_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                guest_session TEXT,
                subject TEXT,
                message TEXT,
                status TEXT DEFAULT 'open',
                priority TEXT DEFAULT 'normal',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                message TEXT,
                is_read BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY,
                reason TEXT,
                banned_by INTEGER,
                expires_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS analytics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE UNIQUE,
                total_downloads INTEGER DEFAULT 0,
                unique_users INTEGER DEFAULT 0,
                new_signups INTEGER DEFAULT 0,
                revenue INTEGER DEFAULT 0
            )
        """)
    
    conn.commit()
    
    # Create default admin
    try:
        c.execute("SELECT * FROM users WHERE username=%s" if db_type == "postgres" else "SELECT * FROM users WHERE username=?", 
                  ('admin',))
        if not c.fetchone():
            hashed = generate_password_hash("admin123")
            c.execute("""
                INSERT INTO users (username, email, password, tokens, is_admin, plan, referral_code) 
                VALUES (%s, %s, %s, 999999, 1, 'God Mode', %s)
            """ if db_type == "postgres" else """
                INSERT INTO users (username, email, password, tokens, is_admin, plan, referral_code) 
                VALUES (?, ?, ?, 999999, 1, 'God Mode', ?)
            """, ('admin', 'admin@indl.com', hashed, 'ADMIN001'))
            conn.commit()
            print("Admin created: admin/admin123")
    except Exception as e:
        print(f"Admin init error: {e}")
    
    conn.close()

init_db()

# -------------------------
# HELPERS & DECORATORS
# -------------------------
def get_client_identifier():
    """Get unique identifier for guest tracking"""
    session_id = request.headers.get('X-Guest-ID', '')
    fingerprint = request.headers.get('X-Fingerprint', '')
    ip = get_real_ip()
    
    if session_id:
        return session_id, 'session'
    
    # Generate from fingerprint + IP combo if no session
    if fingerprint:
        combined = f"{fingerprint}:{ip}"
        return hashlib.md5(combined.encode()).hexdigest()[:16], 'fingerprint'
    
    return ip, 'ip'

def get_real_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def is_banned(ip):
    conn, t = get_db_connection()
    c = conn.cursor()
    q = "SELECT * FROM banned_ips WHERE ip=%s AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)" if t == "postgres" else "SELECT * FROM banned_ips WHERE ip=? AND (expires_at IS NULL OR expires_at > datetime('now'))"
    c.execute(q, (ip,))
    banned = c.fetchone()
    conn.close()
    return banned is not None

def get_or_create_guest_session():
    """Individual guest tracking - fixes the shared guest issue"""
    session_id, id_type = get_client_identifier()
    ip = get_real_ip()
    user_agent = request.headers.get('User-Agent', '')[:200]
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    # Try to get existing session
    if t == "postgres":
        c.execute("""
            SELECT id, session_id, tokens, last_reset 
            FROM user_sessions 
            WHERE session_id = %s OR (fingerprint = %s AND ip_address = %s)
            ORDER BY created_at DESC LIMIT 1
        """, (session_id, request.headers.get('X-Fingerprint', ''), ip))
    else:
        c.execute("""
            SELECT id, session_id, tokens, last_reset 
            FROM user_sessions 
            WHERE session_id = ? OR (fingerprint = ? AND ip_address = ?)
            ORDER BY created_at DESC LIMIT 1
        """, (session_id, request.headers.get('X-Fingerprint', ''), ip))
    
    row = c.fetchone()
    now = datetime.now()
    
    if row:
        session_data = dict(row) if t == "postgres" else {
            'session_id': row['session_id'],
            'tokens': row['tokens'],
            'last_reset': row['last_reset']
        }
        
        # Check reset (every 12 hours for guests)
        last_reset = session_data['last_reset']
        if isinstance(last_reset, str):
            try:
                last_reset = datetime.strptime(last_reset.split('.')[0], "%Y-%m-%d %H:%M:%S")
            except:
                last_reset = now - timedelta(hours=24)
        
        if session_data['tokens'] < 5 and (now - last_reset > timedelta(hours=12)):
            # Reset tokens
            if t == "postgres":
                c.execute("UPDATE user_sessions SET tokens = 5, last_reset = %s WHERE session_id = %s", (now, session_data['session_id']))
            else:
                c.execute("UPDATE user_sessions SET tokens = 5, last_reset = ? WHERE session_id = ?", (now, session_data['session_id']))
            conn.commit()
            session_data['tokens'] = 5
        
        conn.close()
        return session_data['session_id'], session_data['tokens']
    
    # Create new session
    new_session = str(uuid.uuid4())[:16]
    if t == "postgres":
        c.execute("""
            INSERT INTO user_sessions (session_id, fingerprint, ip_address, tokens, last_reset, user_agent)
            VALUES (%s, %s, %s, 5, %s, %s)
        """, (new_session, request.headers.get('X-Fingerprint', ''), ip, now, user_agent))
    else:
        c.execute("""
            INSERT INTO user_sessions (session_id, fingerprint, ip_address, tokens, last_reset, user_agent)
            VALUES (?, ?, ?, 5, ?, ?)
        """, (new_session, request.headers.get('X-Fingerprint', ''), ip, now, user_agent))
    
    conn.commit()
    conn.close()
    return new_session, 5

def check_tokens(user_id=None):
    """Dual tracking: logged in users OR guest sessions"""
    now = datetime.now()
    
    if user_id:
        conn, t = get_db_connection()
        c = conn.cursor()
        q = "SELECT tokens, last_reset, plan FROM users WHERE id=%s" if t == "postgres" else "SELECT tokens, last_reset, plan FROM users WHERE id=?"
        c.execute(q, (user_id,))
        row = c.fetchone()
        
        if not row:
            conn.close()
            return 0, False
        
        tokens, last_reset, plan = row['tokens'], row['last_reset'], row['plan']
        
        if isinstance(last_reset, str):
            try:
                last_reset = datetime.strptime(last_reset.split('.')[0], "%Y-%m-%d %H:%M:%S")
            except:
                last_reset = datetime.min
        
        # Reset every 24 hours for registered users
        if tokens < 15 and (now - last_reset > timedelta(hours=24)):
            uq = "UPDATE users SET tokens=15, last_reset=%s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens=15, last_reset=? WHERE id=?"
            c.execute(uq, (now, user_id))
            conn.commit()
            tokens = 15
        
        if plan == "God Mode":
            tokens = 999999
        
        conn.close()
        return tokens, False
    
    else:
        # Guest mode with individual tracking
        session_id, tokens = get_or_create_guest_session()
        return tokens, session_id

def consume_token(user_id=None, session_id=None):
    conn, t = get_db_connection()
    c = conn.cursor()
    
    if user_id:
        q = "UPDATE users SET tokens = tokens - 1 WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens - 1 WHERE id=?"
        c.execute(q, (user_id,))
    elif session_id:
        q = "UPDATE user_sessions SET tokens = tokens - 1 WHERE session_id=%s" if t == "postgres" else "UPDATE user_sessions SET tokens = tokens - 1 WHERE session_id=?"
        c.execute(q, (session_id,))
    
    conn.commit()
    conn.close()

def get_user_from_token(request):
    try:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split()[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded.get('user_id')
    except:
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = get_user_from_token(request)
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401
        
        conn, t = get_db_connection()
        c = conn.cursor()
        q = "SELECT is_admin FROM users WHERE id=%s" if t == "postgres" else "SELECT is_admin FROM users WHERE id=?"
        c.execute(q, (user_id,))
        row = c.fetchone()
        conn.close()
        
        if not row or row['is_admin'] != 1:
            return jsonify({"error": "Admin only"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def track_analytics(download=False, signup=False):
    """Background analytics tracking"""
    def _track():
        try:
            today = datetime.now().date()
            conn, t = get_db_connection()
            c = conn.cursor()
            
            if t == "postgres":
                c.execute("""
                    INSERT INTO analytics (date, total_downloads, new_signups)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (date) DO UPDATE SET
                    total_downloads = analytics.total_downloads + EXCLUDED.total_downloads,
                    new_signups = analytics.new_signups + EXCLUDED.new_signups
                """, (today, 1 if download else 0, 1 if signup else 0))
            else:
                c.execute("""
                    INSERT INTO analytics (date, total_downloads, new_signups)
                    VALUES (?, ?, ?)
                    ON CONFLICT(date) DO UPDATE SET
                    total_downloads = total_downloads + excluded.total_downloads,
                    new_signups = new_signups + excluded.new_signups
                """, (today, 1 if download else 0, 1 if signup else 0))
            
            conn.commit()
            conn.close()
        except:
            pass
    
    threading.Thread(target=_track, daemon=True).start()

# -------------------------
# VIDEO DOWNLOAD LOGIC
# -------------------------
def detect_platform(url):
    platforms = {
        'instagram.com': 'instagram',
        'youtube.com': 'youtube',
        'youtu.be': 'youtube',
        'tiktok.com': 'tiktok',
        'twitter.com': 'twitter',
        'x.com': 'twitter',
        'facebook.com': 'facebook',
        'fb.watch': 'facebook'
    }
    url_lower = url.lower()
    for domain, name in platforms.items():
        if domain in url_lower:
            return name
    return 'unknown'

def get_video_info(url):
    cache_key = f"info:{hashlib.md5(url.encode()).hexdigest()}"
    cached = cache_get(cache_key)
    if cached:
        return json.loads(cached)
    
    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": False,
        "http_headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0.36"
        },
        "cookiefile": os.path.join(BASE_DIR, "cookies.txt") if os.path.exists(os.path.join(BASE_DIR, "cookies.txt")) else None
    }
    
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            
            # Handle playlists
            if 'entries' in info:
                entries = info['entries'][:5]  # Limit to first 5 for preview
                playlist_data = {
                    'is_playlist': True,
                    'title': info.get('title', 'Playlist'),
                    'uploader': info.get('uploader', 'Unknown'),
                    'entries': []
                }
                for entry in entries:
                    if entry:
                        playlist_data['entries'].append({
                            'id': entry.get('id'),
                            'title': entry.get('title', 'Unknown'),
                            'duration': entry.get('duration_string', '0:00'),
                            'thumbnail': entry.get('thumbnail', '')
                        })
                return playlist_data
            
            # Single video
            formats = []
            duration = info.get('duration', 0)
            
            # Audio formats
            for abr in [128, 192, 320]:
                size = (abr * 1000 * duration) / 8 if duration else 0
                formats.append({
                    "id": f"mp3-{abr}",
                    "type": "audio",
                    "quality": f"{abr}kbps MP3",
                    "ext": "mp3",
                    "size": f"{size / 1024 / 1024:.1f} MB" if size else "Unknown"
                })
            
            # Video formats
            seen_heights = set()
            for f in info.get('formats', []):
                height = f.get('height')
                if not height or height in seen_heights or height < 144:
                    continue
                seen_heights.add(height)
                
                filesize = f.get('filesize') or f.get('filesize_approx')
                if not filesize and duration and f.get('tbr'):
                    filesize = (f['tbr'] * 1000 * duration) / 8
                
                formats.append({
                    "id": f"video-{height}",
                    "type": "video",
                    "quality": f"{height}p",
                    "ext": "mp4",
                    "size": f"{filesize / 1024 / 1024:.1f} MB" if filesize else "Unknown",
                    "vcodec": f.get('vcodec', 'unknown')
                })
            
            # Sort by quality descending
            formats.sort(key=lambda x: int(x['quality'].replace('p', '').replace('kbps MP3', '')) if 'video' in x['type'] else int(x['id'].split('-')[1]), reverse=True)
            
            result = {
                "is_playlist": False,
                "id": info.get('id'),
                "title": info.get('title', 'Unknown'),
                "thumbnail": info.get('thumbnail', ''),
                "duration": info.get('duration_string', '0:00'),
                "uploader": info.get('uploader', 'Unknown'),
                "view_count": info.get('view_count', 0),
                "platform": detect_platform(url),
                "formats": formats[:10]  # Limit to top 10 quality options
            }
            
            cache_set(cache_key, json.dumps(result), ex=1800)  # Cache 30 mins
            return result
            
    except Exception as e:
        print(f"Info extraction error: {e}")
        return None

def process_download(job_id, url, fmt_id, user_id=None, session_id=None):
    with download_semaphore:
        job_status[job_id]["status"] = "downloading"
        start_time = time.time()
        
        def progress_hook(d):
            if d["status"] == "downloading":
                percent_str = d.get("_percent_str", "0%")
                # Clean ANSI codes
                percent_clean = re.sub(r'\x1b\[[0-9;]*m', '', percent_str).strip().replace("%", "")
                speed = d.get("_speed_str", "N/A")
                eta = d.get("_eta_str", "N/A")
                job_status[job_id].update({
                    "percent": percent_clean,
                    "speed": speed,
                    "eta": eta
                })
        
        platform = detect_platform(url)
        ext = 'mp3' if 'mp3' in fmt_id else 'mp4'
        
        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, f"{job_id}_%(title)s.%(ext)s"),
            "progress_hooks": [progress_hook],
            "quiet": True,
            "ffmpeg_location": FFMPEG_PATH,
            "http_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0.36"
            }
        }
        
        if 'mp3' in fmt_id:
            bitrate = fmt_id.split('-')[1]
            ydl_opts.update({
                "format": "bestaudio/best",
                "postprocessors": [{
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": bitrate
                }]
            })
        else:
            height = fmt_id.replace("video-", "")
            if FFMPEG_PATH:
                ydl_opts["format"] = f"bestvideo[height<={height}]+bestaudio/best[height<={height}]"
                ydl_opts["merge_output_format"] = "mp4"
            else:
                ydl_opts["format"] = f"best[height<={height}]"
        
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(url, download=True)
                
                # Find downloaded file
                downloaded_file = None
                for f in os.listdir(DOWNLOAD_FOLDER):
                    if f.startswith(job_id):
                        downloaded_file = os.path.join(DOWNLOAD_FOLDER, f)
                        break
                
                if downloaded_file:
                    file_size = os.path.getsize(downloaded_file)
                    duration = time.time() - start_time
                    
                    job_status[job_id].update({
                        "status": "completed",
                        "file": downloaded_file,
                        "filename": os.path.basename(downloaded_file),
                        "size": file_size,
                        "duration": round(duration, 2)
                    })
                    
                    # Save to history
                    conn, t = get_db_connection()
                    c = conn.cursor()
                    if user_id:
                        q = """INSERT INTO download_history 
                               (user_id, url, title, thumbnail, format_type, file_size, platform) 
                               VALUES (%s, %s, %s, %s, %s, %s, %s)""" if t == "postgres" else """INSERT INTO download_history 
                               (user_id, url, title, thumbnail, format_type, file_size, platform) 
                               VALUES (?, ?, ?, ?, ?, ?, ?)"""
                        c.execute(q, (user_id, url, info.get('title', 'Unknown'), 
                                     info.get('thumbnail', ''), fmt_id, 
                                     f"{file_size/1024/1024:.1f}MB", platform))
                    elif session_id:
                        q = """INSERT INTO download_history 
                               (guest_session, url, title, thumbnail, format_type, file_size, platform) 
                               VALUES (%s, %s, %s, %s, %s, %s, %s)""" if t == "postgres" else """INSERT INTO download_history 
                               (guest_session, url, title, thumbnail, format_type, file_size, platform) 
                               VALUES (?, ?, ?, ?, ?, ?, ?)"""
                        c.execute(q, (session_id, url, info.get('title', 'Unknown'), 
                                     info.get('thumbnail', ''), fmt_id, 
                                     f"{file_size/1024/1024:.1f}MB", platform))
                    conn.commit()
                    conn.close()
                    
                    track_analytics(download=True)
                else:
                    raise Exception("File not found after download")
                    
        except Exception as e:
            job_status[job_id].update({
                "status": "error",
                "error": str(e)
            })

# -------------------------
# API ROUTES - AUTH
# -------------------------
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.json
    username = data.get("username", "").lower().strip()
    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    ref_code = data.get("referral_code", "").strip().upper()
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    try:
        # Check referral
        bonus = 0
        referrer_id = None
        if ref_code:
            c.execute("SELECT id FROM users WHERE referral_code=%s" if t == "postgres" else "SELECT id FROM users WHERE referral_code=?", (ref_code,))
            ref_row = c.fetchone()
            if ref_row:
                referrer_id = ref_row['id']
                bonus = 10
        
        # Generate unique referral code
        new_ref = f"{username[:4].upper()}{secrets.token_hex(3).upper()}"
        
        hashed_pw = generate_password_hash(password)
        
        c.execute("""
            INSERT INTO users (username, email, password, tokens, referral_code, referred_by, plan)
            VALUES (%s, %s, %s, %s, %s, %s, 'Free')
        """ if t == "postgres" else """
            INSERT INTO users (username, email, password, tokens, referral_code, referred_by, plan)
            VALUES (?, ?, ?, ?, ?, ?, 'Free')
        """, (username, email, hashed_pw, 15 + bonus, new_ref, referrer_id))
        
        conn.commit()
        
        # Credit referrer
        if referrer_id:
            c.execute("UPDATE users SET tokens = tokens + 10 WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + 10 WHERE id=?", (referrer_id,))
            conn.commit()
        
        track_analytics(signup=True)
        
        return jsonify({
            "message": "Registration successful" + (" (+10 bonus credits!)" if bonus else ""),
            "referral_code": new_ref
        }), 201
        
    except Exception as e:
        conn.rollback()
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            if "username" in str(e).lower():
                return jsonify({"error": "Username already taken"}), 409
            elif "email" in str(e).lower():
                return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": "Registration failed"}), 500
    finally:
        conn.close()

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get("username", "").lower().strip()
    password = data.get("password", "")
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = "SELECT id, password, is_admin, plan, tokens FROM users WHERE username=%s OR email=%s" if t == "postgres" else "SELECT id, password, is_admin, plan, tokens FROM users WHERE username=? OR email=?"
    c.execute(q, (username, username))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        token = jwt.encode({
            'user_id': user['id'],
            'is_admin': user['is_admin'],
            'plan': user['plan'],
            'exp': datetime.utcnow() + timedelta(days=7)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "token": token,
            "user": {
                "id": user['id'],
                "plan": user['plan'],
                "is_admin": bool(user['is_admin']),
                "tokens": user['tokens']
            }
        })
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    email = request.json.get("email", "").lower().strip()
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = "SELECT id, username FROM users WHERE email=%s" if t == "postgres" else "SELECT id, username FROM users WHERE email=?"
    c.execute(q, (email,))
    user = c.fetchone()
    
    if user:
        token = secrets.token_urlsafe(32)
        expires = datetime.now() + timedelta(hours=1)
        
        q = "UPDATE users SET reset_token=%s, reset_expires=%s WHERE id=%s" if t == "postgres" else "UPDATE users SET reset_token=?, reset_expires=? WHERE id=?"
        c.execute(q, (token, expires, user['id']))
        conn.commit()
        
        # Here you would send email. For now, just return token in dev mode
        # send_reset_email(email, user['username'], token)
        
        return jsonify({"message": "Check your email for reset instructions", "dev_token": token if os.environ.get('FLASK_DEBUG') else None})
    
    return jsonify({"message": "If email exists, reset instructions sent"}), 200

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    token = request.json.get("token")
    new_password = request.json.get("password")
    
    if not token or not new_password:
        return jsonify({"error": "Missing data"}), 400
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = "SELECT id FROM users WHERE reset_token=%s AND reset_expires > CURRENT_TIMESTAMP" if t == "postgres" else "SELECT id FROM users WHERE reset_token=? AND reset_expires > datetime('now')"
    c.execute(q, (token,))
    user = c.fetchone()
    
    if user:
        hashed = generate_password_hash(new_password)
        q = "UPDATE users SET password=%s, reset_token=NULL, reset_expires=NULL WHERE id=%s" if t == "postgres" else "UPDATE users SET password=?, reset_token=NULL, reset_expires=NULL WHERE id=?"
        c.execute(q, (hashed, user['id']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Password updated successfully"})
    
    conn.close()
    return jsonify({"error": "Invalid or expired token"}), 400

@app.route("/api/auth/check", methods=["GET"])
def check_auth():
    """Enhanced status check with daily rewards"""
    user_id = get_user_from_token(request)
    tokens, session_id = check_tokens(user_id)
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    response = {
        "is_logged_in": bool(user_id),
        "tokens": tokens,
        "session_id": session_id if not user_id else None,
        "can_checkin": False
    }
    
    if user_id:
        q = "SELECT username, plan, is_admin, daily_checkin, tokens FROM users WHERE id=%s" if t == "postgres" else "SELECT username, plan, is_admin, daily_checkin, tokens FROM users WHERE id=?"
        c.execute(q, (user_id,))
        user = c.fetchone()
        
        if user:
            response.update({
                "username": user['username'],
                "plan": user['plan'],
                "is_admin": bool(user['is_admin']),
                "tokens": user['tokens']
            })
            
            # Check daily reward eligibility
            last_checkin = user['daily_checkin']
            if isinstance(last_checkin, str):
                try:
                    last_checkin = datetime.strptime(last_checkin.split('.')[0], "%Y-%m-%d %H:%M:%S")
                except:
                    last_checkin = None
            
            if not last_checkin or (datetime.now() - last_checkin) > timedelta(hours=20):
                response["can_checkin"] = True
    
    # Get announcement
    c.execute("SELECT value FROM settings WHERE key='announcement'")
    ann = c.fetchone()
    response["announcement"] = ann['value'] if ann else ""
    
    # Get maintenance mode
    c.execute("SELECT value FROM settings WHERE key='maintenance'")
    maint = c.fetchone()
    response["maintenance"] = maint['value'] == 'true' if maint else False
    
    conn.close()
    return jsonify(response)

@app.route("/api/auth/daily-checkin", methods=["POST"])
def daily_checkin():
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"error": "Login required"}), 401
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = "SELECT daily_checkin FROM users WHERE id=%s" if t == "postgres" else "SELECT daily_checkin FROM users WHERE id=?"
    c.execute(q, (user_id,))
    row = c.fetchone()
    
    last_checkin = row['daily_checkin']
    if isinstance(last_checkin, str):
        try:
            last_checkin = datetime.strptime(last_checkin.split('.')[0], "%Y-%m-%d %H:%M:%S")
        except:
            last_checkin = None
    
    if last_checkin and (datetime.now() - last_checkin) < timedelta(hours=20):
        conn.close()
        return jsonify({"error": "Already checked in today"}), 400
    
    # Give random reward between 5-15 tokens
    reward = secrets.randbelow(11) + 5
    
    q = "UPDATE users SET tokens = tokens + %s, daily_checkin = %s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + ?, daily_checkin = ? WHERE id=?"
    c.execute(q, (reward, datetime.now(), user_id))
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"Daily check-in successful! +{reward} credits", "reward": reward})

# -------------------------
# API ROUTES - DOWNLOAD
# -------------------------
@app.route("/api/download/info", methods=["POST"])
@limiter.limit("30 per minute")
def get_info():
    if is_banned(get_real_ip()):
        return jsonify({"error": "Access denied"}), 403
    
    url = request.json.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        return jsonify({"error": "Invalid URL format"}), 400
    
    info = get_video_info(url)
    if info:
        return jsonify(info)
    return jsonify({"error": "Failed to fetch video info. Check URL and try again."}), 400

@app.route("/api/download/start", methods=["POST"])
@limiter.limit("10 per minute")
def start_download():
    ip = get_real_ip()
    if is_banned(ip):
        return jsonify({"error": "BANNED", "message": "Your IP has been banned"}), 403
    
    # Check maintenance
    conn, t = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key='maintenance'")
    maint = c.fetchone()
    if maint and maint['value'] == 'true':
        user_id = get_user_from_token(request)
        if not user_id:
            conn.close()
            return jsonify({"error": "MAINTENANCE", "message": "System under maintenance"}), 503
    
    # Check credits
    user_id = get_user_from_token(request)
    tokens, session_id = check_tokens(user_id)
    
    if tokens <= 0:
        conn.close()
        msg = "Daily limit reached. Upgrade your plan!" if user_id else "Guest limit reached. Register for more!"
        return jsonify({"error": "LIMIT_REACHED", "message": msg}), 403
    
    # Consume token
    consume_token(user_id, session_id)
    
    data = request.json
    url = data.get("url")
    fmt_id = data.get("format_id")
    
    if not url or not fmt_id:
        return jsonify({"error": "Missing parameters"}), 400
    
    # Check concurrent downloads
    if len(active_downloads) >= MAX_CONCURRENT_DOWNLOADS:
        return jsonify({"error": "Server busy. Please try again in a moment."}), 503
    
    job_id = str(uuid.uuid4())
    job_status[job_id] = {
        "status": "queued",
        "percent": "0",
        "speed": "N/A",
        "eta": "N/A"
    }
    active_downloads[job_id] = True
    
    executor.submit(process_download, job_id, url, fmt_id, user_id, session_id)
    
    return jsonify({
        "job_id": job_id,
        "message": "Download started",
        "check_url": f"/api/download/progress/{job_id}"
    })

@app.route("/api/download/progress/<job_id>")
def check_progress(job_id):
    if job_id not in job_status:
        return jsonify({"status": "not_found"}), 404
    
    status = job_status[job_id].copy()
    
    # Cleanup if completed or error (after 5 minutes)
    if status["status"] in ["completed", "error"]:
        if job_id in active_downloads:
            del active_downloads[job_id]
        # Schedule cleanup
        def cleanup():
            time.sleep(300)
            if job_id in job_status:
                del job_status[job_id]
        threading.Timer(300, cleanup).start()
    
    return jsonify(status)

@app.route("/api/download/file/<job_id>")
def download_file(job_id):
    job = job_status.get(job_id)
    if not job or job.get("status") != "completed":
        return jsonify({"error": "Download not ready"}), 404
    
    file_path = job.get("file")
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": "File expired"}), 404
    
    try:
        return send_file(
            file_path,
            as_attachment=True,
            download_name=job.get("filename", "download.mp4"),
            max_age=0
        )
    except Exception as e:
        return jsonify({"error": "File send error"}), 500

@app.route("/api/download/history")
def get_history():
    user_id = get_user_from_token(request)
    session_id = request.args.get("session_id") or request.headers.get("X-Guest-ID")
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    if user_id:
        q = """SELECT * FROM download_history 
               WHERE user_id=%s 
               ORDER BY downloaded_at DESC 
               LIMIT 50""" if t == "postgres" else """SELECT * FROM download_history 
               WHERE user_id=? 
               ORDER BY downloaded_at DESC 
               LIMIT 50"""
        c.execute(q, (user_id,))
    elif session_id:
        q = """SELECT * FROM download_history 
               WHERE guest_session=%s 
               ORDER BY downloaded_at DESC 
               LIMIT 20""" if t == "postgres" else """SELECT * FROM download_history 
               WHERE guest_session=? 
               ORDER BY downloaded_at DESC 
               LIMIT 20"""
        c.execute(q, (session_id,))
    else:
        conn.close()
        return jsonify({"error": "No identifier"}), 400
    
    rows = c.fetchall()
    history = [dict(row) for row in rows]
    conn.close()
    
    return jsonify({"history": history})

# -------------------------
# API ROUTES - PAYMENTS & CREDITS
# -------------------------
@app.route("/api/payment/request", methods=["POST"])
def request_payment():
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"error": "Login required"}), 401
    
    plan_name = request.form.get("plan_name", "Unknown")
    amount = request.form.get("amount", 0)
    file = request.files.get("screenshot")
    
    if not file:
        return jsonify({"error": "Screenshot required"}), 400
    
    filename = secure_filename(f"{user_id}_{int(time.time())}_{file.filename}")
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = """INSERT INTO payment_requests 
           (user_id, plan_name, screenshot_path, amount, status) 
           VALUES (%s, %s, %s, %s, 'pending')""" if t == "postgres" else """INSERT INTO payment_requests 
           (user_id, plan_name, screenshot_path, amount, status) 
           VALUES (?, ?, ?, ?, 'pending')"""
    
    c.execute(q, (user_id, plan_name, filename, amount))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Payment submitted for review"})

@app.route("/api/credits/watch-ad", methods=["POST"])
def watch_ad_reward():
    """Simulated ad watching for credits"""
    user_id = get_user_from_token(request)
    session_id = request.headers.get("X-Guest-ID")
    
    if not user_id and not session_id:
        return jsonify({"error": "No session"}), 400
    
    # Simple cooldown check using memory (in production use Redis)
    cooldown_key = f"ad_cooldown:{user_id or session_id}"
    last_watch = memory_cache.get(cooldown_key)
    
    if last_watch and (time.time() - last_watch) < 300:  # 5 min cooldown
        return jsonify({"error": "Please wait 5 minutes between ads"}), 429
    
    memory_cache[cooldown_key] = time.time()
    
    # Small reward: 1-3 credits
    reward = secrets.randbelow(3) + 1
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    if user_id:
        q = "UPDATE users SET tokens = tokens + %s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + ? WHERE id=?"
        c.execute(q, (reward, user_id))
    else:
        q = "UPDATE user_sessions SET tokens = tokens + %s WHERE session_id=%s" if t == "postgres" else "UPDATE user_sessions SET tokens = tokens + ? WHERE session_id=?"
        c.execute(q, (reward, session_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"Thanks for watching! +{reward} credits", "reward": reward})

@app.route("/api/credits/transfer", methods=["POST"])
def transfer_credits():
    user_id = get_user_from_token(request)
    if not user_id:
        return jsonify({"error": "Login required"}), 401
    
    recipient = request.json.get("recipient", "").lower().strip()
    amount = int(request.json.get("amount", 0))
    
    if amount <= 0 or amount > 1000:
        return jsonify({"error": "Invalid amount (1-1000)"}), 400
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    # Check sender balance
    q = "SELECT tokens FROM users WHERE id=%s" if t == "postgres" else "SELECT tokens FROM users WHERE id=?"
    c.execute(q, (user_id,))
    sender = c.fetchone()
    
    if not sender or sender['tokens'] < amount:
        conn.close()
        return jsonify({"error": "Insufficient credits"}), 400
    
    # Get recipient
    q = "SELECT id FROM users WHERE username=%s" if t == "postgres" else "SELECT id FROM users WHERE username=?"
    c.execute(q, (recipient,))
    recipient_user = c.fetchone()
    
    if not recipient_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    if recipient_user['id'] == user_id:
        conn.close()
        return jsonify({"error": "Cannot transfer to yourself"}), 400
    
    # Perform transfer
    q1 = "UPDATE users SET tokens = tokens - %s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens - ? WHERE id=?"
    q2 = "UPDATE users SET tokens = tokens + %s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + ? WHERE id=?"
    
    c.execute(q1, (amount, user_id))
    c.execute(q2, (amount, recipient_user['id']))
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"Transferred {amount} credits to {recipient}"})

# -------------------------
# API ROUTES - SUPPORT
# -------------------------
@app.route("/api/support/ticket", methods=["POST"])
def create_ticket():
    data = request.json
    user_id = get_user_from_token(request)
    session_id = request.headers.get("X-Guest-ID")
    
    subject = data.get("subject", "").strip()
    message = data.get("message", "").strip()
    
    if not subject or not message:
        return jsonify({"error": "Subject and message required"}), 400
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = """INSERT INTO support_tickets 
           (user_id, guest_session, subject, message, status) 
           VALUES (%s, %s, %s, %s, 'open')""" if t == "postgres" else """INSERT INTO support_tickets 
           (user_id, guest_session, subject, message, status) 
           VALUES (?, ?, ?, ?, 'open')"""
    
    c.execute(q, (user_id, session_id, subject, message))
    conn.commit()
    conn.close()
    
    return jsonify({"message": "Ticket created successfully"})

@app.route("/api/support/tickets")
def get_user_tickets():
    user_id = get_user_from_token(request)
    session_id = request.headers.get("X-Guest-ID")
    
    if not user_id and not session_id:
        return jsonify({"error": "Auth required"}), 401
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    if user_id:
        q = "SELECT * FROM support_tickets WHERE user_id=%s ORDER BY created_at DESC" if t == "postgres" else "SELECT * FROM support_tickets WHERE user_id=? ORDER BY created_at DESC"
        c.execute(q, (user_id,))
    else:
        q = "SELECT * FROM support_tickets WHERE guest_session=%s ORDER BY created_at DESC" if t == "postgres" else "SELECT * FROM support_tickets WHERE guest_session=? ORDER BY created_at DESC"
        c.execute(q, (session_id,))
    
    rows = c.fetchall()
    tickets = [dict(row) for row in rows]
    conn.close()
    
    return jsonify({"tickets": tickets})

# -------------------------
# API ROUTES - ADMIN
# -------------------------
@app.route("/api/admin/dashboard")
@admin_required
def admin_dashboard():
    conn, t = get_db_connection()
    c = conn.cursor()
    
    # Stats
    c.execute("SELECT COUNT(*) as total_users FROM users")
    total_users = c.fetchone()['total_users']
    
    c.execute("SELECT COUNT(*) as today_downloads FROM download_history WHERE date(downloaded_at) = date('now')" if t == "sqlite" else "SELECT COUNT(*) as today_downloads FROM download_history WHERE DATE(downloaded_at) = CURRENT_DATE")
    today_downloads = c.fetchone()['today_downloads']
    
    c.execute("SELECT COUNT(*) as pending_payments FROM payment_requests WHERE status='pending'")
    pending_payments = c.fetchone()['pending_payments']
    
    c.execute("SELECT COUNT(*) as open_tickets FROM support_tickets WHERE status='open'")
    open_tickets = c.fetchone()['open_tickets']
    
    # Recent users
    c.execute("SELECT id, username, email, tokens, plan, created_at FROM users ORDER BY created_at DESC LIMIT 10")
    recent_users = [dict(row) for row in c.fetchall()]
    
    # Analytics data (last 30 days)
    if t == "postgres":
        c.execute("""
            SELECT date, total_downloads, unique_users, new_signups 
            FROM analytics 
            WHERE date >= CURRENT_DATE - INTERVAL '30 days'
            ORDER BY date
        """)
    else:
        c.execute("""
            SELECT date, total_downloads, unique_users, new_signups 
            FROM analytics 
            WHERE date >= date('now', '-30 days')
            ORDER BY date
        """)
    
    analytics = [dict(row) for row in c.fetchall()]
    
    conn.close()
    
    return jsonify({
        "stats": {
            "total_users": total_users,
            "today_downloads": today_downloads,
            "pending_payments": pending_payments,
            "open_tickets": open_tickets
        },
        "recent_users": recent_users,
        "analytics": analytics
    })

@app.route("/api/admin/users")
@admin_required
def admin_users():
    page = request.args.get("page", 1, type=int)
    per_page = 20
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) as count FROM users")
    total = c.fetchone()['count']
    
    offset = (page - 1) * per_page
    if t == "postgres":
        c.execute("""
            SELECT id, username, email, tokens, plan, is_admin, 
                   (SELECT COUNT(*) FROM download_history WHERE user_id=users.id) as total_downloads
            FROM users 
            ORDER BY created_at DESC 
            LIMIT %s OFFSET %s
        """, (per_page, offset))
    else:
        c.execute("""
            SELECT id, username, email, tokens, plan, is_admin,
                   (SELECT COUNT(*) FROM download_history WHERE user_id=users.id) as total_downloads
            FROM users 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
        """, (per_page, offset))
    
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({
        "users": users,
        "total": total,
        "pages": (total + per_page - 1) // per_page,
        "current_page": page
    })

@app.route("/api/admin/payments")
@admin_required
def admin_payments():
    status = request.args.get("status", "pending")
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    q = """
        SELECT pr.*, u.username, u.email 
        FROM payment_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        WHERE pr.status = %s
        ORDER BY pr.created_at DESC
    """ if t == "postgres" else """
        SELECT pr.*, u.username, u.email 
        FROM payment_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        WHERE pr.status = ?
        ORDER BY pr.created_at DESC
    """
    c.execute(q, (status,))
    payments = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({"payments": payments})

@app.route("/api/admin/payment/process", methods=["POST"])
@admin_required
def process_payment():
    data = request.json
    payment_id = data.get("payment_id")
    action = data.get("action")  # 'approve' or 'reject'
    
    if not payment_id or action not in ['approve', 'reject']:
        return jsonify({"error": "Invalid data"}), 400
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    # Get payment details
    q = "SELECT * FROM payment_requests WHERE id=%s" if t == "postgres" else "SELECT * FROM payment_requests WHERE id=?"
    c.execute(q, (payment_id,))
    payment = c.fetchone()
    
    if not payment:
        conn.close()
        return jsonify({"error": "Payment not found"}), 404
    
    if action == "approve":
        # Credit user
        credits = 50 if "Booster" in payment['plan_name'] else 999999 if "God" in payment['plan_name'] else 50
        
        q1 = "UPDATE users SET tokens=%s, plan=%s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens=?, plan=? WHERE id=?"
        c.execute(q1, (credits, payment['plan_name'], payment['user_id']))
        
        q2 = "UPDATE payment_requests SET status='approved', processed_at=%s WHERE id=%s" if t == "postgres" else "UPDATE payment_requests SET status='approved', processed_at=? WHERE id=?"
        c.execute(q2, (datetime.now(), payment_id))
    else:
        q = "UPDATE payment_requests SET status='rejected', processed_at=%s WHERE id=%s" if t == "postgres" else "UPDATE payment_requests SET status='rejected', processed_at=? WHERE id=?"
        c.execute(q, (datetime.now(), payment_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"Payment {action}ed"})

@app.route("/api/admin/ban", methods=["POST", "DELETE"])
@admin_required
def manage_ban():
    data = request.json
    ip = data.get("ip")
    reason = data.get("reason", "Admin ban")
    duration = data.get("duration")  # hours, null = permanent
    
    if not ip:
        return jsonify({"error": "IP required"}), 400
    
    conn, t = get_db_connection()
    c = conn.cursor()
    
    if request.method == "POST":
        expires = None
        if duration:
            expires = datetime.now() + timedelta(hours=int(duration))
        
        q = """
            INSERT INTO banned_ips (ip, reason, banned_by, expires_at) 
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (ip) DO UPDATE SET reason=EXCLUDED.reason, expires_at=EXCLUDED.expires_at
        """ if t == "postgres" else """
            INSERT OR REPLACE INTO banned_ips (ip, reason, banned_by, expires_at) 
            VALUES (?, ?, ?, ?)
        """
        
        admin_id = get_user_from_token(request)
        c.execute(q, (ip, reason, admin_id, expires))
        conn.commit()
        
    elif request.method == "DELETE":
        q = "DELETE FROM banned_ips WHERE ip=%s" if t == "postgres" else "DELETE FROM banned_ips WHERE ip=?"
        c.execute(q, (ip,))
        conn.commit()
    
    conn.close()
    return jsonify({"message": "Ban updated"})

@app.route("/api/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    conn, t = get_db_connection()
    c = conn.cursor()
    
    if request.method == "POST":
        data = request.json
        settings_to_update = [
            ('maintenance', str(data.get('maintenance', False)).lower()),
            ('announcement', data.get('announcement', '')),
            ('site_name', data.get('site_name', 'In.dl')),
            ('registration_enabled', str(data.get('registration_enabled', True)).lower())
        ]
        
        for key, value in settings_to_update:
            if t == "postgres":
                c.execute("""
                    INSERT INTO settings (key, value) VALUES (%s, %s)
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
                """, (key, value))
            else:
                c.execute("""
                    INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)
                """, (key, value))
        
        conn.commit()
        conn.close()
        return jsonify({"message": "Settings saved"})
    
    # GET
    c.execute("SELECT key, value FROM settings")
    settings = {row['key']: row['value'] for row in c.fetchall()}
    conn.close()
    
    return jsonify(settings)

# -------------------------
# CLEANUP & MAINTENANCE
# -------------------------
def cleanup_old_files():
    while True:
        now = time.time()
        try:
            # Cleanup downloads older than 1 hour
            for f in os.listdir(DOWNLOAD_FOLDER):
                f_path = os.path.join(DOWNLOAD_FOLDER, f)
                if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 3600:
                    os.remove(f_path)
            
            # Cleanup old upload proofs (older than 30 days)
            for f in os.listdir(UPLOAD_FOLDER):
                f_path = os.path.join(UPLOAD_FOLDER, f)
                if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 30 * 86400:
                    os.remove(f_path)
                    
            # Cleanup old guest sessions (older than 7 days)
            conn, t = get_db_connection()
            c = conn.cursor()
            if t == "postgres":
                c.execute("DELETE FROM user_sessions WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'")
            else:
                c.execute("DELETE FROM user_sessions WHERE created_at < datetime('now', '-7 days')")
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"Cleanup error: {e}")
        
        time.sleep(600)  # Run every 10 minutes

cleanup_thread = threading.Thread(target=cleanup_old_files, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=True)
