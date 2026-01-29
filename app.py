from flask import Flask, request, jsonify, send_file, send_from_directory
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

# -------------------------
# CONFIGURATION
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
# Fix 405 Errors by allowing cross-origin properly
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Secrets & Cookies
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
COOKIE_FILE = os.path.join(BASE_DIR, "cookies.txt")

# --- DEBUG: VERIFY COOKIES ---
print("------------------------------------------------")
if os.path.exists(COOKIE_FILE):
    print(f"✅ COOKIES DETECTED: {os.path.getsize(COOKIE_FILE)} bytes")
    print("   (Using Desktop Mode to match cookies)")
else:
    print(f"⚠️ NO COOKIES FOUND")
    print("   (Upload cookies.txt to fix rate limits)")
print("------------------------------------------------")

def get_secret_key():
    if os.environ.get('SECRET_KEY'): return os.environ.get('SECRET_KEY')
    if os.path.exists(SECRET_FILE):
        try: 
            with open(SECRET_FILE, 'r') as f: return f.read().strip()
        except: pass
    return secrets.token_hex(32)

app.config['SECRET_KEY'] = get_secret_key()

# Folders
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# FFmpeg Check
if os.path.exists(os.path.join(BASE_DIR, "ffmpeg.exe")): FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg.exe") 
elif os.path.exists(os.path.join(BASE_DIR, "ffmpeg")): FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg") 
elif shutil.which("ffmpeg"): FFMPEG_PATH = shutil.which("ffmpeg") 
else: FFMPEG_PATH = None 

# Threading
MAX_CONCURRENT_DOWNLOADS = int(os.environ.get('MAX_WORKERS', 2))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS) 
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
job_status = {}

# -------------------------
# DATABASE ENGINE
# -------------------------
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    if not DATABASE_URL:
        import sqlite3
        conn = sqlite3.connect("users.db", timeout=10)
        conn.row_factory = sqlite3.Row
        return conn, "sqlite"
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn, "postgres"

def init_db():
    conn, db_type = get_db_connection()
    c = conn.cursor()
    
    # Common Schema
    users_sql = """CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE, email TEXT, password TEXT, tokens INTEGER DEFAULT 15, last_reset TIMESTAMP, is_admin INTEGER DEFAULT 0, plan TEXT DEFAULT 'Free', referral_code TEXT UNIQUE, referred_by TEXT)"""
    guests_sql = """CREATE TABLE IF NOT EXISTS guests (ip TEXT PRIMARY KEY, tokens INTEGER DEFAULT 5, last_reset TIMESTAMP)"""
    req_sql = """CREATE TABLE IF NOT EXISTS payment_requests (id SERIAL PRIMARY KEY, user_id INTEGER, username TEXT, plan_name TEXT, screenshot_path TEXT, status TEXT DEFAULT 'pending', timestamp TIMESTAMP)"""
    msg_sql = """CREATE TABLE IF NOT EXISTS messages (id SERIAL PRIMARY KEY, name TEXT, email TEXT, message TEXT, timestamp TIMESTAMP)"""
    
    if db_type == "sqlite":
        # Adjust for SQLite
        users_sql = users_sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("TIMESTAMP", "DATETIME")
        guests_sql = guests_sql.replace("TIMESTAMP", "DATETIME")
        req_sql = req_sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("TIMESTAMP", "DATETIME")
        msg_sql = msg_sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT").replace("TIMESTAMP", "DATETIME")

    # Execute
    try:
        c.execute(users_sql)
        c.execute(guests_sql)
        c.execute(req_sql)
        c.execute(msg_sql)
        c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, reason TEXT, timestamp TIMESTAMP)".replace("TIMESTAMP", "DATETIME" if db_type=="sqlite" else "TIMESTAMP"))
        
        # Admin Creation
        user_ph = "?" if db_type == "sqlite" else "%s"
        c.execute(f"SELECT * FROM users WHERE username={user_ph}", ('ashishadmin',))
        if not c.fetchone():
            hashed = generate_password_hash("anu9936")
            insert_sql = f"INSERT INTO users (username, password, tokens, last_reset, is_admin, plan) VALUES ({user_ph}, {user_ph}, 999999, {user_ph}, 1, 'God Mode')"
            c.execute(insert_sql, ('ashishadmin', hashed, datetime.now()))
            print("👑 Admin created")
        
        conn.commit()
    except Exception as e:
        print(f"DB Init Error: {e}")
    finally:
        conn.close()

init_db()

# -------------------------
# HELPERS
# -------------------------
def is_banned(ip):
    conn, t = get_db_connection(); c = conn.cursor()
    q = "SELECT * FROM banned_ips WHERE ip=%s" if t == "postgres" else "SELECT * FROM banned_ips WHERE ip=?"
    c.execute(q, (ip,)); banned = c.fetchone(); conn.close()
    return banned is not None

def check_tokens(ip, user_id=None):
    conn, t = get_db_connection(); c = conn.cursor(); now = datetime.now()
    if user_id:
        q = "SELECT tokens, last_reset, plan FROM users WHERE id=%s" if t == "postgres" else "SELECT tokens, last_reset, plan FROM users WHERE id=?"
        c.execute(q, (user_id,)); row = c.fetchone()
        if not row: return 0, False
        tokens, last_reset, plan = row['tokens'], row['last_reset'], row['plan']
    else:
        q = "SELECT tokens, last_reset FROM guests WHERE ip=%s" if t == "postgres" else "SELECT tokens, last_reset FROM guests WHERE ip=?"
        c.execute(q, (ip,)); row = c.fetchone()
        if not row:
            iq = "INSERT INTO guests (ip, tokens, last_reset) VALUES (%s, 5, %s)" if t == "postgres" else "INSERT INTO guests (ip, tokens, last_reset) VALUES (?, 5, ?)"
            c.execute(iq, (ip, now)); conn.commit(); return 5, False
        tokens, last_reset = row['tokens'], row['last_reset']; plan = "Guest"

    if isinstance(last_reset, str):
        try: last_reset = datetime.strptime(last_reset.split('.')[0], "%Y-%m-%d %H:%M:%S")
        except: last_reset = datetime.min
    
    if tokens < 15 and (now - last_reset > timedelta(hours=12)):
        uq = "UPDATE users SET tokens=15, last_reset=%s WHERE id=%s" if t == "postgres" and user_id else "UPDATE users SET tokens=15, last_reset=? WHERE id=?"
        gq = "UPDATE guests SET tokens=5, last_reset=%s WHERE ip=%s" if t == "postgres" and not user_id else "UPDATE guests SET tokens=5, last_reset=? WHERE ip=?"
        if user_id: c.execute(uq, (now, user_id))
        else: c.execute(gq, (now, ip))
        conn.commit(); tokens = 15 if user_id else 5
        
    if plan == "God Mode": tokens = 999999
    conn.close(); return tokens, False

def consume_token(ip, user_id=None):
    conn, t = get_db_connection(); c = conn.cursor()
    if user_id:
        q = "UPDATE users SET tokens = tokens - 1 WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens - 1 WHERE id=?"
        c.execute(q, (user_id,))
    else:
        q = "UPDATE guests SET tokens = tokens - 1 WHERE ip=%s" if t == "postgres" else "UPDATE guests SET tokens = tokens - 1 WHERE ip=?"
        c.execute(q, (ip,))
    conn.commit(); conn.close()

def get_user_from_token(request):
    try:
        token = request.headers.get("Authorization").split()[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded['user_id']
    except: return None

def is_admin_request(request):
    user_id = get_user_from_token(request)
    if not user_id: return False
    conn, t = get_db_connection(); c = conn.cursor()
    q = "SELECT is_admin FROM users WHERE id=%s" if t == "postgres" else "SELECT is_admin FROM users WHERE id=?"
    c.execute(q, (user_id,)); row = c.fetchone(); conn.close()
    return row and row['is_admin'] == 1

# -------------------------
# ROUTES
# -------------------------
@app.route('/')
def index(): return send_file('index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(BASE_DIR, path)): return send_from_directory(BASE_DIR, path)
    return send_file('index.html')

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json; conn, t = get_db_connection(); c = conn.cursor()
    ref_code = (data["username"][:4] + secrets.token_hex(2)).upper()
    used_ref = data.get("referral_code", "").strip().upper(); bonus = 0
    try:
        if used_ref:
            q = "SELECT id FROM users WHERE referral_code=%s" if t == "postgres" else "SELECT id FROM users WHERE referral_code=?"
            c.execute(q, (used_ref,)); referrer = c.fetchone()
            if referrer:
                u_q = "UPDATE users SET tokens = tokens + 10 WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + 10 WHERE id=?"
                c.execute(u_q, (referrer[0] if t=="postgres" else referrer['id'],)); bonus = 10 
        q = "INSERT INTO users(username, email, password, tokens, last_reset, is_admin, plan, referral_code, referred_by) VALUES (%s, %s, %s, %s, %s, 0, 'Free', %s, %s)" if t == "postgres" else "INSERT INTO users(username, email, password, tokens, last_reset, is_admin, plan, referral_code, referred_by) VALUES (?, ?, ?, ?, ?, 0, 'Free', ?, ?)"
        c.execute(q, (data["username"].lower(), data.get("email",""), generate_password_hash(data["password"]), 15+bonus, datetime.now(), ref_code, used_ref if bonus>0 else None))
        conn.commit(); return jsonify({"message": f"Registered! {'+10 Credits' if bonus else ''}"}), 201
    except: return jsonify({"message": "Username taken"}), 409
    finally: conn.close()

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json; conn, t = get_db_connection(); c = conn.cursor()
    q = "SELECT id, password FROM users WHERE username=%s" if t == "postgres" else "SELECT id, password FROM users WHERE username=?"
    c.execute(q, (data["username"].lower(),)); user = c.fetchone(); conn.close()
    if user and check_password_hash(user['password'], data["password"]):
        token = jwt.encode({'user_id': user['id'], 'exp': datetime.utcnow() + timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "Login success", "token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/api/status", methods=["GET"])
def get_status():
    user_id = get_user_from_token(request); conn, t = get_db_connection(); c = conn.cursor()
    try:
        q = "SELECT value FROM settings WHERE key=%s" if t == "postgres" else "SELECT value FROM settings WHERE key=?"
        c.execute(q, ('maintenance',)); m_row = c.fetchone()
        c.execute(q, ('announcement',)); a_row = c.fetchone()
    except: m_row, a_row = None, None
    maintenance = m_row['value'] if m_row else 'false'
    announcement = a_row['value'] if a_row else ''
    
    username, is_admin, plan = "", False, "Guest"
    if user_id:
        q = "SELECT username, is_admin, plan FROM users WHERE id=%s" if t == "postgres" else "SELECT username, is_admin, plan FROM users WHERE id=?"
        c.execute(q, (user_id,)); row = c.fetchone()
        if row: username, is_admin, plan = row['username'], (row['is_admin'] == 1), row['plan']
    conn.close()
    tokens, _ = check_tokens(request.remote_addr, user_id)
    return jsonify({"tokens": tokens, "is_logged_in": user_id is not None, "is_admin": is_admin, "username": username, "plan": plan, "maintenance": maintenance == 'true', "announcement": announcement})

@app.route("/api/payment/request", methods=["POST"])
def pay_req():
    user_id = get_user_from_token(request)
    if not user_id: return jsonify({"error": "Login required"}), 401
    file = request.files.get("screenshot")
    if file:
        filename = secure_filename(f"{user_id}_{int(time.time())}_{file.filename}")
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        conn, t = get_db_connection(); c = conn.cursor()
        uq = "SELECT username FROM users WHERE id=%s" if t == "postgres" else "SELECT username FROM users WHERE id=?"
        c.execute(uq, (user_id,)); u = c.fetchone()['username']
        iq = "INSERT INTO payment_requests (user_id, username, plan_name, screenshot_path, status, timestamp) VALUES (%s, %s, %s, %s, 'pending', %s)" if t == "postgres" else "INSERT INTO payment_requests (user_id, username, plan_name, screenshot_path, status, timestamp) VALUES (?, ?, ?, ?, 'pending', ?)"
        c.execute(iq, (user_id, u, request.form.get("plan_name"), filename, datetime.now())); conn.commit(); conn.close()
        return jsonify({"message": "Submitted"})
    return jsonify({"error": "No file"}), 400

@app.route("/uploads/<filename>")
def serve_up(filename):
    if not is_admin_request(request): return "Unauthorized", 403
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/api/contact", methods=["POST"])
def contact_submit():
    data = request.json; conn, t = get_db_connection(); c = conn.cursor()
    q = "INSERT INTO messages (name, email, message, timestamp) VALUES (%s, %s, %s, %s)" if t == "postgres" else "INSERT INTO messages (name, email, message, timestamp) VALUES (?, ?, ?, ?)"
    c.execute(q, (data.get("name"), data.get("email"), data.get("message"), datetime.now())); conn.commit(); conn.close()
    return jsonify({"message": "Message sent"})

# -------------------------
# ADMIN API 
# -------------------------
@app.route("/api/admin/messages", methods=["GET"])
def get_messages():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    c.execute("SELECT * FROM messages ORDER BY timestamp DESC"); rows = c.fetchall(); conn.close()
    return jsonify([dict(row) for row in rows])

@app.route("/api/admin/message/<int:msg_id>", methods=["DELETE"])
def delete_message(msg_id):
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    q = "DELETE FROM messages WHERE id=%s" if t == "postgres" else "DELETE FROM messages WHERE id=?"
    c.execute(q, (msg_id,)); conn.commit(); conn.close()
    return jsonify({"message": "Deleted"})

@app.route("/api/admin/settings", methods=["GET", "POST"])
def manage_settings():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    if request.method == "POST":
        data = request.json
        if t == "postgres":
            if "maintenance" in data: c.execute("INSERT INTO settings (key, value) VALUES ('maintenance', %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (str(data['maintenance']).lower(),))
            if "announcement" in data: c.execute("INSERT INTO settings (key, value) VALUES ('announcement', %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", (data['announcement'],))
        else:
            if "maintenance" in data: c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance', ?)", (str(data['maintenance']).lower(),))
            if "announcement" in data: c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('announcement', ?)", (data['announcement'],))
        conn.commit()
    q = "SELECT value FROM settings WHERE key=%s" if t == "postgres" else "SELECT value FROM settings WHERE key=?"
    c.execute(q, ('maintenance',)); m = c.fetchone()
    c.execute(q, ('announcement',)); a = c.fetchone()
    conn.close()
    return jsonify({"maintenance": (m['value'] == 'true') if m else False, "announcement": a['value'] if a else ""})

@app.route("/api/admin/ban", methods=["GET", "POST", "DELETE"])
def manage_bans():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    if request.method == "GET":
        c.execute("SELECT * FROM banned_ips"); bans = [dict(row) for row in c.fetchall()]; conn.close(); return jsonify(bans)
    if request.method == "POST":
        ip = request.json.get("ip")
        if ip:
            if t == "postgres": c.execute("INSERT INTO banned_ips (ip, reason, timestamp) VALUES (%s, 'Admin Ban', %s) ON CONFLICT (ip) DO UPDATE SET timestamp = EXCLUDED.timestamp", (ip, datetime.now()))
            else: c.execute("INSERT OR REPLACE INTO banned_ips (ip, reason, timestamp) VALUES (?, 'Admin Ban', ?)", (ip, datetime.now()))
        conn.commit()
    if request.method == "DELETE":
        ip = request.json.get("ip")
        q = "DELETE FROM banned_ips WHERE ip=%s" if t == "postgres" else "DELETE FROM banned_ips WHERE ip=?"
        c.execute(q, (ip,)); conn.commit()
    conn.close(); return jsonify({"message": "Updated"})

@app.route("/api/admin/requests", methods=["GET"])
def get_requests():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    c.execute("SELECT * FROM payment_requests WHERE status='pending' ORDER BY timestamp DESC"); rows = c.fetchall(); conn.close()
    return jsonify({"requests": [dict(row) for row in rows]})

@app.route("/api/admin/approve", methods=["POST"])
def approve_request():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    data = request.json; conn, t = get_db_connection(); c = conn.cursor()
    q = "SELECT user_id, plan_name FROM payment_requests WHERE id=%s" if t == "postgres" else "SELECT user_id, plan_name FROM payment_requests WHERE id=?"
    c.execute(q, (data.get("request_id"),)); req = c.fetchone()
    if not req: return jsonify({"error": "Not found"}), 404
    if data.get("action") == "approve":
        tokens = 999999 if "God" in req['plan_name'] else 50
        uq = "UPDATE users SET tokens = tokens + %s, plan = %s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + ?, plan = ? WHERE id=?"
        pq = "UPDATE payment_requests SET status='approved' WHERE id=%s" if t == "postgres" else "UPDATE payment_requests SET status='approved' WHERE id=?"
        c.execute(uq, (tokens, req['plan_name'], req['user_id'])); c.execute(pq, (data.get("request_id"),))
    else:
        pq = "UPDATE payment_requests SET status='rejected' WHERE id=%s" if t == "postgres" else "UPDATE payment_requests SET status='rejected' WHERE id=?"
        c.execute(pq, (data.get("request_id"),))
    conn.commit(); conn.close(); return jsonify({"message": "Processed"})

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    c.execute("SELECT id, username, email, tokens, is_admin, plan FROM users"); users = [dict(row) for row in c.fetchall()]; conn.close()
    return jsonify({"users": users})

@app.route("/api/admin/credits", methods=["POST"])
def admin_add_credits():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    q = "UPDATE users SET tokens = tokens + %s WHERE id=%s" if t == "postgres" else "UPDATE users SET tokens = tokens + ? WHERE id=?"
    c.execute(q, (int(request.json.get("amount",0)), request.json.get("user_id"))); conn.commit(); conn.close()
    return jsonify({"message": "Updated"})

@app.route("/api/admin/promote", methods=["POST"])
def promote():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    q = "UPDATE users SET is_admin = %s WHERE id = %s" if t == "postgres" else "UPDATE users SET is_admin = ? WHERE id = ?"
    c.execute(q, (1 if request.json.get("is_admin") else 0, request.json.get("user_id"))); conn.commit(); conn.close()
    return jsonify({"message": "Updated"})

@app.route("/api/admin/user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn, t = get_db_connection(); c = conn.cursor()
    q = "DELETE FROM users WHERE id = %s" if t == "postgres" else "DELETE FROM users WHERE id = ?"
    c.execute(q, (user_id,)); conn.commit(); conn.close()
    return jsonify({"message": "Deleted"})

@app.route("/api/admin/reset-password", methods=["POST"])
def admin_reset_pass():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    hashed = generate_password_hash(request.json.get("password"))
    conn, t = get_db_connection(); c = conn.cursor()
    q = "UPDATE users SET password = %s WHERE id = %s" if t == "postgres" else "UPDATE users SET password = ? WHERE id = ?"
    c.execute(q, (hashed, request.json.get("user_id"))); conn.commit(); conn.close()
    return jsonify({"message": "Reset"})

# -------------------------
# DOWNLOADER LOGIC (DESKTOP MODE + COOKIES)
# -------------------------
def format_bytes(size):
    if not size: return "N/A"
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power: size /= power; n += 1
    return f"{size:.2f} {power_labels[n]}B"

def safe_float(val):
    try: return float(val) if val else 0.0
    except: return 0.0

def get_video_formats(url):
    # USE COOKIES + DESKTOP USER AGENT
    ydl_opts = { 
        "quiet": True, 
        "no_warnings": True, 
        "noplaylist": True, 
        "extract_flat": "in_playlist",
        "http_headers": { 
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 
        },
        "cookiefile": COOKIE_FILE if os.path.exists(COOKIE_FILE) else None,
        "ffmpeg_location": FFMPEG_PATH
    }

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            formats_list = []
            is_insta = 'instagram' in info.get('webpage_url_domain', 'youtube')
            duration = safe_float(info.get('duration'))
            mp3_size = (128 * 1000 * duration) / 8 if duration > 0 else 0
            formats_list.append({"id": "mp3-128", "type": "audio", "quality": "128kbps", "ext": "mp3", "size": format_bytes(mp3_size)})

            if is_insta:
                f_size = safe_float(info.get('filesize') or info.get('filesize_approx'))
                formats_list.append({"id": "best", "type": "video", "quality": "HD (Best)", "ext": "mp4", "size": format_bytes(f_size)})
            else:
                seen_res = set()
                for f in info.get('formats', []):
                    h = f.get('height')
                    if not h or h in seen_res or h < 144: continue
                    seen_res.add(h)
                    if not FFMPEG_PATH and f.get('acodec') == 'none': continue 
                    f_size = safe_float(f.get('filesize') or f.get('filesize_approx'))
                    if f_size == 0 and duration > 0:
                        tbr = safe_float(f.get('tbr'))
                        if tbr > 0: f_size = (tbr * 1000 * duration) / 8
                    formats_list.append({"id": f"video-{h}", "type": "video", "quality": f"{h}p", "ext": "mp4", "size": format_bytes(f_size), "height": h})
                formats_list.sort(key=lambda x: x.get('height', 0), reverse=True)

            return { "title": info.get("title", "Video"), "thumbnail": info.get("thumbnail", ""), "duration": info.get("duration_string", "N/A"), "formats": formats_list }
    except Exception as e: 
        print(f"Info Error: {e}")
        return None

def process_download(job_id, url, fmt_id):
    with download_semaphore:
        job_status[job_id]["status"] = "downloading"
        def progress_hook(d):
            if d["status"] == "downloading":
                raw_percent = d.get("_percent_str", "0%")
                clean_percent = re.sub(r'\x1b\[[0-9;]*m', '', raw_percent).strip()
                job_status[job_id].update({"percent": clean_percent.replace("%",""), "speed": d.get("_speed_str", "N/A")})

        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, f"{job_id}_%(title)s.%(ext)s"),
            "progress_hooks": [progress_hook],
            "quiet": True,
            "concurrent_fragment_downloads": 10,
            "buffersize": 1024 * 1024,
            "http_headers": { 
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 
            },
            "cookiefile": COOKIE_FILE if os.path.exists(COOKIE_FILE) else None,
            "ffmpeg_location": FFMPEG_PATH
        }

        if "mp3" in fmt_id:
            ydl_opts["format"] = "bestaudio/best"
            if FFMPEG_PATH: ydl_opts["postprocessors"] = [{"key": "FFmpegExtractAudio","preferredcodec": "mp3"}]
        elif fmt_id == "best": ydl_opts["format"] = "best"
        elif "video" in fmt_id:
            height = fmt_id.replace("video-", "")
            if FFMPEG_PATH:
                ydl_opts["format"] = f"best[height<={height}]/bestvideo[height<={height}]+bestaudio/best[height<={height}]"
                ydl_opts["merge_output_format"] = "mp4"
            else: ydl_opts["format"] = f"best[height<={height}]"

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.extract_info(url, download=True)
                for f in os.listdir(DOWNLOAD_FOLDER):
                    if f.startswith(job_id):
                        job_status[job_id].update({"status": "completed", "file": os.path.join(DOWNLOAD_FOLDER, f), "filename": f})
                        return
                raise Exception("File missing")
        except Exception as e:
            job_status[job_id].update({"status": "error", "error": str(e)})

@app.route("/api/info", methods=["POST", "OPTIONS"])
def api_info(): 
    if request.method == "OPTIONS": return jsonify({"status":"ok"}), 200
    res = get_video_formats(request.json.get("url"))
    return jsonify(res) if res else (jsonify({"error": "Failed"}), 400)

@app.route("/api/download", methods=["POST", "OPTIONS"])
def api_download():
    if request.method == "OPTIONS": return jsonify({"status":"ok"}), 200
    ip = request.remote_addr
    if is_banned(ip): return jsonify({"error": "BANNED", "message": "IP Banned"}), 403
    
    conn, t = get_db_connection(); c = conn.cursor()
    q = "SELECT value FROM settings WHERE key=%s" if t == "postgres" else "SELECT value FROM settings WHERE key=?"
    c.execute(q, ('maintenance',)); m = c.fetchone(); conn.close()
    if m and m['value'] == 'true' and not is_admin_request(request): return jsonify({"error": "MAINTENANCE", "message": "Under maintenance"}), 503

    user_id = get_user_from_token(request)
    tokens_left, _ = check_tokens(ip, user_id)

    if tokens_left <= 0:
        msg = "Daily limit reached (15/15)." if user_id else "Guest limit reached (5/5). Login for more!"
        return jsonify({"error": "LIMIT_REACHED", "message": msg}), 403

    consume_token(ip, user_id)
    data = request.json
    job_id = str(uuid.uuid4())
    job_status[job_id] = {"status": "queued", "percent": "0"}
    executor.submit(process_download, job_id, data.get("url"), data.get("format_id"))
    return jsonify({"job_id": job_id})

@app.route("/api/progress/<job_id>")
def api_progress(job_id): return jsonify(job_status.get(job_id, {"status": "unknown"}))

@app.route("/api/file/<job_id>")
def api_file(job_id):
    job = job_status.get(job_id)
    if job and job.get("status") == "completed": return send_file(job["file"], as_attachment=True, download_name=job["filename"])
    return jsonify({"error": "Not ready"}), 404

def cleanup_files():
    while True:
        now = time.time()
        for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
            try:
                for f in os.listdir(folder):
                    f_path = os.path.join(folder, f)
                    if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 3600: os.remove(f_path)
            except: pass
        time.sleep(600)
threading.Thread(target=cleanup_files, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
