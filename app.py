from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import yt_dlp
import os
import shutil
import uuid
import time
import threading
import re
import sqlite3
import jwt 
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# SETUP: Serve static files from the current directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)

# -------------------------
# SECURITY FIX: PERSISTENT SECRET KEY
# -------------------------
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
COOKIE_FILE = os.path.join(BASE_DIR, "cookies.txt") # Added Cookie Path

def get_secret_key():
    if os.environ.get('SECRET_KEY'):
        return os.environ.get('SECRET_KEY')
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, 'w') as f:
            f.write(key)
    except: pass 
    return key

app.config['SECRET_KEY'] = get_secret_key()

# -------------------------
# SETUP & CONFIG
# -------------------------
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# --- FIXED FFMPEG DETECTION FOR RENDER ---
if os.path.exists(os.path.join(BASE_DIR, "ffmpeg.exe")):
    FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg.exe") # Windows Local
elif os.path.exists(os.path.join(BASE_DIR, "ffmpeg")):
    FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg") # Linux/Render Local (IMPORTANT)
elif shutil.which("ffmpeg"):
    FFMPEG_PATH = shutil.which("ffmpeg") # System installed
else:
    FFMPEG_PATH = None # Not found

# Database Path
DB_PATH = os.environ.get('DB_PATH', os.path.join(BASE_DIR, "users.db"))

for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

print(f"🚀 System Check: FFmpeg Path: {FFMPEG_PATH or '❌ MISSING'}")
print(f"📂 Database Path: {DB_PATH}")

MAX_CONCURRENT_DOWNLOADS = int(os.environ.get('MAX_WORKERS', 2))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS) 
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
job_status = {}

# -------------------------
# DATABASE SETUP
# -------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            tokens INTEGER DEFAULT 15,
            last_reset DATETIME,
            is_admin INTEGER DEFAULT 0,
            plan TEXT DEFAULT 'Free'
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS guests (
            ip TEXT PRIMARY KEY,
            tokens INTEGER DEFAULT 5,
            last_reset DATETIME
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS payment_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            plan_name TEXT,
            screenshot_path TEXT,
            status TEXT DEFAULT 'pending',
            timestamp DATETIME
        )
    """)
    
    try: c.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN plan TEXT DEFAULT 'Free'")
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except: pass

    # Create Admin
    c.execute("SELECT * FROM users WHERE username='ashishadmin'")
    if not c.fetchone():
        hashed = generate_password_hash("anu9936")
        c.execute("INSERT INTO users (username, password, tokens, last_reset, is_admin, plan) VALUES (?, ?, 999999, ?, 1, 'God Mode')", 
                  ('ashishadmin', hashed, datetime.now()))
        print("👑 Admin account created: ashishadmin")

    conn.commit()
    conn.close()

init_db()

# -------------------------
# TOKEN LOGIC
# -------------------------
def check_tokens(ip, user_id=None):
    conn = get_db_connection()
    c = conn.cursor()
    now = datetime.now()
    
    if user_id:
        c.execute("SELECT tokens, last_reset, plan FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        if not row: return 0, False
        tokens, last_reset_str, plan = row
        last_reset = datetime.strptime(last_reset_str, "%Y-%m-%d %H:%M:%S.%f") if last_reset_str else datetime.min
        
        if tokens < 15 and (now - last_reset > timedelta(hours=12)):
            c.execute("UPDATE users SET tokens=15, last_reset=? WHERE id=?", (now, user_id))
            conn.commit()
            tokens = 15
        
        if plan == "God Mode" and tokens < 9999:
            tokens = 9999
            
        return tokens, False
    else:
        c.execute("SELECT tokens, last_reset FROM guests WHERE ip=?", (ip,))
        row = c.fetchone()
        if not row:
            c.execute("INSERT INTO guests (ip, tokens, last_reset) VALUES (?, 5, ?)", (ip, now))
            conn.commit()
            return 5, False
        tokens, last_reset_str = row
        last_reset = datetime.strptime(last_reset_str, "%Y-%m-%d %H:%M:%S.%f") if last_reset_str else datetime.min
        if now - last_reset > timedelta(hours=12):
            c.execute("UPDATE guests SET tokens=5, last_reset=? WHERE ip=?", (now, ip))
            conn.commit()
            tokens = 5
        return tokens, False

def consume_token(ip, user_id=None):
    conn = get_db_connection()
    c = conn.cursor()
    if user_id:
        c.execute("UPDATE users SET tokens = tokens - 1 WHERE id=?", (user_id,))
    else:
        c.execute("UPDATE guests SET tokens = tokens - 1 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

def get_user_from_token(request):
    try:
        token = request.headers.get("Authorization").split()[1]
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        return decoded['user_id']
    except: return None

def is_admin_request(request):
    user_id = get_user_from_token(request)
    if not user_id: return False
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row and row[0] == 1

# -------------------------
# ROUTES
# -------------------------
@app.route('/')
def index():
    return send_file('index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(BASE_DIR, path)):
        return send_from_directory(BASE_DIR, path)
    return send_file('index.html')

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"].lower()
    hashed = generate_password_hash(data["password"])
    email = data.get("email", "")
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO users(username, email, password, tokens, last_reset, is_admin, plan) VALUES (?, ?, ?, 15, ?, 0, 'Free')", 
                  (username, email, hashed, datetime.now()))
        conn.commit()
        return jsonify({"message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username taken"}), 409
    finally: conn.close()

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"].lower()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user and check_password_hash(user[1], data["password"]):
        token = jwt.encode({'user_id': user[0], 'exp': datetime.utcnow() + timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "Login success", "token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/api/status", methods=["GET"])
def get_status():
    user_id = get_user_from_token(request)
    is_admin = False
    username = ""
    plan = "Guest"
    
    if user_id:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT username, is_admin, plan FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        if row:
            username = row[0]
            is_admin = (row[1] == 1)
            plan = row[2]
        conn.close()
        
    ip = request.remote_addr
    tokens, _ = check_tokens(ip, user_id)
    return jsonify({
        "tokens": tokens, 
        "is_logged_in": user_id is not None,
        "is_admin": is_admin,
        "username": username,
        "plan": plan
    })

@app.route("/api/payment/request", methods=["POST"])
def payment_request():
    user_id = get_user_from_token(request)
    if not user_id: return jsonify({"error": "Login required"}), 401
    
    plan_name = request.form.get("plan_name")
    file = request.files.get("screenshot")
    if not file or not plan_name:
        return jsonify({"error": "Missing data"}), 400

    filename = secure_filename(f"{user_id}_{int(time.time())}_{file.filename}")
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(save_path)
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id=?", (user_id,))
    username = c.fetchone()[0]
    
    c.execute("INSERT INTO payment_requests (user_id, username, plan_name, screenshot_path, status, timestamp) VALUES (?, ?, ?, ?, 'pending', ?)",
              (user_id, username, plan_name, filename, datetime.now()))
    conn.commit()
    conn.close()
    return jsonify({"message": "Request submitted"})

@app.route("/uploads/<filename>")
def serve_screenshot(filename):
    if not is_admin_request(request): return "Unauthorized", 403
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/api/admin/requests", methods=["GET"])
def get_requests():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM payment_requests WHERE status='pending' ORDER BY timestamp DESC")
    rows = c.fetchall()
    requests = [dict(row) for row in rows]
    conn.close()
    return jsonify({"requests": requests})

@app.route("/api/admin/approve", methods=["POST"])
def approve_request():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    req_id = data.get("request_id")
    action = data.get("action")
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT user_id, plan_name FROM payment_requests WHERE id=?", (req_id,))
    req = c.fetchone()
    
    if not req: return jsonify({"error": "Not found"}), 404
    user_id, plan_name = req
    
    if action == "approve":
        tokens_to_add = 0
        if "Booster" in plan_name: tokens_to_add = 50
        elif "God" in plan_name: tokens_to_add = 999999
        c.execute("UPDATE users SET tokens = tokens + ?, plan = ? WHERE id=?", (tokens_to_add, plan_name, user_id))
        c.execute("UPDATE payment_requests SET status='approved' WHERE id=?", (req_id,))
        msg = "Approved and Plan Updated"
    else:
        c.execute("UPDATE payment_requests SET status='rejected' WHERE id=?", (req_id,))
        msg = "Rejected"

    conn.commit()
    conn.close()
    return jsonify({"message": msg})

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, email, tokens, is_admin, plan FROM users")
    users = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({"users": users})

@app.route("/api/admin/credits", methods=["POST"])
def add_credits():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET tokens = tokens + ? WHERE id=?", (int(data.get("amount",0)), data.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Credits updated"})

@app.route("/api/admin/promote", methods=["POST"])
def promote_user():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if data.get("is_admin") else 0, data.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Updated"})

@app.route("/api/admin/user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})

@app.route("/api/admin/reset-password", methods=["POST"])
def reset_password():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    hashed = generate_password_hash(data.get("password"))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, data.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Reset"})

# -------------------------
# DOWNLOADER LOGIC (FIXED WITH COOKIES)
# -------------------------
def format_bytes(size):
    if not size: return "N/A"
    power = 2**10
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}B"

def safe_float(val):
    try: return float(val) if val else 0.0
    except: return 0.0

def get_video_formats(url):
    ydl_opts = { 
        "quiet": True, 
        "no_warnings": True, 
        "noplaylist": True, 
        "extract_flat": "in_playlist", 
        "http_headers": { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" } 
    }
    
    # 🍪 COOKIES FIX: Add this to your old code
    if os.path.exists(COOKIE_FILE):
        ydl_opts['cookiefile'] = COOKIE_FILE

    if FFMPEG_PATH: ydl_opts["ffmpeg_location"] = FFMPEG_PATH

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
                    if not FFMPEG_PATH and f.get('acodec') == 'none': continue # Skip video-only if no FFmpeg
                    f_size = safe_float(f.get('filesize') or f.get('filesize_approx'))
                    if f_size == 0 and duration > 0:
                        tbr = safe_float(f.get('tbr'))
                        if tbr > 0: f_size = (tbr * 1000 * duration) / 8
                    formats_list.append({"id": f"video-{h}", "type": "video", "quality": f"{h}p", "ext": "mp4", "size": format_bytes(f_size), "height": h})
                formats_list.sort(key=lambda x: x.get('height', 0), reverse=True)

            return { "title": info.get("title", "Video"), "thumbnail": info.get("thumbnail", ""), "duration": info.get("duration_string", "N/A"), "formats": formats_list }
    except Exception as e: return None

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
            "concurrent_fragment_downloads": 5,
            "buffersize": 1024,
            "http_headers": { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" }
        }
        
        # 🍪 COOKIES FIX HERE TOO
        if os.path.exists(COOKIE_FILE):
            ydl_opts['cookiefile'] = COOKIE_FILE

        if FFMPEG_PATH: ydl_opts["ffmpeg_location"] = FFMPEG_PATH

        if "mp3" in fmt_id:
            ydl_opts["format"] = "bestaudio/best"
            if FFMPEG_PATH:
                ydl_opts["postprocessors"] = [{"key": "FFmpegExtractAudio","preferredcodec": "mp3"}]
        elif fmt_id == "best": ydl_opts["format"] = "best"
        elif "video" in fmt_id:
            height = fmt_id.replace("video-", "")
            ydl_opts["format"] = f"bestvideo[height<={height}]+bestaudio/best[height<={height}]" if FFMPEG_PATH else f"best[height<={height}]"
            if FFMPEG_PATH: ydl_opts["merge_output_format"] = "mp4"

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

@app.route("/api/info", methods=["POST"])
def api_info(): return jsonify(get_video_formats(request.json.get("url")) or {"error": "Failed"})

@app.route("/api/download", methods=["POST"])
def api_download():
    user_id = get_user_from_token(request)
    ip = request.remote_addr
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
                    if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 3600:
                        os.remove(f_path)
            except: pass
        time.sleep(600)
threading.Thread(target=cleanup_files, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
