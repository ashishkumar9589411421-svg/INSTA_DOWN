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

# -------------------------
# CONFIGURATION & SETUP
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)

# Persistent Secret Key (Crucial for Render)
SECRET_FILE = os.path.join(BASE_DIR, "secret.key")
COOKIE_FILE = os.path.join(BASE_DIR, "cookies.txt")

def get_secret_key():
    if os.environ.get('SECRET_KEY'):
        return os.environ.get('SECRET_KEY')
    if os.path.exists(SECRET_FILE):
        try:
            with open(SECRET_FILE, 'r') as f:
                return f.read().strip()
        except: pass
    key = secrets.token_hex(32)
    try:
        with open(SECRET_FILE, 'w') as f:
            f.write(key)
    except: pass 
    return key

app.config['SECRET_KEY'] = get_secret_key()

# Folders
DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.environ.get('DB_PATH', os.path.join(BASE_DIR, "users.db"))

for folder in [DOWNLOAD_FOLDER, UPLOAD_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

# FFmpeg Detection (Windows + Linux/Render)
if os.path.exists(os.path.join(BASE_DIR, "ffmpeg.exe")):
    FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg.exe") 
elif os.path.exists(os.path.join(BASE_DIR, "ffmpeg")):
    FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg") 
elif shutil.which("ffmpeg"):
    FFMPEG_PATH = shutil.which("ffmpeg") 
else:
    FFMPEG_PATH = None 

# --- SYSTEM DIAGNOSTICS (DEBUGGING) ---
print("\n" + "="*40)
print("🚀 SYSTEM STARTUP CHECKS")
print(f"📂 Base Directory: {BASE_DIR}")
print(f"🎥 FFmpeg Path: {FFMPEG_PATH or '❌ MISSING (Videos will fail)'}")
if os.path.exists(COOKIE_FILE):
    print(f"✅ COOKIES FOUND ({os.path.getsize(COOKIE_FILE)} bytes)")
else:
    print("❌ COOKIES NOT FOUND (Instagram downloads may fail)")
print("="*40 + "\n")

# Threading
MAX_CONCURRENT_DOWNLOADS = int(os.environ.get('MAX_WORKERS', 2))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS) 
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
job_status = {}

# -------------------------
# DATABASE ENGINE
# -------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row # Access columns by name
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Tables
    c.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT, password TEXT, tokens INTEGER DEFAULT 15, last_reset DATETIME, is_admin INTEGER DEFAULT 0, plan TEXT DEFAULT 'Free')""")
    c.execute("""CREATE TABLE IF NOT EXISTS guests (ip TEXT PRIMARY KEY, tokens INTEGER DEFAULT 5, last_reset DATETIME)""")
    c.execute("""CREATE TABLE IF NOT EXISTS payment_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, plan_name TEXT, screenshot_path TEXT, status TEXT DEFAULT 'pending', timestamp DATETIME)""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, reason TEXT, timestamp DATETIME)""")

    # Create Admin (ashishadmin)
    try:
        c.execute("SELECT * FROM users WHERE username='ashishadmin'")
        if not c.fetchone():
            hashed = generate_password_hash("anu9936")
            c.execute("INSERT INTO users (username, password, tokens, last_reset, is_admin, plan) VALUES (?, ?, 999999, ?, 1, 'God Mode')", 
                      ('ashishadmin', hashed, datetime.now()))
            print("👑 Admin 'ashishadmin' created.")
    except Exception as e:
        print(f"Admin init warning: {e}")

    conn.commit()
    conn.close()

init_db()

# -------------------------
# HELPERS
# -------------------------
def is_banned(ip):
    conn = get_db_connection()
    banned = conn.execute("SELECT * FROM banned_ips WHERE ip=?", (ip,)).fetchone()
    conn.close()
    return banned is not None

def check_tokens(ip, user_id=None):
    conn = get_db_connection()
    now = datetime.now()
    
    if user_id:
        row = conn.execute("SELECT tokens, last_reset, plan FROM users WHERE id=?", (user_id,)).fetchone()
        if not row: return 0, False
        tokens, last_reset_str, plan = row['tokens'], row['last_reset'], row['plan']
        
        try: last_reset = datetime.strptime(str(last_reset_str).split('.')[0], "%Y-%m-%d %H:%M:%S")
        except: last_reset = datetime.min

        if tokens < 15 and (now - last_reset > timedelta(hours=12)):
            conn.execute("UPDATE users SET tokens=15, last_reset=? WHERE id=?", (now, user_id))
            conn.commit()
            tokens = 15
        
        if plan == "God Mode": tokens = 999999
        return tokens, False
    else:
        row = conn.execute("SELECT tokens, last_reset FROM guests WHERE ip=?", (ip,)).fetchone()
        if not row:
            conn.execute("INSERT INTO guests (ip, tokens, last_reset) VALUES (?, 5, ?)", (ip, now))
            conn.commit()
            return 5, False
        tokens, last_reset_str = row['tokens'], row['last_reset']
        
        try: last_reset = datetime.strptime(str(last_reset_str).split('.')[0], "%Y-%m-%d %H:%M:%S")
        except: last_reset = datetime.min
            
        if now - last_reset > timedelta(hours=12):
            conn.execute("UPDATE guests SET tokens=5, last_reset=? WHERE ip=?", (now, ip))
            conn.commit()
            tokens = 5
        return tokens, False

def consume_token(ip, user_id=None):
    conn = get_db_connection()
    if user_id: conn.execute("UPDATE users SET tokens = tokens - 1 WHERE id=?", (user_id,))
    else: conn.execute("UPDATE guests SET tokens = tokens - 1 WHERE ip=?", (ip,))
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
    row = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return row and row['is_admin'] == 1

# -------------------------
# GENERAL ROUTES
# -------------------------
@app.route('/')
def index(): return send_file('index.html')

@app.route('/<path:path>')
def serve_static(path):
    if os.path.exists(os.path.join(BASE_DIR, path)): return send_from_directory(BASE_DIR, path)
    return send_file('index.html')

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO users(username, email, password, tokens, last_reset, is_admin, plan) VALUES (?, ?, ?, 15, ?, 0, 'Free')", 
                  (data["username"].lower(), data.get("email",""), generate_password_hash(data["password"]), datetime.now()))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered"}), 201
    except: return jsonify({"message": "Username taken"}), 409

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    conn = get_db_connection()
    user = conn.execute("SELECT id, password FROM users WHERE username=?", (data["username"].lower(),)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], data["password"]):
        token = jwt.encode({'user_id': user['id'], 'exp': datetime.utcnow() + timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "Login success", "token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/api/status", methods=["GET"])
def get_status():
    user_id = get_user_from_token(request)
    conn = get_db_connection()
    
    # Settings
    m_row = conn.execute("SELECT value FROM settings WHERE key='maintenance'").fetchone()
    a_row = conn.execute("SELECT value FROM settings WHERE key='announcement'").fetchone()
    maintenance = m_row['value'] if m_row else 'false'
    announcement = a_row['value'] if a_row else ''
    
    username, is_admin, plan = "", False, "Guest"
    if user_id:
        row = conn.execute("SELECT username, is_admin, plan FROM users WHERE id=?", (user_id,)).fetchone()
        if row: username, is_admin, plan = row['username'], (row['is_admin'] == 1), row['plan']
    conn.close()
    
    tokens, _ = check_tokens(request.remote_addr, user_id)
    return jsonify({
        "tokens": tokens, "is_logged_in": user_id is not None, "is_admin": is_admin, "username": username, "plan": plan,
        "maintenance": maintenance == 'true', "announcement": announcement
    })

@app.route("/api/payment/request", methods=["POST"])
def pay_req():
    user_id = get_user_from_token(request)
    if not user_id: return jsonify({"error": "Login required"}), 401
    file = request.files.get("screenshot")
    if file:
        filename = secure_filename(f"{user_id}_{int(time.time())}_{file.filename}")
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        conn = get_db_connection()
        u = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()['username']
        conn.execute("INSERT INTO payment_requests (user_id, username, plan_name, screenshot_path, status, timestamp) VALUES (?, ?, ?, ?, 'pending', ?)",
                (user_id, u, request.form.get("plan_name"), filename, datetime.now()))
        conn.commit()
        conn.close()
        return jsonify({"message": "Submitted"})
    return jsonify({"error": "No file"}), 400

@app.route("/uploads/<filename>")
def serve_up(filename):
    if not is_admin_request(request): return "Unauthorized", 403
    return send_from_directory(UPLOAD_FOLDER, filename)

# -------------------------
# ADMIN ROUTES (RESTORED)
# -------------------------
@app.route("/api/admin/settings", methods=["GET", "POST"])
def manage_settings():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    if request.method == "POST":
        data = request.json
        if "maintenance" in data: conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('maintenance', ?)", (str(data['maintenance']).lower(),))
        if "announcement" in data: conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('announcement', ?)", (data['announcement'],))
        conn.commit()
    
    m = conn.execute("SELECT value FROM settings WHERE key='maintenance'").fetchone()
    a = conn.execute("SELECT value FROM settings WHERE key='announcement'").fetchone()
    conn.close()
    return jsonify({"maintenance": (m['value'] == 'true') if m else False, "announcement": a['value'] if a else ""})

@app.route("/api/admin/ban", methods=["GET", "POST", "DELETE"])
def manage_bans():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    if request.method == "GET":
        bans = [dict(row) for row in conn.execute("SELECT * FROM banned_ips").fetchall()]
        conn.close()
        return jsonify(bans)
    
    if request.method == "POST":
        ip = request.json.get("ip")
        if ip: conn.execute("INSERT OR REPLACE INTO banned_ips (ip, reason, timestamp) VALUES (?, 'Admin Ban', ?)", (ip, datetime.now()))
        conn.commit()
        conn.close()
        return jsonify({"message": "IP Banned"})

    if request.method == "DELETE":
        ip = request.json.get("ip")
        conn.execute("DELETE FROM banned_ips WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
        return jsonify({"message": "IP Unbanned"})

@app.route("/api/admin/requests", methods=["GET"])
def get_requests():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM payment_requests WHERE status='pending' ORDER BY timestamp DESC").fetchall()
    conn.close()
    return jsonify({"requests": [dict(row) for row in rows]})

@app.route("/api/admin/approve", methods=["POST"])
def approve_request():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    data = request.json
    conn = get_db_connection()
    req = conn.execute("SELECT user_id, plan_name FROM payment_requests WHERE id=?", (data.get("request_id"),)).fetchone()
    if not req: return jsonify({"error": "Not found"}), 404
    
    if data.get("action") == "approve":
        tokens = 999999 if "God" in req['plan_name'] else 50
        conn.execute("UPDATE users SET tokens = tokens + ?, plan = ? WHERE id=?", (tokens, req['plan_name'], req['user_id']))
        conn.execute("UPDATE payment_requests SET status='approved' WHERE id=?", (data.get("request_id"),))
    else:
        conn.execute("UPDATE payment_requests SET status='rejected' WHERE id=?", (data.get("request_id"),))
    conn.commit()
    conn.close()
    return jsonify({"message": "Processed"})

@app.route("/api/admin/users", methods=["GET"])
def get_all_users():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    users = [dict(row) for row in conn.execute("SELECT id, username, email, tokens, is_admin, plan FROM users").fetchall()]
    conn.close()
    return jsonify({"users": users})

@app.route("/api/admin/credits", methods=["POST"])
def admin_add_credits():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    conn.execute("UPDATE users SET tokens = tokens + ? WHERE id=?", (int(request.json.get("amount",0)), request.json.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Updated"})

@app.route("/api/admin/promote", methods=["POST"])
def promote():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    conn.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if request.json.get("is_admin") else 0, request.json.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Updated"})

@app.route("/api/admin/user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted"})

@app.route("/api/admin/reset-password", methods=["POST"])
def admin_reset_pass():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    hashed = generate_password_hash(request.json.get("password"))
    conn = get_db_connection()
    conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, request.json.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Reset"})

# -------------------------
# DOWNLOADER LOGIC (WITH COOKIES)
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
    ydl_opts = { 
        "quiet": True, 
        "no_warnings": True, 
        "noplaylist": True, 
        "extract_flat": "in_playlist", 
        "http_headers": { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" }
    }
    
    # 🍪 COOKIES LOAD
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
                    if not FFMPEG_PATH and f.get('acodec') == 'none': continue 
                    f_size = safe_float(f.get('filesize') or f.get('filesize_approx'))
                    if f_size == 0 and duration > 0:
                        tbr = safe_float(f.get('tbr'))
                        if tbr > 0: f_size = (tbr * 1000 * duration) / 8
                    formats_list.append({"id": f"video-{h}", "type": "video", "quality": f"{h}p", "ext": "mp4", "size": format_bytes(f_size), "height": h})
                formats_list.sort(key=lambda x: x.get('height', 0), reverse=True)

            return { "title": info.get("title", "Video"), "thumbnail": info.get("thumbnail", ""), "duration": info.get("duration_string", "N/A"), "formats": formats_list }
    except Exception as e:
        print(f"❌ INFO ERROR: {e}")
        return None

def process_download(job_id, url, fmt_id):
    with download_semaphore:
        job_status[job_id]["status"] = "downloading"
        
        def progress_hook(d):
            if d["status"] == "downloading":
                # Clean up percentage string to avoid errors
                raw_percent = d.get("_percent_str", "0%")
                clean_percent = re.sub(r'\x1b\[[0-9;]*m', '', raw_percent).strip()
                job_status[job_id].update({"percent": clean_percent.replace("%",""), "speed": d.get("_speed_str", "N/A")})

        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, f"{job_id}_%(title)s.%(ext)s"),
            "progress_hooks": [progress_hook],
            "quiet": True,
            
            # --- 🚀 SPEED OPTIMIZATION SETTINGS ---
            "format": "best", # Avoid merging if possible (merging takes CPU time)
            "concurrent_fragment_downloads": 10, # Download 10 parts at once (Faster on Cloud)
            "buffersize": 1024 * 1024, # Larger buffer (1MB) for stable speed
            "http_headers": { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
            
            # Use aria2c if available (optional, but faster external downloader)
            # "external_downloader": "aria2c", 
            # "external_downloader_args": ["-x", "16", "-k", "1M"]
        }
        
        # Cookie Check
        if os.path.exists(COOKIE_FILE):
            ydl_opts['cookiefile'] = COOKIE_FILE

        if FFMPEG_PATH: ydl_opts["ffmpeg_location"] = FFMPEG_PATH

        # --- OPTIMIZED FORMAT SELECTION ---
        # If user wants MP3, we MUST use FFmpeg (CPU intensive but necessary)
        if "mp3" in fmt_id:
            ydl_opts["format"] = "bestaudio/best"
            if FFMPEG_PATH:
                ydl_opts["postprocessors"] = [{
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": "mp3",
                    "preferredquality": "128"
                }]
        
        # If user wants Video, try to avoid "merging" video+audio if a single file exists
        elif fmt_id == "best": 
            ydl_opts["format"] = "best" # 'best' usually gets a single pre-merged file (Fastest)
        
        elif "video" in fmt_id:
            height = fmt_id.replace("video-", "")
            # Try to find a single file with that height first to avoid FFmpeg merge
            if FFMPEG_PATH:
                ydl_opts["format"] = f"best[height<={height}]/bestvideo[height<={height}]+bestaudio/best[height<={height}]"
                ydl_opts["merge_output_format"] = "mp4"
            else:
                 ydl_opts["format"] = f"best[height<={height}]"

        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.extract_info(url, download=True)
                # Find the file that was just created
                for f in os.listdir(DOWNLOAD_FOLDER):
                    if f.startswith(job_id):
                        job_status[job_id].update({
                            "status": "completed", 
                            "file": os.path.join(DOWNLOAD_FOLDER, f), 
                            "filename": f
                        })
                        return
                raise Exception("File missing after download")
        except Exception as e:
            print(f"❌ DOWNLOAD ERROR: {e}")
            job_status[job_id].update({"status": "error", "error": str(e)})

            
@app.route("/api/info", methods=["POST"])
def api_info(): 
    res = get_video_formats(request.json.get("url"))
    return jsonify(res) if res else (jsonify({"error": "Failed"}), 400)

@app.route("/api/download", methods=["POST"])
def api_download():
    ip = request.remote_addr
    
    # Check Bans
    if is_banned(ip): return jsonify({"error": "BANNED", "message": "IP Banned"}), 403
    
    # Check Maintenance
    conn = get_db_connection()
    m = conn.execute("SELECT value FROM settings WHERE key='maintenance'").fetchone()
    conn.close()
    if m and m['value'] == 'true' and not is_admin_request(request):
        return jsonify({"error": "MAINTENANCE", "message": "Under maintenance"}), 503

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
                    if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 3600:
                        os.remove(f_path)
            except: pass
        time.sleep(600)
threading.Thread(target=cleanup_files, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
