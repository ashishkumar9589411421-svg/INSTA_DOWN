import os
import shutil
import uuid
import time
import threading
import sqlite3
import jwt 
import secrets
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import yt_dlp

# -------------------------
# CONFIGURATION
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path='')
CORS(app)

# Secret Key (Use Env Var in Production)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Render specific paths (Use /tmp for ephemeral storage if not persistent)
# Note: On free Render, /tmp is wiped on restart. 
if os.environ.get('RENDER'):
    DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads") # We create this in build.sh
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    DB_PATH = os.path.join(BASE_DIR, "users.db")
    # FFmpeg path from our build script
    FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg")
else:
    DOWNLOAD_FOLDER = os.path.join(BASE_DIR, "downloads")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    DB_PATH = os.path.join(BASE_DIR, "users.db")
    # Local FFmpeg check
    if os.path.exists(os.path.join(BASE_DIR, "ffmpeg.exe")):
        FFMPEG_PATH = os.path.join(BASE_DIR, "ffmpeg.exe") 
    elif shutil.which("ffmpeg"):
        FFMPEG_PATH = shutil.which("ffmpeg") 
    else:
        FFMPEG_PATH = None 

# Ensure directories exist
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Threading
MAX_CONCURRENT_DOWNLOADS = int(os.environ.get('MAX_WORKERS', 4))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS) 
download_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_DOWNLOADS)
job_status = {}

# -------------------------
# DATABASE ENGINE
# -------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row # Return dict-like rows
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Core Tables
    c.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, email TEXT, password TEXT, tokens INTEGER DEFAULT 15, last_reset DATETIME, is_admin INTEGER DEFAULT 0, plan TEXT DEFAULT 'Free')""")
    c.execute("""CREATE TABLE IF NOT EXISTS guests (ip TEXT PRIMARY KEY, tokens INTEGER DEFAULT 5, last_reset DATETIME)""")
    c.execute("""CREATE TABLE IF NOT EXISTS payment_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, plan_name TEXT, screenshot_path TEXT, status TEXT DEFAULT 'pending', timestamp DATETIME)""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, reason TEXT, timestamp DATETIME)""")

    # Create Admin if not exists
    try:
        c.execute("SELECT * FROM users WHERE username='ashishadmin'")
        if not c.fetchone():
            print("Creating Admin Account...")
            hashed = generate_password_hash("anu9936")
            c.execute("INSERT INTO users (username, password, tokens, last_reset, is_admin, plan) VALUES (?, ?, 999999, ?, 1, 'God Mode')", 
                    ('ashishadmin', hashed, datetime.now()))
    except Exception as e:
        print(f"Admin creation error: {e}")

    # Default Settings
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('maintenance', 'false')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('announcement', '')")

    conn.commit()
    conn.close()

# Initialize DB on start
init_db()

# -------------------------
# HELPER FUNCTIONS
# -------------------------
def get_setting(key):
    try:
        conn = get_db_connection()
        val = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        conn.close()
        return val['value'] if val else None
    except: return None

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
        if not row: 
            conn.close()
            return 0, False
        
        tokens, last_reset_str, plan = row['tokens'], row['last_reset'], row['plan']
        
        # Handle datetime parsing safely
        try:
            last_reset = datetime.strptime(str(last_reset_str).split('.')[0], "%Y-%m-%d %H:%M:%S")
        except:
            last_reset = datetime.min

        if tokens < 15 and (now - last_reset > timedelta(hours=24)):
            conn.execute("UPDATE users SET tokens=15, last_reset=? WHERE id=?", (now, user_id))
            conn.commit()
            tokens = 15
            
        if plan == "God Mode": tokens = 999999
        conn.close()
        return tokens, False
    else:
        row = conn.execute("SELECT tokens, last_reset FROM guests WHERE ip=?", (ip,)).fetchone()
        if not row:
            conn.execute("INSERT INTO guests (ip, tokens, last_reset) VALUES (?, 5, ?)", (ip, now))
            conn.commit()
            conn.close()
            return 5, False
        
        tokens, last_reset_str = row['tokens'], row['last_reset']
        try:
            last_reset = datetime.strptime(str(last_reset_str).split('.')[0], "%Y-%m-%d %H:%M:%S")
        except:
            last_reset = datetime.min
            
        if now - last_reset > timedelta(hours=24):
            conn.execute("UPDATE guests SET tokens=5, last_reset=? WHERE ip=?", (now, ip))
            conn.commit()
            tokens = 5
            
        conn.close()
        return tokens, False

def consume_token(ip, user_id=None):
    conn = get_db_connection()
    if user_id: conn.execute("UPDATE users SET tokens = tokens - 1 WHERE id=?", (user_id,))
    else: conn.execute("UPDATE guests SET tokens = tokens - 1 WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

def get_user_from_token(request):
    try:
        token = None
        if request.headers.get("Authorization"):
            token = request.headers.get("Authorization").split()[1]
        elif request.args.get("token"):
            token = request.args.get("token")
        
        if not token: return None
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
# ROUTES
# -------------------------
@app.route('/')
def index(): return send_file('index.html')

@app.route('/health')
def health_check(): return "OK", 200

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

# --- ADMIN ROUTES ---
@app.route("/api/admin/settings", methods=["GET", "POST"])
def manage_settings():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    conn = get_db_connection()
    if request.method == "POST":
        data = request.json
        if "maintenance" in data: conn.execute("REPLACE INTO settings (key, value) VALUES ('maintenance', ?)", (str(data['maintenance']).lower(),))
        if "announcement" in data: conn.execute("REPLACE INTO settings (key, value) VALUES ('announcement', ?)", (data['announcement'],))
        conn.commit()
        msg = "Settings updated"
    
    m = conn.execute("SELECT value FROM settings WHERE key='maintenance'").fetchone()
    a = conn.execute("SELECT value FROM settings WHERE key='announcement'").fetchone()
    conn.close()
    return jsonify({"maintenance": (m['value'] == 'true') if m else False, "announcement": a['value'] if a else "", "message": locals().get('msg', '')})

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
def add_credits():
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
def reset_pass():
    if not is_admin_request(request): return jsonify({"error": "Unauthorized"}), 403
    hashed = generate_password_hash(request.json.get("password"))
    conn = get_db_connection()
    conn.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, request.json.get("user_id")))
    conn.commit()
    conn.close()
    return jsonify({"message": "Reset"})

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
# DOWNLOADER LOGIC
# -------------------------
def get_video_formats(url):
    ydl_opts = { 
        "quiet": True, 
        "no_warnings": True, 
        "noplaylist": True, 
        "extract_flat": "in_playlist", 
        "http_headers": { "User-Agent": "Mozilla/5.0" }
    }
    if FFMPEG_PATH: ydl_opts["ffmpeg_location"] = FFMPEG_PATH
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            return { 
                "title": info.get("title", "Instagram Media"), 
                "thumbnail": info.get("thumbnail", ""), 
                "duration": info.get("duration_string", "00:00"), 
                "formats": [
                    {"id": "best", "type": "video", "quality": "HD (Best)", "ext": "mp4", "size": "Unknown"},
                    {"id": "audio", "type": "audio", "quality": "MP3 Audio", "ext": "mp3", "size": "Unknown"}
                ]
            }
    except Exception as e:
        print(f"Info Error: {e}")
        return None

def process_download(job_id, url, fmt_id):
    with download_semaphore:
        job_status[job_id]["status"] = "downloading"
        ydl_opts = {
            "outtmpl": os.path.join(DOWNLOAD_FOLDER, f"{job_id}_%(title)s.%(ext)s"),
            "quiet": True, 
            "format": "best"
        }
        if FFMPEG_PATH: 
            ydl_opts["ffmpeg_location"] = FFMPEG_PATH
        
        if "audio" in fmt_id: 
            ydl_opts["format"] = "bestaudio/best"
            ydl_opts["postprocessors"] = [{"key": "FFmpegExtractAudio","preferredcodec": "mp3"}]
            
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                ydl.extract_info(url, download=True)
                for f in os.listdir(DOWNLOAD_FOLDER):
                    if f.startswith(job_id):
                        job_status[job_id].update({"status": "completed", "file": os.path.join(DOWNLOAD_FOLDER, f), "filename": f})
                        return
                raise Exception("File missing")
        except Exception as e: 
            print(f"Download Error: {e}")
            job_status[job_id].update({"status": "error", "error": str(e)})

@app.route("/api/info", methods=["POST"])
def api_info(): 
    res = get_video_formats(request.json.get("url"))
    return jsonify(res) if res else (jsonify({"error": "Failed"}), 400)

@app.route("/api/download", methods=["POST"])
def api_download():
    ip = request.remote_addr
    if is_banned(ip): return jsonify({"error": "BANNED", "message": "Your IP is banned due to abuse."}), 403
    
    # Check Maintenance
    conn = get_db_connection()
    m = conn.execute("SELECT value FROM settings WHERE key='maintenance'").fetchone()
    conn.close()
    if m and m['value'] == 'true' and not is_admin_request(request):
        return jsonify({"error": "MAINTENANCE", "message": "Server is under maintenance. Try later."}), 503

    user_id = get_user_from_token(request)
    tokens_left, _ = check_tokens(ip, user_id)
    if tokens_left <= 0: return jsonify({"error": "LIMIT_REACHED", "message": "Limit reached."}), 403

    consume_token(ip, user_id)
    job_id = str(uuid.uuid4())
    job_status[job_id] = {"status": "queued", "percent": "0"}
    executor.submit(process_download, job_id, request.json.get("url"), request.json.get("format_id"))
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
                if os.path.exists(folder):
                    for f in os.listdir(folder):
                        f_path = os.path.join(folder, f)
                        if os.path.isfile(f_path) and now - os.path.getmtime(f_path) > 3600: os.remove(f_path)
            except: pass
        time.sleep(600)

threading.Thread(target=cleanup_files, daemon=True).start()

# For local development
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))