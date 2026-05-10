import os
import sqlite3
import hmac
import secrets
import time
import shutil
import subprocess
from datetime import timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["DB_PATH"] = os.environ.get("DB_PATH", "/data/feeds.db")
app.config["ADMIN_USERNAME"] = os.environ.get("ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "change-this-password")
app.config["HLS_ROOT"] = os.environ.get("HLS_ROOT", "/data/hls")
app.config["FFMPEG_BIN"] = os.environ.get("FFMPEG_BIN", "ffmpeg")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("SESSION_COOKIE_SECURE", "false").strip().lower()
    in ("1", "true", "yes", "on")
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "8"))
)
app.config["MAX_LOGIN_ATTEMPTS"] = int(os.environ.get("MAX_LOGIN_ATTEMPTS", "10"))
app.config["LOGIN_WINDOW_SECONDS"] = int(os.environ.get("LOGIN_WINDOW_SECONDS", "300"))

FAILED_LOGINS = {}
STREAM_PROCESSES = {}


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DB_PATH"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            rtsp_url TEXT NOT NULL,
            remove_blue INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(feeds)").fetchall()
    }
    if "remove_blue" not in columns:
        db.execute("ALTER TABLE feeds ADD COLUMN remove_blue INTEGER NOT NULL DEFAULT 0")

    db.commit()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


def verify_admin_password(password: str) -> bool:
    return hmac.compare_digest(password, app.config["ADMIN_PASSWORD"])


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def is_login_limited(ip: str) -> bool:
    now = time.time()
    window = app.config["LOGIN_WINDOW_SECONDS"]
    attempts = [t for t in FAILED_LOGINS.get(ip, []) if now - t < window]
    FAILED_LOGINS[ip] = attempts
    return len(attempts) >= app.config["MAX_LOGIN_ATTEMPTS"]


def record_login_failure(ip: str) -> None:
    now = time.time()
    attempts = [t for t in FAILED_LOGINS.get(ip, []) if now - t < app.config["LOGIN_WINDOW_SECONDS"]]
    attempts.append(now)
    FAILED_LOGINS[ip] = attempts


def clear_login_failures(ip: str) -> None:
    FAILED_LOGINS.pop(ip, None)


def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_or_abort() -> None:
    form_token = request.form.get("_csrf_token", "")
    session_token = session.get("_csrf_token", "")
    if not form_token or not session_token or not hmac.compare_digest(form_token, session_token):
        abort(400, description="Invalid CSRF token")


def mask_rtsp_url(rtsp_url: str) -> str:
    parsed = urlparse(rtsp_url)
    if not parsed.username and not parsed.password:
        return rtsp_url

    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"

    if parsed.username and parsed.password:
        auth = f"{parsed.username}:***"
    elif parsed.username:
        auth = parsed.username
    else:
        auth = "***"

    masked_netloc = f"{auth}@{host}" if host else auth
    return parsed._replace(netloc=masked_netloc).geturl()


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": get_csrf_token, "mask_rtsp_url": mask_rtsp_url}


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Range"
    response.headers["Access-Control-Expose-Headers"] = "Content-Length, Content-Range, Accept-Ranges"
    response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    return response


def to_hls_proxy_url(feed: sqlite3.Row) -> str:
    return f"/hls/feed-{feed['id']}/index.m3u8"


def stream_key(feed_id: int) -> str:
    return f"feed-{feed_id}"


def stream_dir(feed_id: int) -> str:
    return os.path.join(app.config["HLS_ROOT"], stream_key(feed_id))


def get_feed_rtsp_url(feed_id: int) -> str | None:
    db = get_db()
    row = db.execute("SELECT rtsp_url FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    return row["rtsp_url"] if row else None


def ensure_stream_running(feed_id: int, rtsp_url: str) -> bool:
    proc = STREAM_PROCESSES.get(feed_id)
    if proc is not None and proc.poll() is None:
        return True
    return start_stream(feed_id, rtsp_url)


def stop_stream(feed_id: int) -> None:
    proc = STREAM_PROCESSES.pop(feed_id, None)
    if not proc:
        return

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        proc.kill()


def start_stream(feed_id: int, rtsp_url: str) -> bool:
    stop_stream(feed_id)

    output_dir = stream_dir(feed_id)
    os.makedirs(output_dir, exist_ok=True)
    for filename in os.listdir(output_dir):
        path = os.path.join(output_dir, filename)
        if os.path.isfile(path):
            os.remove(path)

    ffmpeg_cmd = [
        app.config["FFMPEG_BIN"],
        "-hide_banner",
        "-loglevel",
        "warning",
        "-rtsp_transport",
        "tcp",
        "-i",
        rtsp_url,
    ]

    db = get_db()
    feed = db.execute("SELECT remove_blue FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    remove_blue = bool(feed and feed["remove_blue"])

    if remove_blue:
        # Zero out the blue output channel.
        ffmpeg_cmd.extend(["-vf", "colorchannelmixer=bb=0"])

    ffmpeg_cmd.extend([
        "-an",
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-tune",
        "zerolatency",
        "-f",
        "hls",
        "-hls_time",
        "2",
        "-hls_list_size",
        "6",
        "-hls_flags",
        "delete_segments+append_list+omit_endlist+independent_segments",
        "-hls_segment_filename",
        os.path.join(output_dir, "seg_%05d.ts"),
        os.path.join(output_dir, "index.m3u8"),
    ])

    try:
        proc = subprocess.Popen(ffmpeg_cmd)
        STREAM_PROCESSES[feed_id] = proc
        app.logger.info("Started ffmpeg worker for %s", stream_key(feed_id))
        return True
    except OSError:
        app.logger.exception("Failed to start ffmpeg worker for %s", stream_key(feed_id))
        return False


def start_all_streams() -> None:
    db = get_db()
    feeds = db.execute("SELECT id, rtsp_url FROM feeds").fetchall()
    os.makedirs(app.config["HLS_ROOT"], exist_ok=True)
    for feed in feeds:
        start_stream(feed["id"], feed["rtsp_url"])


@app.route("/")
def index():
    db = get_db()
    feeds = db.execute("SELECT id, name, rtsp_url, remove_blue FROM feeds ORDER BY id DESC").fetchall()
    return render_template("index.html", feeds=feeds, to_hls_proxy_url=to_hls_proxy_url)


@app.route("/hls/<stream_name>/<path:filename>")
def serve_hls(stream_name: str, filename: str):
    if not stream_name.startswith("feed-"):
        abort(404)
    if not (filename.endswith(".m3u8") or filename.endswith(".ts")):
        abort(404)

    try:
        feed_id = int(stream_name.split("-", 1)[1])
    except (IndexError, ValueError):
        abort(404)

    directory = os.path.join(app.config["HLS_ROOT"], stream_name)
    file_path = os.path.join(directory, filename)

    if filename.endswith(".m3u8") and not os.path.exists(file_path):
        rtsp_url = get_feed_rtsp_url(feed_id)
        if not rtsp_url:
            abort(404)

        if not ensure_stream_running(feed_id, rtsp_url):
            return "Stream worker failed to start.", 503

        deadline = time.time() + 8
        while time.time() < deadline:
            if os.path.exists(file_path):
                break
            time.sleep(0.25)

        if not os.path.exists(file_path):
            return "Stream is starting. Retry in a few seconds.", 503

    return send_from_directory(directory, filename)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        validate_csrf_or_abort()
        ip = client_ip()
        if is_login_limited(ip):
            flash("Too many failed attempts. Try again later.", "error")
            return render_template("login.html"), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == app.config["ADMIN_USERNAME"] and verify_admin_password(password):
            clear_login_failures(ip)
            session.clear()
            session["admin_logged_in"] = True
            session["_csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            return redirect(url_for("admin_dashboard"))

        record_login_failure(ip)
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    validate_csrf_or_abort()
    session.clear()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
def admin_dashboard():
    db = get_db()
    feeds = db.execute("SELECT id, name, rtsp_url, remove_blue FROM feeds ORDER BY id DESC").fetchall()
    return render_template("admin.html", feeds=feeds)


def is_likely_rtsp(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme.lower() == "rtsp" and bool(parsed.netloc)


@app.route("/admin/feeds", methods=["POST"])
@login_required
def add_feed():
    validate_csrf_or_abort()
    name = request.form.get("name", "").strip()
    rtsp_url = request.form.get("rtsp_url", "").strip()

    if not name or not rtsp_url:
        flash("Name and RTSP URL are required.", "error")
        return redirect(url_for("admin_dashboard"))

    if not is_likely_rtsp(rtsp_url):
        flash("RTSP URL must look like rtsp://...", "error")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    cursor = db.execute("INSERT INTO feeds (name, rtsp_url) VALUES (?, ?)", (name, rtsp_url))
    db.commit()
    feed_id = cursor.lastrowid

    if not start_stream(feed_id, rtsp_url):
        flash("Feed saved, but stream worker failed to start. Check ffmpeg is installed.", "error")
        return redirect(url_for("admin_dashboard"))

    flash("Feed added.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/feeds/<int:feed_id>/delete", methods=["POST"])
@login_required
def delete_feed(feed_id: int):
    validate_csrf_or_abort()
    db = get_db()
    db.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
    db.commit()
    stop_stream(feed_id)
    shutil.rmtree(stream_dir(feed_id), ignore_errors=True)
    flash("Feed deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/feeds/<int:feed_id>/blue-filter", methods=["POST"])
def toggle_blue_filter(feed_id: int):
    validate_csrf_or_abort()
    wants_json = "application/json" in request.headers.get("Accept", "")
    enabled = request.form.get("enabled", "").strip().lower() in ("1", "true", "on", "yes")

    db = get_db()
    feed = db.execute("SELECT id, rtsp_url FROM feeds WHERE id = ?", (feed_id,)).fetchone()
    if not feed:
        abort(404)

    db.execute("UPDATE feeds SET remove_blue = ? WHERE id = ?", (1 if enabled else 0, feed_id))
    db.commit()

    if not start_stream(feed_id, feed["rtsp_url"]):
        if wants_json:
            return jsonify({"ok": False, "error": "Failed to restart stream worker."}), 503
        flash("Could not restart stream worker.", "error")
        return redirect(url_for("admin_dashboard"))

    if wants_json:
        return jsonify({"ok": True, "remove_blue": enabled})

    flash("Blue filter enabled." if enabled else "Blue filter disabled.", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    with app.app_context():
        init_db()
        start_all_streams()
    app.run(host="0.0.0.0", port=8000, debug=False)
