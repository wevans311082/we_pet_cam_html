import os
import sqlite3
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["DB_PATH"] = os.environ.get("DB_PATH", "/data/feeds.db")
app.config["ADMIN_USERNAME"] = os.environ.get("ADMIN_USERNAME", "admin")
app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "change-this-password")


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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return fn(*args, **kwargs)

    return wrapper


def to_hls_proxy_url(rtsp_url: str) -> str:
    # Stream converter endpoint provided by mediamtx.
    return f"/hls_proxy?src={rtsp_url}"


@app.route("/")
def index():
    db = get_db()
    feeds = db.execute("SELECT id, name, rtsp_url FROM feeds ORDER BY id DESC").fetchall()
    return render_template("index.html", feeds=feeds, to_hls_proxy_url=to_hls_proxy_url)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if (
            username == app.config["ADMIN_USERNAME"]
            and password == app.config["ADMIN_PASSWORD"]
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials", "error")
    return render_template("login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
def admin_dashboard():
    db = get_db()
    feeds = db.execute("SELECT id, name, rtsp_url FROM feeds ORDER BY id DESC").fetchall()
    return render_template("admin.html", feeds=feeds)


def is_likely_rtsp(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme.lower() == "rtsp" and bool(parsed.netloc)


@app.route("/admin/feeds", methods=["POST"])
@login_required
def add_feed():
    name = request.form.get("name", "").strip()
    rtsp_url = request.form.get("rtsp_url", "").strip()

    if not name or not rtsp_url:
        flash("Name and RTSP URL are required.", "error")
        return redirect(url_for("admin_dashboard"))

    if not is_likely_rtsp(rtsp_url):
        flash("RTSP URL must look like rtsp://...", "error")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    db.execute("INSERT INTO feeds (name, rtsp_url) VALUES (?, ?)", (name, rtsp_url))
    db.commit()
    flash("Feed added.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/feeds/<int:feed_id>/delete", methods=["POST"])
@login_required
def delete_feed(feed_id: int):
    db = get_db()
    db.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
    db.commit()
    flash("Feed deleted.", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=8000, debug=False)
