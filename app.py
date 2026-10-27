"""Secure Private Data Vault - Flask application (application factory)."""
from __future__ import annotations

import hmac
import io
import os
import re
import secrets
import time
import uuid
from pathlib import Path

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

from database import db as dbm
from uploads import CATEGORIES, UploadError, validate_upload
from vault_crypto import ALGORITHMS, DecryptionError, Envelope, decrypt_bytes, encrypt_bytes

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD = 8
# What the user may pick in the form. "ALL" stores three independent copies.
REQUIRED_TRIO = ("AES-GCM", "DES-CBC", "RC4")
ALGORITHM_CHOICES = list(ALGORITHMS) + ["ALL"]
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env reader (avoids an extra dependency). Real env vars win."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def create_app(test_config: dict | None = None) -> Flask:
    load_dotenv()
    app = Flask(__name__)
    max_mb = int(os.environ.get("MAX_UPLOAD_MB", "100"))
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "instance/vault.db"),
        MAX_UPLOAD_BYTES=max_mb * 1024 * 1024,
        KDF_ITERATIONS=int(os.environ.get("KDF_ITERATIONS", "600000")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
        PERMANENT_SESSION_LIFETIME=1800,
        LOGIN_MAX_FAILURES=5, LOGIN_WINDOW_SECONDS=300,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY is not set. Copy .env.example to .env and set a long random value "
                           "(python -c \"import secrets;print(secrets.token_hex(32))\").")
    # Leave headroom for multipart overhead; the exact limit is re-checked after reading.
    app.config["MAX_CONTENT_LENGTH"] = app.config["MAX_UPLOAD_BYTES"] * 3 + 1024 * 1024
    dbm.init_db(app.config["DATABASE_PATH"])
    app.extensions["login_failures"] = {}

    # ------------------------------------------------------------ helpers ---
    def get_db():
        if "db" not in g:
            g.db = dbm.connect(app.config["DATABASE_PATH"])
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        conn = g.pop("db", None)
        if conn is not None:
            conn.close()

    def csrf_token() -> str:
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["CATEGORIES"] = CATEGORIES
    app.jinja_env.globals["ALGORITHM_CHOICES"] = ALGORITHM_CHOICES

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRFToken", "")
            expected = session.get("_csrf", "")
            if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
                abort(400, description="CSRF token missing or invalid.")

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src https://cdn.jsdelivr.net https://fonts.gstatic.com; script-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
        if "user_id" in session:
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def login_required(view):
        from functools import wraps

        @wraps(view)
        def wrapper(*a, **kw):
            if "user_id" not in session:
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapper

    def owned_file_or_404(file_id: int, columns: str = "*"):
        # Ownership is enforced IN the SQL: another user's id simply does not exist for you.
        row = get_db().execute(f"SELECT {columns} FROM encrypted_files WHERE id = ? AND user_id = ?",
                               (file_id, session["user_id"])).fetchone()
        if row is None:
            abort(404)
        return row

    # ------------------------------------------------------------- errors ---
    def error_page(code: int, msg: str):
        return render_template("error.html", code=code, message=msg), code

    @app.errorhandler(400)
    def e400(e):
        return error_page(400, getattr(e, "description", "Bad request."))

    @app.errorhandler(404)
    def e404(_e):
        return error_page(404, "Halaman atau berkas tidak ditemukan.")

    @app.errorhandler(RequestEntityTooLarge)
    def e413(_e):
        return error_page(413, "Ukuran unggahan melebihi batas yang diizinkan.")

    @app.errorhandler(500)
    def e500(_e):  # generic text only: no stack trace, no internals
        return error_page(500, "Terjadi kesalahan internal.")

    # ------------------------------------------------------------- routes ---
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if "user_id" in session else "login"))

    def too_many_failures(key) -> bool:
        now = time.time()
        fails = [t for t in app.extensions["login_failures"].get(key, [])
                 if now - t < app.config["LOGIN_WINDOW_SECONDS"]]
        app.extensions["login_failures"][key] = fails
        return len(fails) >= app.config["LOGIN_MAX_FAILURES"]

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            key = (username.lower(), request.remote_addr)
            if too_many_failures(key):
                flash("Terlalu banyak percobaan gagal. Coba lagi beberapa menit lagi.", "danger")
                return render_template("login.html"), 429
            user = get_db().execute("SELECT id, username, password_hash FROM users WHERE username = ?",
                                    (username,)).fetchone()
            # Always run one hash check so unknown users and wrong passwords take similar time.
            ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
            if user and ok:
                app.extensions["login_failures"].pop(key, None)
                session.clear()  # new session on login (anti session-fixation)
                session.permanent = True
                session["user_id"], session["username"] = user["id"], user["username"]
                flash("Login berhasil!", "success")
                return redirect(url_for("dashboard"))
            app.extensions["login_failures"].setdefault(key, []).append(time.time())
            flash("Username atau password salah!", "danger")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not USERNAME_RE.match(username):
                flash("Username harus 3-32 karakter: huruf, angka, titik, garis bawah, atau strip.", "danger")
            elif len(password) < MIN_PASSWORD or len(password) > 256:
                flash(f"Password minimal {MIN_PASSWORD} karakter.", "danger")
            else:
                try:
                    with get_db() as conn:
                        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                                     (username, generate_password_hash(password)))
                except Exception:  # UNIQUE violation (sqlite3.IntegrityError)
                    flash("Username sudah terdaftar!", "danger")
                else:
                    flash("Registrasi berhasil, silakan login.", "success")
                    return redirect(url_for("login"))
            return render_template("register.html"), 400
        return render_template("register.html")

    @app.route("/dashboard", methods=["GET", "POST"])
    @login_required
    def dashboard():
        if request.method == "POST":
            return handle_upload()
        rows = get_db().execute(
            "SELECT id, original_filename, category, mime_type, algorithm, plaintext_size, ciphertext_size, "
            "uploaded_at, group_id FROM encrypted_files WHERE user_id = ? ORDER BY id DESC",
            (session["user_id"],)).fetchall()
        return render_template("dashboard.html", files=rows)

    def handle_upload():
        f = request.files.get("file")
        category = request.form.get("file_type", "")
        algorithm = request.form.get("algorithm", "")
        password = request.form.get("password", "")
        if not f or not f.filename or not password:
            flash("Harap lengkapi file dan password enkripsi!", "danger")
            return redirect(url_for("dashboard"))
        if algorithm not in ALGORITHM_CHOICES:
            flash("Algoritma tidak valid.", "danger")
            return redirect(url_for("dashboard"))
        if len(password) < MIN_PASSWORD or len(password) > 256:
            flash(f"Password enkripsi minimal {MIN_PASSWORD} karakter.", "danger")
            return redirect(url_for("dashboard"))
        data = f.read(app.config["MAX_UPLOAD_BYTES"] + 1)
        try:
            safe_name, mime = validate_upload(f.filename, f.mimetype, data, category,
                                              app.config["MAX_UPLOAD_BYTES"])
        except UploadError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("dashboard"))
        algos = REQUIRED_TRIO if algorithm == "ALL" else (algorithm,)
        group = uuid.uuid4().hex if algorithm == "ALL" else None
        try:
            with get_db() as conn:  # all-or-nothing for the three "ALL" copies
                for algo in algos:
                    env = encrypt_bytes(data, password, algo, app.config["KDF_ITERATIONS"])
                    conn.execute(
                        "INSERT INTO encrypted_files (user_id, group_id, original_filename, category, mime_type, "
                        "algorithm, kdf_iterations, salt, iv, mac, plaintext_size, ciphertext_size, ciphertext) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (session["user_id"], group, safe_name, category, mime, algo, env.kdf_iterations,
                         env.salt, env.iv, env.mac, len(data), len(env.ciphertext), env.ciphertext))
        except Exception:
            app.logger.exception("encryption/storage failure")
            flash("Gagal mengenkripsi atau menyimpan berkas.", "danger")
            return redirect(url_for("dashboard"))
        flash(f"File berhasil diunggah dan dienkripsi dengan {', '.join(algos)}!", "success")
        return redirect(url_for("dashboard"))

    @app.route("/decrypt/<int:file_id>", methods=["POST"])
    @login_required
    def decrypt_file(file_id: int):
        row = owned_file_or_404(file_id)
        password = request.form.get("password", "")
        try:
            env = Envelope(row["algorithm"], row["kdf_iterations"], bytes(row["salt"]), bytes(row["iv"]),
                           bytes(row["ciphertext"]), bytes(row["mac"]))
            plaintext = decrypt_bytes(env, password)
            if len(plaintext) != row["plaintext_size"]:  # defence in depth against metadata tampering
                raise DecryptionError("size mismatch")
        except Exception:  # DecryptionError or anything unexpected: same generic answer
            flash("Password salah atau file terkorupsi!", "danger")
            return redirect(url_for("dashboard"))
        # Plaintext is streamed from memory; it is never written to disk.
        return send_file(io.BytesIO(plaintext), as_attachment=True, download_name=row["original_filename"],
                         mimetype=row["mime_type"])

    @app.route("/files/<int:file_id>/meta")
    @login_required
    def file_meta(file_id: int):
        row = owned_file_or_404(
            file_id, "id, original_filename, category, mime_type, algorithm, kdf, kdf_iterations, "
                     "plaintext_size, ciphertext_size, uploaded_at, group_id")
        return jsonify(dict(row))

    @app.route("/files/<int:file_id>/delete", methods=["POST"])
    @login_required
    def delete_file(file_id: int):
        owned_file_or_404(file_id, "id")
        with get_db() as conn:
            conn.execute("DELETE FROM encrypted_files WHERE id = ? AND user_id = ?", (file_id, session["user_id"]))
        flash("Berkas dihapus.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/category/<category_key>")
    @login_required
    def category_view(category_key):
        if category_key not in CATEGORIES:
            abort(404)
        rows = get_db().execute(
            "SELECT id, original_filename, category, mime_type, algorithm, plaintext_size, ciphertext_size, uploaded_at, group_id "
            "FROM encrypted_files WHERE user_id = ? AND category = ? ORDER BY id DESC",
            (session["user_id"], category_key),
        ).fetchall()
        return render_template(
            "category.html", files=rows, category_key=category_key,
            category_label=CATEGORIES[category_key]
        )

    return app


if __name__ == "__main__":
    # Debug mode is intentionally OFF. Use a real WSGI server (gunicorn/waitress) behind HTTPS in production.
    create_app().run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
