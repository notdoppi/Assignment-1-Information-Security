"""Integration tests for the Flask app using the Flask test client."""
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from app import create_app
from vault_crypto import ALGORITHMS

PW = "account-pass-1"
FPW = "file-pass-1234"

# Minimal valid magic headers + random body ("arbitrary binary contents")
HEADERS = {
    ".png": b"\x89PNG\r\n\x1a\n", ".jpg": b"\xff\xd8\xff\xe0", ".jpeg": b"\xff\xd8\xff\xe1",
    ".pdf": b"%PDF-1.7\n", ".doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".xls": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    ".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04", ".mp4": b"\x00\x00\x00\x18ftypmp42",
    ".mov": b"\x00\x00\x00\x14ftypqt  ", ".avi": b"RIFF\x00\x00\x00\x00AVI LIST",
    ".webm": b"\x1a\x45\xdf\xa3", ".mkv": b"\x1a\x45\xdf\xa3",
}
CATEGORY = {".png": "id_card", ".jpg": "id_card", ".jpeg": "id_card", ".mp4": "video", ".mov": "video",
            ".avi": "video", ".webm": "video", ".mkv": "video"}


def sample(ext, body_len=5000):
    return HEADERS[ext] + os.urandom(body_len)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "t.db")
        self.cfg = dict(SECRET_KEY="test-secret-key-not-real", DATABASE_PATH=self.db, KDF_ITERATIONS=1000,
                        SESSION_COOKIE_SECURE=False, TESTING=True, MAX_UPLOAD_BYTES=2 * 1024 * 1024)
        self.app = create_app(self.cfg)
        self.c = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers
    def token(self, client, path="/login"):
        html = client.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def register(self, client, user, pw=PW):
        return client.post("/register", data={"username": user, "password": pw, "csrf_token": self.token(client, "/register")})

    def login(self, client, user, pw=PW):
        return client.post("/login", data={"username": user, "password": pw, "csrf_token": self.token(client)})

    def signup_login(self, client, user):
        self.register(client, user); return self.login(client, user)

    def upload(self, client, name, data, category="document", algo="AES-GCM", pw=FPW, mime=None):
        return client.post("/dashboard", data={
            "csrf_token": self.token(client, "/dashboard"), "file_type": category, "algorithm": algo, "password": pw,
            "file": (io.BytesIO(data), name, mime or "application/octet-stream")}, content_type="multipart/form-data")

    def rows(self, sql="SELECT * FROM encrypted_files ORDER BY id", args=()):
        conn = sqlite3.connect(self.db); conn.row_factory = sqlite3.Row
        try: return conn.execute(sql, args).fetchall()
        finally: conn.close()

    def download(self, client, fid, pw=FPW):
        return client.post(f"/decrypt/{fid}", data={"password": pw, "csrf_token": self.token(client, "/dashboard")})

    def mutate_ciphertext(self, fid, fn):
        conn = sqlite3.connect(self.db)
        ct = conn.execute("SELECT ciphertext FROM encrypted_files WHERE id=?", (fid,)).fetchone()[0]
        conn.execute("UPDATE encrypted_files SET ciphertext=? WHERE id=?", (sqlite3.Binary(fn(bytes(ct))), fid))
        conn.commit(); conn.close()

    def alter(self, sql, args=()):
        conn = sqlite3.connect(self.db); conn.execute(sql, args); conn.commit(); conn.close()


class Auth(Base):
    def test_register_and_login(self):
        r = self.register(self.c, "alice"); self.assertEqual(r.status_code, 302)
        r = self.login(self.c, "alice"); self.assertEqual(r.status_code, 302)
        self.assertEqual(self.c.get("/dashboard").status_code, 200)

    def test_password_is_hashed(self):
        self.register(self.c, "alice")
        h = self.rows("SELECT password_hash FROM users")[0][0]
        self.assertNotIn(PW, h); self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))

    def test_invalid_logins(self):
        self.register(self.c, "alice")
        self.assertEqual(self.login(self.c, "alice", "wrong-password").status_code, 401)
        self.assertEqual(self.login(self.c, "nobody", PW).status_code, 401)
        self.assertEqual(self.c.get("/dashboard").status_code, 302)  # still anonymous

    def test_duplicate_weak_and_bad_usernames(self):
        self.register(self.c, "alice")
        self.assertEqual(self.register(self.c, "ALICE").status_code, 400)   # case-insensitive unique
        self.assertEqual(self.register(self.c, "bob", "short").status_code, 400)
        self.assertEqual(self.register(self.c, "b o b!").status_code, 400)
        self.assertEqual(self.register(self.c, "../x").status_code, 400)

    def test_login_throttling(self):
        self.register(self.c, "alice")
        for _ in range(5): self.login(self.c, "alice", "bad-password")
        self.assertEqual(self.login(self.c, "alice", PW).status_code, 429)

    def test_logout_clears_session(self):
        self.signup_login(self.c, "alice")
        self.c.post("/logout", data={"csrf_token": self.token(self.c, "/dashboard")})
        self.assertEqual(self.c.get("/dashboard").status_code, 302)

    def test_anonymous_endpoints_redirect(self):
        for path in ("/dashboard", "/files/1/meta"):
            self.assertEqual(self.c.get(path).status_code, 302)
        self.assertEqual(self.c.get("/decrypt/1").status_code, 405)


class Security(Base):
    def test_csrf_required(self):
        self.assertEqual(self.c.post("/register", data={"username": "eve", "password": PW}).status_code, 400)
        self.signup_login(self.c, "alice")
        self.assertEqual(self.c.post("/logout").status_code, 400)
        self.assertEqual(self.c.post("/decrypt/1", data={"password": FPW}).status_code, 400)
        self.assertEqual(self.c.post("/files/1/delete").status_code, 400)
        self.assertEqual(self.c.post("/dashboard", data={"csrf_token": "forged"}).status_code, 400)

    def test_secret_key_required_and_debug_off(self):
        old = os.environ.pop("SECRET_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                create_app({"SECRET_KEY": None, "DATABASE_PATH": self.db})
        finally:
            if old: os.environ["SECRET_KEY"] = old
        self.assertFalse(self.app.debug)

    def test_cookie_flags_and_headers(self):
        r = self.c.get("/login")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])
        self.assertTrue(self.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(self.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        secure = create_app({**self.cfg, "SESSION_COOKIE_SECURE": True})
        self.assertTrue(secure.config["SESSION_COOKIE_SECURE"])

    def _cfg_without_cookie_setting(self):
        return {k: v for k, v in self.cfg.items() if k != "SESSION_COOKIE_SECURE"}

    def test_default_secure_cookie_when_env_unset(self):
        # Isolated from the developer's real environment AND local .env file:
        # load_dotenv is stubbed (create_app would otherwise re-read .env and
        # re-set the variable) and os.environ is restored afterwards.
        with mock.patch.dict(os.environ), mock.patch("app.load_dotenv"):
            os.environ.pop("SESSION_COOKIE_SECURE", None)
            self.assertNotIn("SESSION_COOKIE_SECURE", os.environ)
            self.assertTrue(create_app(self._cfg_without_cookie_setting()).config["SESSION_COOKIE_SECURE"])

    def test_env_can_disable_secure_cookie_for_local_http(self):
        with mock.patch.dict(os.environ, {"SESSION_COOKIE_SECURE": "0"}), mock.patch("app.load_dotenv"):
            self.assertFalse(create_app(self._cfg_without_cookie_setting()).config["SESSION_COOKIE_SECURE"])
        with mock.patch.dict(os.environ, {"SESSION_COOKIE_SECURE": "1"}), mock.patch("app.load_dotenv"):
            self.assertTrue(create_app(self._cfg_without_cookie_setting()).config["SESSION_COOKIE_SECURE"])


class UploadDownload(Base):
    def setUp(self):
        super().setUp(); self.signup_login(self.c, "alice")

    def test_each_algorithm_roundtrip_byte_for_byte(self):
        for algo in ALGORITHMS:
            with self.subTest(algo=algo):
                data = sample(".pdf", 20000)
                self.upload(self.c, f"{algo}.pdf", data, "document", algo)
                row = self.rows("SELECT * FROM encrypted_files WHERE algorithm=? ORDER BY id DESC", (algo,))[0]
                r = self.download(self.c, row["id"])
                self.assertEqual(r.status_code, 200); self.assertEqual(r.data, data)
                self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_all_three_required_algorithms_option(self):
        data = sample(".png", 3000)
        self.upload(self.c, "ktp.png", data, "id_card", "ALL")
        rows = self.rows()
        self.assertEqual({r["algorithm"] for r in rows}, {"AES-GCM", "DES-CBC", "RC4"})
        self.assertEqual(len({r["group_id"] for r in rows}), 1)
        for r in rows:
            self.assertEqual(self.download(self.c, r["id"]).data, data)

    def test_all_file_types_and_categories(self):
        for ext in HEADERS:
            with self.subTest(ext=ext):
                data = sample(ext, 4321)
                cat = CATEGORY.get(ext, "document")
                self.upload(self.c, f"file{ext}", data, cat, "AES-GCM")
                row = self.rows("SELECT * FROM encrypted_files ORDER BY id DESC")[0]
                self.assertEqual(row["category"], cat)
                self.assertEqual(self.download(self.c, row["id"]).data, data)

    def test_large_video_like_upload(self):
        data = sample(".mp4", 1_500_000)
        self.upload(self.c, "clip.mp4", data, "video", "AES-GCM")
        self.assertEqual(self.download(self.c, self.rows()[0]["id"]).data, data)

    def test_stored_blob_is_ciphertext_and_metadata_complete(self):
        marker = b"TOP-SECRET-MARKER-" * 20
        data = HEADERS[".pdf"] + marker
        self.upload(self.c, "s.pdf", data, "document", "AES-GCM")
        row = self.rows()[0]
        self.assertNotIn(b"TOP-SECRET-MARKER", bytes(row["ciphertext"]))
        self.assertEqual((row["user_id"], row["original_filename"], row["mime_type"], row["algorithm"],
                          row["plaintext_size"]), (1, "s.pdf", "application/pdf", "AES-GCM", len(data)))
        self.assertEqual(len(row["salt"]), 16); self.assertEqual(len(row["iv"]), 12)
        self.assertEqual(len(row["mac"]), 0); self.assertEqual(row["ciphertext_size"], len(row["ciphertext"]))
        self.assertTrue(row["uploaded_at"])
        for root, _d, files in os.walk(os.getcwd()):  # plaintext never written to disk
            for f in files:
                if f == "s.pdf": self.fail("plaintext file written to disk")

    def test_wrong_password_returns_no_file(self):
        data = sample(".pdf"); self.upload(self.c, "a.pdf", data)
        r = self.download(self.c, 1, "not-the-password")
        self.assertEqual(r.status_code, 302)
        self.assertNotIn(b"%PDF", r.data)
        self.assertIn("Password salah", self.c.get("/dashboard").get_data(as_text=True))

    def test_empty_file_rejected(self):
        self.upload(self.c, "empty.pdf", b"")
        self.assertEqual(self.rows(), [])

    def test_unsupported_and_mismatched_types(self):
        self.upload(self.c, "evil.exe", b"MZ" + os.urandom(100))
        self.upload(self.c, "evil.php", b"<?php ?>", "document")
        self.upload(self.c, "fake.pdf", b"not really a pdf", "document")       # bad magic
        self.upload(self.c, "movie.mp4", sample(".mp4"), "document")          # wrong category
        self.upload(self.c, "doc.pdf", sample(".pdf"), "document", mime="image/png")  # lying MIME
        self.upload(self.c, "x.pdf", sample(".pdf"), "nonexistent-category")
        self.upload(self.c, "x.pdf", sample(".pdf"), "document", algo="AES-ECB")
        self.upload(self.c, "x.pdf", sample(".pdf"), "document", pw="short")
        self.assertEqual(self.rows(), [])

    def test_oversized_upload(self):
        big = HEADERS[".mp4"] + os.urandom(2 * 1024 * 1024 + 10)
        r = self.upload(self.c, "big.mp4", big, "video")
        self.assertIn(r.status_code, (302, 413))
        self.assertEqual(self.rows(), [])
        huge = HEADERS[".mp4"] + os.urandom(8 * 1024 * 1024)  # beyond MAX_CONTENT_LENGTH
        r = self.c.post("/dashboard", data={"csrf_token": self.token(self.c, "/dashboard"), "file_type": "video",
                        "algorithm": "AES-GCM", "password": FPW, "file": (io.BytesIO(huge), "h.mp4")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413); self.assertEqual(self.rows(), [])

    def test_delete_own_file(self):
        self.upload(self.c, "a.pdf", sample(".pdf"))
        r = self.c.post("/files/1/delete", data={"csrf_token": self.token(self.c, "/dashboard")})
        self.assertEqual(r.status_code, 302); self.assertEqual(self.rows(), [])


class Tampering(Base):
    def setUp(self):
        super().setUp(); self.signup_login(self.c, "alice")
        self.data = sample(".pdf", 4000)

    def _fresh(self, algo):
        self.alter("DELETE FROM encrypted_files")
        self.upload(self.c, "a.pdf", self.data, "document", algo)
        return self.rows()[0]["id"]

    def _assert_rejected(self, fid, why):
        r = self.download(self.c, fid)
        self.assertEqual(r.status_code, 302, why)
        self.assertNotEqual(r.data, self.data, why)
        page = self.c.get("/dashboard").get_data(as_text=True)
        self.assertIn("terkorupsi", page); self.assertNotIn("Traceback", page)

    def test_corrupted_ciphertext_all_algorithms(self):
        for algo in ALGORITHMS:
            fid = self._fresh(algo)
            self.mutate_ciphertext(fid, lambda c: c[:10] + bytes([c[10] ^ 0xFF]) + c[11:])
            self._assert_rejected(fid, algo)

    def test_truncated_ciphertext(self):
        for algo in ALGORITHMS:
            fid = self._fresh(algo)
            self.mutate_ciphertext(fid, lambda c: c[:-5])
            self._assert_rejected(fid, algo)

    def test_invalid_or_missing_metadata(self):
        cases = ["algorithm='BOGUS'", "kdf_iterations=0", "kdf_iterations=999999999999", "iv=x''", "salt=x''",
                 "plaintext_size=1", "algorithm='AES-OFB'"]
        for c in cases:
            fid = self._fresh("AES-GCM")
            self.alter(f"UPDATE encrypted_files SET {c} WHERE id=?", (fid,))
            self._assert_rejected(fid, c)

    def test_null_metadata_blocked_by_schema(self):
        fid = self._fresh("AES-GCM")
        with self.assertRaises(sqlite3.IntegrityError):
            self.alter("UPDATE encrypted_files SET salt=NULL WHERE id=?", (fid,))


class Authorization(Base):
    def setUp(self):
        super().setUp()
        self.signup_login(self.c, "alice")
        self.data = sample(".pdf", 1000)
        self.upload(self.c, "alice-secret.pdf", self.data, "document", "AES-GCM")
        self.b = self.app.test_client(); self.signup_login(self.b, "bob")

    def test_other_user_cannot_download_even_with_right_password(self):
        r = self.download(self.b, 1, FPW)
        self.assertEqual(r.status_code, 404); self.assertNotIn(b"%PDF", r.data)

    def test_other_user_cannot_read_meta_or_delete(self):
        self.assertEqual(self.b.get("/files/1/meta").status_code, 404)
        r = self.b.post("/files/1/delete", data={"csrf_token": self.token(self.b, "/dashboard")})
        self.assertEqual(r.status_code, 404); self.assertEqual(len(self.rows()), 1)

    def test_listing_is_scoped(self):
        self.assertNotIn("alice-secret.pdf", self.b.get("/dashboard").get_data(as_text=True))
        self.assertIn("alice-secret.pdf", self.c.get("/dashboard").get_data(as_text=True))

    def test_owner_meta_excludes_secrets(self):
        meta = json.loads(self.c.get("/files/1/meta").data)
        self.assertEqual(meta["algorithm"], "AES-GCM")
        for k in ("ciphertext", "salt", "iv", "mac", "password_hash"):
            self.assertNotIn(k, meta)

    def test_nonexistent_file_404(self):
        self.assertEqual(self.c.get("/files/999/meta").status_code, 404)


class PathTraversal(Base):
    def setUp(self):
        super().setUp(); self.signup_login(self.c, "alice")

    def test_traversal_in_uploaded_filename_is_neutralised(self):
        for evil in ("../../../etc/passwd.pdf", "..\\..\\windows\\win.pdf", "/abs/path/x.pdf",
                     "a/../../b.pdf", "x\x00.pdf", "..%2f..%2fx.pdf"):
            self.alter("DELETE FROM encrypted_files")
            self.upload(self.c, evil, sample(".pdf"))
            rows = self.rows()
            self.assertEqual(len(rows), 1, evil)
            name = rows[0]["original_filename"]
            self.assertNotIn("/", name); self.assertNotIn("\\", name); self.assertNotIn("..", name.replace(".pdf", ""))
            r = self.download(self.c, rows[0]["id"])
            self.assertNotIn("/", r.headers["Content-Disposition"].split("filename=")[-1])

    def test_traversal_in_urls(self):
        for p in ("/files/../app.py/meta", "/decrypt/../../etc/passwd", "/static/../app.py", "/files/..%2fapp.py/meta"):
            self.assertIn(self.c.get(p).status_code, (301, 302, 308, 404, 405), p)

    def test_nothing_written_outside_database(self):
        before = set(os.listdir("."))
        self.upload(self.c, "../../evil.pdf", sample(".pdf"))
        self.assertEqual(set(os.listdir(".")) - before - {"__pycache__"}, set())


class Persistence(Base):
    def test_survives_application_restart(self):
        self.signup_login(self.c, "alice")
        data = sample(".xlsx", 9000)
        self.upload(self.c, "sheet.xlsx", data, "document", "RC4")
        app2 = create_app(self.cfg)  # brand-new app object, same database file = restart
        c2 = app2.test_client()
        self.login(c2, "alice")
        self.assertIn("sheet.xlsx", c2.get("/dashboard").get_data(as_text=True))
        r = c2.post("/decrypt/1", data={"password": FPW, "csrf_token": self.token(c2, "/dashboard")})
        self.assertEqual(r.data, data)


class ErrorPages(Base):
    def test_404_is_generic(self):
        r = self.c.get("/does-not-exist")
        self.assertEqual(r.status_code, 404); self.assertNotIn(b"Traceback", r.data)

    def test_500_does_not_leak(self):
        app = create_app({**self.cfg, "TESTING": False, "PROPAGATE_EXCEPTIONS": False})
        @app.route("/boom")
        def boom(): raise RuntimeError("secret-internal-detail")
        r = app.test_client().get("/boom")
        self.assertEqual(r.status_code, 500); self.assertNotIn(b"secret-internal-detail", r.data)


if __name__ == "__main__":
    unittest.main()
