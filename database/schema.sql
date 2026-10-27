-- Encrypted bytes live INSIDE the database (BLOB). Only ciphertext is stored.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,          -- Werkzeug salted hash, never the password
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE TABLE IF NOT EXISTS encrypted_files (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id          TEXT,                  -- shared by the 3 copies of an "ALL" upload
    original_filename TEXT    NOT NULL,
    category          TEXT    NOT NULL CHECK (category IN ('id_card','document','video')),
    mime_type         TEXT    NOT NULL,
    algorithm         TEXT    NOT NULL,      -- e.g. AES-CBC, DES-CBC, RC4
    kdf               TEXT    NOT NULL DEFAULT 'PBKDF2-HMAC-SHA256',
    kdf_iterations    INTEGER NOT NULL,
    salt              BLOB    NOT NULL,
    iv                BLOB    NOT NULL,      -- empty for RC4
    mac               BLOB    NOT NULL,      -- HMAC-SHA256 tag (empty for AES-GCM)
    plaintext_size    INTEGER NOT NULL,
    ciphertext_size   INTEGER NOT NULL,
    ciphertext        BLOB    NOT NULL,
    uploaded_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_files_user ON encrypted_files(user_id);
