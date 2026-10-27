"""Tiny sqlite3 layer (stdlib). Every query on files is scoped by user_id."""
from __future__ import annotations
import sqlite3
from pathlib import Path

SCHEMA = Path(__file__).with_name("schema.sql")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    with conn:
        conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    conn.close()


if __name__ == "__main__":  # python -m database.db [path]
    import os, sys
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DATABASE_PATH", "instance/vault.db")
    init_db(target)
    print(f"Database initialised at {target}")
