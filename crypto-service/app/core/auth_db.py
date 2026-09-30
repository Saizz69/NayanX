"""
User and Session Database Store for Forensic Attribution Enclave.
Uses the existing SQLite database (ledger.db) with Argon2 password hashing
and opaque 256-bit base64url session tokens.
"""

from __future__ import annotations
import sqlite3
import secrets
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from app import config

_auth_db_lock = threading.RLock()
_hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=1)


class AuthDatabase:
    """Thread-safe SQLite store for users, sessions, and security alerts."""

    def __init__(self, db_path: Optional[Path | str] = None):
        self.db_path = Path(db_path or config.LEDGER_DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self):
        with _auth_db_lock, self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('head', 'recipient')),
                    recipient_id TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    created_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    recipient_id TEXT,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_id TEXT NOT NULL,
                    recipient_name TEXT,
                    violation_type TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details TEXT,
                    dismissed INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_recipient_id ON users (recipient_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions (token);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_dismissed ON security_notifications (dismissed);")
            conn.commit()

        # Seed initial head admin account and sync existing sample recipients
        self._seed_default_accounts()

    def hash_password(self, password: str) -> str:
        return _hasher.hash(password)

    def verify_password(self, hash_str: str, password: str) -> bool:
        try:
            return _hasher.verify(hash_str, password)
        except (VerifyMismatchError, InvalidHashError):
            return False

    def _seed_default_accounts(self):
        """Seeds default Head account and ensures sample recipients have login credentials."""
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # 1. Seed Head account: username "head", password "123456"
        with _auth_db_lock, self._get_connection() as conn:
            head_row = conn.execute("SELECT id FROM users WHERE username = 'head'").fetchone()
            if not head_row:
                pw_hash = self.hash_password("123456")
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, recipient_id, failed_attempts, created_at) "
                    "VALUES (?, ?, 'head', NULL, 0, ?)",
                    ("head", pw_hash, now_iso),
                )
            
            # Also create "admin" alias for convenience if not exists
            admin_row = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
            if not admin_row:
                pw_hash = self.hash_password("123456")
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, recipient_id, failed_attempts, created_at) "
                    "VALUES (?, ?, 'head', NULL, 0, ?)",
                    ("admin", pw_hash, now_iso),
                )
            conn.commit()

    def create_recipient_user_if_missing(
        self, username: str, recipient_id: str, password: str = "123456"
    ) -> Optional[int]:
        now_iso = datetime.now(timezone.utc).isoformat()
        with _auth_db_lock, self._get_connection() as conn:
            existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                return existing["id"]
            pw_hash = self.hash_password(password)
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, recipient_id, failed_attempts, created_at) "
                "VALUES (?, ?, 'recipient', ?, 0, ?)",
                (username, pw_hash, recipient_id, now_iso),
            )
            conn.commit()
            return cur.lastrowid

    def create_user(
        self, username: str, password: str, role: str, recipient_id: Optional[str] = None
    ) -> int:
        if role not in ("head", "recipient"):
            raise ValueError("Role must be 'head' or 'recipient'")
        now_iso = datetime.now(timezone.utc).isoformat()
        pw_hash = self.hash_password(password)
        with _auth_db_lock, self._get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, role, recipient_id, failed_attempts, created_at) "
                "VALUES (?, ?, ?, ?, 0, ?)",
                (username, pw_hash, role, recipient_id, now_iso),
            )
            conn.commit()
            return cur.lastrowid

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with _auth_db_lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with _auth_db_lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None

    def record_login_failure(self, user_id: int) -> Dict[str, Any]:
        """Increments failed attempts; locks account for 15 min on 5th failure."""
        now = datetime.now(timezone.utc)
        with _auth_db_lock, self._get_connection() as conn:
            user = conn.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,)).fetchone()
            if not user:
                return {"locked": False, "attempts": 0}

            new_attempts = (user["failed_attempts"] or 0) + 1
            locked_until_iso = None
            is_locked = False

            if new_attempts >= 5:
                is_locked = True
                locked_until = now + timedelta(minutes=15)
                locked_until_iso = locked_until.isoformat()

            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_attempts, locked_until_iso, user_id),
            )
            conn.commit()
            return {
                "locked": is_locked,
                "attempts": new_attempts,
                "locked_until": locked_until_iso,
            }

    def reset_login_failures(self, user_id: int):
        with _auth_db_lock, self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,),
            )
            conn.commit()

    def create_session(self, user: Dict[str, Any], hours_valid: int = 24) -> str:
        """Generates a 256-bit opaque base64url session token and stores in DB."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=hours_valid)).isoformat()
        with _auth_db_lock, self._get_connection() as conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, username, role, recipient_id, expires_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    token,
                    user["id"],
                    user["username"],
                    user["role"],
                    user.get("recipient_id"),
                    expires_at,
                    now.isoformat(),
                ),
            )
            conn.commit()
        return token

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validates token against server-side session table and checks expiration."""
        if not token:
            return None
        now_iso = datetime.now(timezone.utc).isoformat()
        with _auth_db_lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
            if not row:
                return None
            sess = dict(row)
            if sess["expires_at"] < now_iso:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                return None
            return sess

    def delete_session(self, token: str) -> bool:
        with _auth_db_lock, self._get_connection() as conn:
            cur = conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return cur.rowcount > 0

    # --------------------------------------------------------------------------
    # Head Security Alerts / Screenshot Incident Notifications
    # --------------------------------------------------------------------------
    def add_security_notification(
        self,
        recipient_id: str,
        recipient_name: Optional[str],
        violation_type: str,
        reason: str,
        details: Optional[str] = None,
    ) -> int:
        now_iso = datetime.now(timezone.utc).isoformat()
        with _auth_db_lock, self._get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO security_notifications (recipient_id, recipient_name, violation_type, reason, details, dismissed, created_at) "
                "VALUES (?, ?, ?, ?, ?, 0, ?)",
                (recipient_id, recipient_name or recipient_id, violation_type, reason, details, now_iso),
            )
            conn.commit()
            return cur.lastrowid

    def get_security_notifications(self, unread_only: bool = True) -> List[Dict[str, Any]]:
        with _auth_db_lock, self._get_connection() as conn:
            if unread_only:
                rows = conn.execute(
                    "SELECT * FROM security_notifications WHERE dismissed = 0 ORDER BY id DESC"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM security_notifications ORDER BY id DESC LIMIT 100"
                ).fetchall()
            res = []
            for r in rows:
                d = dict(r)
                d["is_read"] = bool(d.get("dismissed", 0))
                d["timestamp"] = d.get("created_at")
                res.append(d)
            return res

    def dismiss_notification(self, notif_id: int) -> bool:
        with _auth_db_lock, self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE security_notifications SET dismissed = 1 WHERE id = ?",
                (notif_id,),
            )
            conn.commit()
            return cur.rowcount > 0


auth_db = AuthDatabase()
