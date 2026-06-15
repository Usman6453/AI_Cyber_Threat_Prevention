from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from database.db import DatabaseManager
from utils.system_info import get_system_snapshot


@dataclass
class AuthResult:
    success: bool
    message: str
    username: str | None = None
    attempts: int = 0


class AuthService:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    @staticmethod
    def _hash_password(password: str, salt: bytes | None = None) -> str:
        salt = salt or os.urandom(16)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
        return f"{salt.hex()}:{derived.hex()}"

    @staticmethod
    def _verify_password(password: str, stored_hash: str) -> bool:
        salt_hex, hash_hex = stored_hash.split(":", 1)
        recalculated = AuthService._hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(recalculated, hash_hex)

    def ensure_admin(self) -> None:
        if self.database.fetch_one("SELECT id FROM users WHERE username = ?", ("admin",)) is None:
            self.register_user("admin", "Admin@12345", role="admin")

    def register_user(self, username: str, password: str, role: str = "user") -> AuthResult:
        existing = self.database.fetch_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            return AuthResult(False, "Username already exists")
        self.database.execute(
            "INSERT INTO users (username, password_hash, role, remember_me, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, self._hash_password(password), role, 0, __import__("datetime").datetime.utcnow().isoformat()),
        )
        return AuthResult(True, "Registration successful", username=username)

    def authenticate(self, username: str, password: str) -> AuthResult:
        snapshot = get_system_snapshot()
        user = self.database.fetch_one("SELECT * FROM users WHERE username = ?", (username,))
        attempts = 0
        if user is None:
            self.database.log_login(username, False, snapshot.hostname, snapshot.ip_address, attempts)
            return AuthResult(False, "Unknown account", attempts=1)
        attempts = len(self.database.fetch_all("SELECT id FROM login_logs WHERE username = ? AND success = 0", (username,))) + 1
        success = self._verify_password(password, user["password_hash"])
        self.database.log_login(username, success, snapshot.hostname, snapshot.ip_address, attempts)
        if success:
            return AuthResult(True, "Login successful", username=username, attempts=attempts)
        return AuthResult(False, "Invalid password", username=username, attempts=attempts)
