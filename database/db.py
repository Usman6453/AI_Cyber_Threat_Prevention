from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Iterable

from config.settings import DB_PATH, ensure_directories


class DatabaseManager:
    def __init__(self, db_path: str | None = None) -> None:
        ensure_directories()
        self.db_path = db_path or str(DB_PATH)
        self.initialize()

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def initialize(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                remember_me INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                success INTEGER NOT NULL,
                device_name TEXT,
                ip_address TEXT,
                attempts INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS phishing_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_text TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS monitoring_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpu REAL NOT NULL,
                memory REAL NOT NULL,
                processes INTEGER NOT NULL,
                network_sent REAL NOT NULL,
                network_recv REAL NOT NULL,
                threat_score REAL NOT NULL,
                severity TEXT NOT NULL,
                anomaly_score REAL NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS device_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_name TEXT,
                ip_address TEXT,
                status TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS protection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                target TEXT,
                result TEXT,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                key_path TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        ]
        with self.connection() as conn:
            for statement in statements:
                conn.execute(statement)

    def execute(self, query: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self.connection() as conn:
            return conn.execute(query, tuple(params))

    def fetch_all(self, query: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self.connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return cursor.fetchall()

    def fetch_one(self, query: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        with self.connection() as conn:
            cursor = conn.execute(query, tuple(params))
            return cursor.fetchone()

    def log_login(self, username: str, success: bool, device_name: str, ip_address: str, attempts: int = 0) -> None:
        self.execute(
            "INSERT INTO login_logs (username, success, device_name, ip_address, attempts, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (username, int(success), device_name, ip_address, attempts, datetime.utcnow().isoformat()),
        )

    def log_phishing(self, input_text: str, prediction: str, confidence: float, source: str) -> None:
        self.execute(
            "INSERT INTO phishing_logs (input_text, prediction, confidence, source, created_at) VALUES (?, ?, ?, ?, ?)",
            (input_text, prediction, confidence, source, datetime.utcnow().isoformat()),
        )

    def log_threat(self, threat_type: str, severity: str, description: str, source: str) -> None:
        self.execute(
            "INSERT INTO threat_logs (threat_type, severity, description, source, created_at) VALUES (?, ?, ?, ?, ?)",
            (threat_type, severity, description, source, datetime.utcnow().isoformat()),
        )

    def log_monitoring(self, cpu: float, memory: float, processes: int, network_sent: float, network_recv: float, threat_score: float, severity: str, anomaly_score: float) -> None:
        self.execute(
            "INSERT INTO monitoring_logs (cpu, memory, processes, network_sent, network_recv, threat_score, severity, anomaly_score, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (cpu, memory, processes, network_sent, network_recv, threat_score, severity, anomaly_score, datetime.utcnow().isoformat()),
        )

    def log_protection(self, action: str, target: str, result: str) -> None:
        self.execute(
            "INSERT INTO protection_logs (action, target, result, created_at) VALUES (?, ?, ?, ?)",
            (action, target, result, datetime.utcnow().isoformat()),
        )

    def log_device(self, device_name: str, ip_address: str, status: str, details: str) -> None:
        self.execute(
            "INSERT INTO device_logs (device_name, ip_address, status, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (device_name, ip_address, status, details, datetime.utcnow().isoformat()),
        )
