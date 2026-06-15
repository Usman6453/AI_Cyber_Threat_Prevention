from __future__ import annotations

import os
import shutil
from pathlib import Path

import psutil

from config.settings import BLOCKED_IPS_PATH, QUARANTINE_DIR
from database.db import DatabaseManager
from encryption.fernet_manager import FileEncryptionManager
from utils.event_bus import AppEventBus


class ProtectionService:
    def __init__(self, database: DatabaseManager, event_bus: AppEventBus | None = None) -> None:
        self.database = database
        self.event_bus = event_bus
        self.encryption = FileEncryptionManager(QUARANTINE_DIR / "master.key")

    def simulate_emergency_mode(self, reason: str) -> dict:
        payload = {"action": "emergency_mode", "reason": reason, "status": "activated"}
        self.database.log_protection("emergency_mode", reason, "activated")
        if self.event_bus:
            self.event_bus.emit_alert({"title": "Emergency mode", "message": reason, "severity": "critical", "module": "protection"})
            self.event_bus.emit_log({"module": "protection", **payload})
        return payload

    def quarantine_file(self, file_path: str | Path) -> dict:
        source = Path(file_path)
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        target = QUARANTINE_DIR / source.name
        shutil.copy2(source, target)
        encrypted_path = self.encryption.encrypt_file(target)
        self.database.execute(
            "INSERT INTO encrypted_files (file_path, key_path, status, created_at) VALUES (?, ?, ?, datetime('now'))",
            (str(source), str(self.encryption.key_path), "encrypted"),
        )
        self.database.log_protection("quarantine_file", str(source), "encrypted and quarantined")
        if self.event_bus:
            self.event_bus.emit_alert({"title": "File quarantined", "message": source.name, "severity": "high", "module": "protection"})
        return {"source": str(source), "quarantine": str(target), "encrypted": str(encrypted_path)}

    def terminate_process(self, pid: int) -> dict:
        if pid == os.getpid():
            return {"pid": pid, "status": "skipped"}
        try:
            process = psutil.Process(pid)
            process.terminate()
            result = f"terminated {pid}"
        except Exception as exc:
            result = f"failed: {exc}"
        self.database.log_protection("terminate_process", str(pid), result)
        return {"pid": pid, "result": result}

    def block_ip(self, ip_address: str) -> dict:
        BLOCKED_IPS_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = BLOCKED_IPS_PATH.read_text(encoding="utf-8") if BLOCKED_IPS_PATH.exists() else ""
        if ip_address not in existing.splitlines():
            BLOCKED_IPS_PATH.write_text(existing + f"{ip_address}\n", encoding="utf-8")
        self.database.log_protection("block_ip", ip_address, "added to local block list")
        return {"ip": ip_address, "status": "blocked"}
