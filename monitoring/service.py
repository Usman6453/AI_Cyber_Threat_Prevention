from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import psutil
from PyQt6.QtCore import QThread, pyqtSignal
from sklearn.ensemble import IsolationForest

from pathlib import Path
from typing import Optional
from config.settings import MONITORED_FOLDER
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from protection.service import ProtectionService
try:
    from protection.malware_scanner import MalwareScanner
except Exception:
    MalwareScanner = None

from database.db import DatabaseManager
from utils.event_bus import AppEventBus


@dataclass
class MonitoringSample:
    cpu: float
    memory: float
    processes: int
    network_sent: float
    network_recv: float
    threat_score: float
    severity: str
    timestamp: str
    anomaly_score: float = 0.0


class MonitoringService(QThread):
    sample_ready = pyqtSignal(object)

    def __init__(self, database: DatabaseManager, event_bus: AppEventBus | None = None, interval: int = 3, protection_service: ProtectionService | None = None, monitored_folder: str | Path | None = None) -> None:
        super().__init__()
        self.database = database
        self.event_bus = event_bus
        self.interval = interval
        self._running = True
        self._history: deque[list[float]] = deque(maxlen=60)
        self._previous_net = psutil.net_io_counters()
        self._model = None
        # anomaly detection tuning
        self.anomaly_window: int = 3  # require this many consecutive anomaly samples before alert
        self.anomaly_threshold: float = 0.6  # score above which a sample is considered anomalous
        self._anomaly_count: int = 0
        self._last_alert_time: float = 0.0
        self.alert_cooldown_seconds: int = 60  # minimum seconds between alerts for same condition
        # monitored folder / auto-quarantine
        self.protection_service: Optional[ProtectionService] = protection_service
        self.monitored_folder: Path = Path(monitored_folder or MONITORED_FOLDER)
        self._observer = None
        self._pending_files: set[Path] = set()
        # malware scanner for new files
        try:
            self.malware_scanner = MalwareScanner(event_bus=self.event_bus) if MalwareScanner is not None else None
        except Exception:
            self.malware_scanner = None
        # only auto-quarantine when severity is critical or configured threshold
        self.auto_quarantine_enabled: bool = False
        

    def stop(self) -> None:
        self._running = False
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=2)
            except Exception:
                pass

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 0.8:
            return "critical"
        if score >= 0.6:
            return "high"
        if score >= 0.35:
            return "medium"
        return "low"

    def _sample(self) -> MonitoringSample:
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        processes = len(psutil.pids())
        current_net = psutil.net_io_counters()
        network_sent = max(0.0, float(current_net.bytes_sent - self._previous_net.bytes_sent) / 1024.0)
        network_recv = max(0.0, float(current_net.bytes_recv - self._previous_net.bytes_recv) / 1024.0)
        self._previous_net = current_net
        vector = [cpu, memory, float(processes), network_sent, network_recv]
        self._history.append(vector)
        score = min(1.0, (cpu / 100.0) * 0.35 + (memory / 100.0) * 0.35 + min(1.0, (network_sent + network_recv) / 2000.0) * 0.3)
        anomaly = 0.0
        if len(self._history) >= 12:
            if self._model is None:
                self._model = IsolationForest(contamination=0.15, random_state=42)
                self._model.fit(list(self._history))
            # decision_function returns positive values for normal, negative for anomalies
            anomaly = float(-self._model.decision_function([vector])[0])
            score = max(score, min(1.0, anomaly + 0.5))
        severity = self._severity(score)
        return MonitoringSample(
            cpu,
            memory,
            processes,
            network_sent,
            network_recv,
            score,
            severity,
            datetime.now(timezone.utc).isoformat(),
            anomaly_score=anomaly,
        )

    def run(self) -> None:
        # start folder watcher if configured
        try:
            if self.monitored_folder and self.monitored_folder.exists():
                handler = self._FolderHandler(self)
                self._observer = Observer()
                self._observer.schedule(handler, str(self.monitored_folder), recursive=True)
                self._observer.start()
        except Exception:
            self._observer = None

        while self._running:
            sample = self._sample()
            payload = asdict(sample)
            # log routine samples separately so they do not inflate threat counts
            self.database.log_monitoring(
                sample.cpu,
                sample.memory,
                sample.processes,
                sample.network_sent,
                sample.network_recv,
                sample.threat_score,
                sample.severity,
                sample.anomaly_score,
            )
            if self.event_bus:
                self.event_bus.emit_metrics(payload)
                self.event_bus.emit_log({"module": "monitoring", **payload})

            # decide anomaly persistence before emitting high-severity alerts to reduce false positives
            is_anomalous = float(payload.get("anomaly_score", 0.0)) >= self.anomaly_threshold or float(payload.get("threat_score", 0.0)) >= self.anomaly_threshold
            if is_anomalous:
                self._anomaly_count += 1
            else:
                self._anomaly_count = 0

            now = __import__("time").time()
            if self._anomaly_count >= self.anomaly_window and (now - self._last_alert_time) >= self.alert_cooldown_seconds:
                # emit a consolidated threat alert
                self.database.log_threat(
                    "system_monitor",
                    sample.severity,
                    f"Sustained monitoring severity {sample.severity} detected",
                    "monitoring_alert",
                )
                if self.event_bus:
                    self.event_bus.emit_threat({"module": "monitoring", **payload})
                    self.event_bus.emit_alert({
                        "title": "System threat alert",
                        "message": f"Sustained monitoring severity {sample.severity} detected",
                        "severity": sample.severity,
                        "module": "monitoring",
                    })
                self._last_alert_time = now
                # reset counter after alert to avoid immediate repeats
                self._anomaly_count = 0
                # if auto-quarantine enabled and protection service available and severity high/critical
                try:
                    if self.auto_quarantine_enabled and self.protection_service and sample.severity in ("critical", "high"):
                        # quarantine pending files (copy + encrypt) but do not delete originals
                        for f in list(self._pending_files):
                            try:
                                self.protection_service.quarantine_file(f)
                            except Exception:
                                pass
                        # clear pending files after action
                        self._pending_files.clear()
                except Exception:
                    pass

    class _FolderHandler(FileSystemEventHandler):
        def __init__(self, outer: "MonitoringService") -> None:
            super().__init__()
            self.outer = outer

        def on_created(self, event: FileSystemEvent):
            try:
                path = Path(str(event.src_path))
                if path.is_file():
                    # add to pending set
                    self.outer._pending_files.add(path)
                    # run a quick scan for suspicious files and auto-quarantine if detected
                    try:
                        scanner = getattr(self.outer, 'malware_scanner', None)
                        if scanner is not None and self.outer.protection_service is not None:
                            res = scanner.scan_file(path)
                            if res.get('malicious'):
                                try:
                                    self.outer.protection_service.quarantine_file(path)
                                    # record as threat
                                    try:
                                        self.outer.database.log_threat('malware_scanner', 'high', f'File quarantined: {path.name}', 'malware_detected')
                                    except Exception:
                                        pass
                                    # remove from pending since action taken
                                    if path in self.outer._pending_files:
                                        self.outer._pending_files.discard(path)
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                pass

        def on_moved(self, event: FileSystemEvent):
            try:
                path = Path(str(event.dest_path))
                if path.is_file():
                    self.outer._pending_files.add(path)
                    try:
                        scanner = getattr(self.outer, 'malware_scanner', None)
                        if scanner is not None and self.outer.protection_service is not None:
                            res = scanner.scan_file(path)
                            if res.get('malicious'):
                                try:
                                    self.outer.protection_service.quarantine_file(path)
                                    try:
                                        self.outer.database.log_threat('malware_scanner', 'high', f'File quarantined: {path.name}', 'malware_detected')
                                    except Exception:
                                        pass
                                    if path in self.outer._pending_files:
                                        self.outer._pending_files.discard(path)
                                except Exception:
                                    pass
                    except Exception:
                        pass
            except Exception:
                pass
