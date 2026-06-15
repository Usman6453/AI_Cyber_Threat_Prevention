from __future__ import annotations

from dataclasses import dataclass

from database.db import DatabaseManager


@dataclass
class AnalyticsSummary:
    login_count: int
    phishing_count: int
    threat_count: int
    protection_count: int
    device_count: int
    security_score: float


class AnalyticsService:
    def __init__(self, database: DatabaseManager) -> None:
        self.database = database

    def summary(self) -> AnalyticsSummary:
        login_count = self.database.fetch_one("SELECT COUNT(*) AS c FROM login_logs")['c']
        phishing_count = self.database.fetch_one("SELECT COUNT(*) AS c FROM phishing_logs")['c']
        threat_count = self.database.fetch_one("SELECT COUNT(*) AS c FROM threat_logs WHERE source != 'monitoring'")['c']
        protection_count = self.database.fetch_one("SELECT COUNT(*) AS c FROM protection_logs")['c']
        device_count = self.database.fetch_one("SELECT COUNT(*) AS c FROM device_logs")['c']
        security_score = max(0.0, 100.0 - float(threat_count) * 3.0 - float(phishing_count) * 2.0)
        return AnalyticsSummary(
            login_count=int(login_count),
            phishing_count=int(phishing_count),
            threat_count=int(threat_count),
            protection_count=int(protection_count),
            device_count=int(device_count),
            security_score=round(security_score, 1),
        )
