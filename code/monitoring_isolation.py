from __future__ import annotations

from collections import deque
from typing import List
from sklearn.ensemble import IsolationForest
import numpy as np


class MonitoringIsolationModel:
    def __init__(self, history_len: int = 60, contamination: float = 0.15):
        self.history = deque(maxlen=history_len)
        self.model: IsolationForest | None = None
        self.contamination = contamination

    def add_sample(self, sample: List[float]) -> None:
        # sample: [cpu, memory, processes, net_sent, net_recv]
        self.history.append(sample)

    def ready(self) -> bool:
        return len(self.history) >= 12

    def train_if_needed(self) -> None:
        if self.model is None and len(self.history) >= 12:
            data = np.array(list(self.history))
            self.model = IsolationForest(contamination=self.contamination, random_state=42)
            self.model.fit(data)

    def anomaly_score(self, sample: List[float]) -> float:
        # returns 0.0 normal .. higher means more anomalous (normalized)
        if self.model is None:
            return 0.0
        df = float(-self.model.decision_function([sample])[0])
        return float(df)
