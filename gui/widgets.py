from __future__ import annotations

from typing import Iterable

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPainter, QPen, QPolygonF, QFontMetrics
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QProgressBar,
    QSpacerItem,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)


class MetricCard(QFrame):
    def __init__(self, title: str, value: str = "0", subtitle: str = "Live") -> None:
        super().__init__()
        self.setObjectName("metricCard")
        layout = QVBoxLayout(self)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("metricTitle")
        self.value_label = QLabel(value)
        self.value_label.setObjectName("metricValue")
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setObjectName("metricSubtitle")
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.subtitle_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(value)

    def set_subtitle(self, text: str) -> None:
        self.subtitle_label.setText(text)


class GlowButton(QPushButton):
    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.setObjectName("glowButton")


class CyberTerminal(QTextEdit):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("cyberTerminal")
        self.setReadOnly(True)
        self.setPlaceholderText("Live cyber terminal output appears here...")

    def append_line(self, text: str) -> None:
        self.append(text)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


class LineChartWidget(QWidget):
    def __init__(self, title: str = "Live Graph") -> None:
        super().__init__()
        self.title = title
        self.values: list[float] = []
        self.setMinimumHeight(180)
        self.setObjectName("lineChart")

    def set_values(self, values: Iterable[float]) -> None:
        self.values = list(values)[-60:]
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(12, 28, -12, -12)
        painter.fillRect(self.rect(), QColor("#0b1020"))
        painter.setPen(QColor("#7cf7ff"))
        painter.drawText(12, 18, self.title)
        painter.setPen(QColor("#23304f"))
        painter.drawRect(rect)
        if len(self.values) < 2:
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, "Waiting for live data")
            return
        minimum = min(self.values)
        maximum = max(self.values)
        span = max(maximum - minimum, 1.0)
        points = []
        for index, value in enumerate(self.values):
            x = rect.left() + (rect.width() * index / max(len(self.values) - 1, 1))
            y = rect.bottom() - ((value - minimum) / span) * rect.height()
            points.append((x, y))
        painter.setPen(QPen(QColor("#00e5ff"), 2))
        for left, right in zip(points, points[1:]):
            painter.drawLine(int(left[0]), int(left[1]), int(right[0]), int(right[1]))
        painter.setPen(QPen(QColor("#00ff95"), 4))
        for x, y in points[-10:]:
            painter.drawPoint(int(x), int(y))


class PhishingScannerWidget(QWidget):
    def __init__(self, phishing_service) -> None:
        super().__init__()
        self.phishing_service = phishing_service
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        header = QLabel("Standalone Phishing Scanner")
        header.setObjectName("sectionHeader")
        layout.addWidget(header)

        self.input_box = QTextEdit()
        self.input_box.setPlaceholderText("Paste a URL, email, or message here for phishing analysis...")
        self.input_box.setMinimumHeight(140)
        layout.addWidget(self.input_box)

        button_row = QHBoxLayout()
        self.scan_button = GlowButton("Scan Now")
        self.scan_button.clicked.connect(self.scan_text)
        button_row.addWidget(self.scan_button)
        button_row.addItem(QSpacerItem(20, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        layout.addLayout(button_row)

        self.result_label = QLabel("Result: waiting")
        self.result_label.setObjectName("resultLabel")
        self.confidence_bar = QProgressBar()
        self.confidence_bar.setRange(0, 100)
        self.confidence_bar.setFormat("Confidence %p%")
        layout.addWidget(self.result_label)
        layout.addWidget(self.confidence_bar)

        self.history_table = QTableWidget(0, 4)
        self.history_table.setHorizontalHeaderLabels(["Text", "Prediction", "Confidence", "Risk"])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.history_table)

    def scan_text(self) -> None:
        text = self.input_box.toPlainText().strip()
        if not text:
            self.result_label.setText("Result: enter text to scan")
            return
        payload = self.phishing_service.scan(text, source="gui")
        label = str(payload["prediction"]).title()
        confidence = float(payload["confidence"])
        risk = str(payload["risk"]).title()
        self.result_label.setText(f"Result: {label} | Risk: {risk}")
        self.confidence_bar.setValue(int(confidence * 100))
        row = self.history_table.rowCount()
        self.history_table.insertRow(row)
        self.history_table.setItem(row, 0, QTableWidgetItem(text[:80]))
        self.history_table.setItem(row, 1, QTableWidgetItem(label))
        self.history_table.setItem(row, 2, QTableWidgetItem(f"{confidence:.2f}"))
        self.history_table.setItem(row, 3, QTableWidgetItem(risk))
