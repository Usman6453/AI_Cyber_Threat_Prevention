

from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap
from PyQt6.QtWidgets import (
	QCheckBox,
	QDoubleSpinBox,
	QFileDialog,
	QFormLayout,
	QFrame,
	QHBoxLayout,
	QLabel,
	QLineEdit,
	QMainWindow,
	QMessageBox,
	QPushButton,
	QProgressBar,
	QSpinBox,
	QStackedWidget,
	QSystemTrayIcon,
	QTableWidget,
	QTableWidgetItem,
	QVBoxLayout,
	QWidget,
)

from analytics.service import AnalyticsService
from authentication.auth_service import AuthService
from config.settings import APP_NAME, APP_SHORT_NAME, REPORTS_DIR
from database.db import DatabaseManager
from monitoring.service import MonitoringService
from phishing_detection.service import PhishingService
from protection.service import ProtectionService
from utils.event_bus import AppEventBus
from utils.system_info import get_system_snapshot
from utils.windows_startup import set_startup

from .widgets import CyberTerminal, GlowButton, LineChartWidget, MetricCard, PhishingScannerWidget


class LoginPage(QWidget):
	def __init__(self, auth_service: AuthService, on_login_success) -> None:
		super().__init__()
		self.auth_service = auth_service
		self.on_login_success = on_login_success
		self._build_ui()

	def _build_ui(self) -> None:
		layout = QVBoxLayout(self)
		layout.setContentsMargins(28, 28, 28, 28)
		layout.setSpacing(14)
		title = QLabel("AI-Driven Cyber Threat Prevention System")
		title.setObjectName("sectionHeader")
		subtitle = QLabel("Premium cyber defense dashboard with AI phishing detection and live monitoring")
		subtitle.setObjectName("smallText")
		layout.addWidget(title)
		layout.addWidget(subtitle)

		form_card = QFrame()
		form_card.setObjectName("panelCard")
		form_layout = QFormLayout(form_card)
		form_layout.setContentsMargins(18, 18, 18, 18)
		form_layout.setSpacing(12)
		self.username = QLineEdit()
		self.username.setPlaceholderText("Username")
		self.password = QLineEdit()
		self.password.setPlaceholderText("Password")
		self.password.setEchoMode(QLineEdit.EchoMode.Password)
		self.new_password = QLineEdit()
		self.new_password.setPlaceholderText("New password for sign up")
		self.new_password.setEchoMode(QLineEdit.EchoMode.Password)
		self.remember_me = QCheckBox("Remember me")
		form_layout.addRow("Username", self.username)
		form_layout.addRow("Password", self.password)
		form_layout.addRow("Sign up password", self.new_password)
		form_layout.addRow("", self.remember_me)

		button_row = QHBoxLayout()
		login_button = GlowButton("Login")
		signup_button = GlowButton("Create Account")
		login_button.clicked.connect(self.login)
		signup_button.clicked.connect(self.signup)
		button_row.addWidget(login_button)
		button_row.addWidget(signup_button)
		form_layout.addRow(button_row)

		layout.addWidget(form_card)
		layout.addStretch(1)

	def login(self) -> None:
		result = self.auth_service.authenticate(self.username.text().strip(), self.password.text())
		if result.success:
			self.on_login_success(result.username or self.username.text().strip())
		else:
			QMessageBox.warning(self, "Login failed", result.message)

	def signup(self) -> None:
		username = self.username.text().strip()
		password = self.new_password.text()
		if not username or not password:
			QMessageBox.warning(self, "Missing data", "Enter a username and sign up password")
			return
		result = self.auth_service.register_user(username, password)
		if result.success:
			QMessageBox.information(self, "Account created", "You can now log in")
		else:
			QMessageBox.warning(self, "Sign up failed", result.message)


class LandingPage(QWidget):
	def __init__(self, on_complete) -> None:
		super().__init__()
		self.on_complete = on_complete
		self.step_index = 0
		self._build_ui()
		self._pulse_timer = QTimer(self)
		self._pulse_timer.timeout.connect(self._animate)
		self._pulse_timer.start(300)
		self._finish_timer = QTimer(self)
		self._finish_timer.setSingleShot(True)
		self._finish_timer.timeout.connect(self.finish)
		self._finish_timer.start(6500)

	def _build_ui(self) -> None:
		layout = QVBoxLayout(self)
		layout.setContentsMargins(32, 32, 32, 32)
		layout.setSpacing(18)
		layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

		self.logo_label = QLabel(APP_SHORT_NAME)
		self.logo_label.setObjectName("landingLogo")
		self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
		layout.addWidget(self.logo_label)

		tagline = QLabel("Secure your Windows environment with AI-powered threat defense.")
		tagline.setObjectName("landingSubtitle")
		tagline.setAlignment(Qt.AlignmentFlag.AlignCenter)
		layout.addWidget(tagline)

		self.progress = QLabel("Preparing your security command center...")
		self.progress.setObjectName("landingProgress")
		self.progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
		layout.addWidget(self.progress)

		steps_card = QFrame()
		steps_card.setObjectName("panelCard")
		steps_layout = QVBoxLayout(steps_card)
		steps_layout.setContentsMargins(18, 18, 18, 18)
		steps_layout.setSpacing(12)
		head = QLabel("Getting started in seconds")
		head.setObjectName("sectionHeader")
		steps_layout.addWidget(head)

		self.step_labels: list[QLabel] = []
		for step in [
			"1. Login to the secure dashboard",
			"2. Monitor live system telemetry",
			"3. Scan URLs and files for phishing",
			"4. Quarantine suspicious artifacts",
			"5. Review reports and threat insights",
		]:
			label = QLabel(step)
			label.setObjectName("landingStep")
			steps_layout.addWidget(label)
			self.step_labels.append(label)

		layout.addWidget(steps_card)

		self.start_button = GlowButton("Start Secure Session")
		self.start_button.clicked.connect(self.finish)
		layout.addWidget(self.start_button)
		layout.addStretch(1)

	def _animate(self) -> None:
		pulse = 72 + ((self.step_index % 6) * 2)
		self.logo_label.setStyleSheet(
			f"font-size: {pulse}px; color: #00e5ff; font-weight: 900;"
		)
		active = self.step_index % len(self.step_labels)
		for idx, label in enumerate(self.step_labels):
			label.setStyleSheet(
				"color: #ffffff;" if idx != active else "color: #00e5ff; font-weight: bold;"
			)
		self.progress.setText(
			"Loading AI modules..." if active < 2 else "Configuring threat engine..." if active < 4 else "Almost ready..."
		)
		self.step_index += 1

	def finish(self) -> None:
		self._pulse_timer.stop()
		self._finish_timer.stop()
		self.on_complete()


class HomePage(QWidget):
	def __init__(self, analytics_service: AnalyticsService, phishing_service: PhishingService) -> None:
		super().__init__()
		self.analytics_service = analytics_service
		self.phishing_service = phishing_service
		self.security_history: list[float] = []
		self._build_ui()

	def _build_ui(self) -> None:
		layout = QVBoxLayout(self)
		layout.setContentsMargins(24, 24, 24, 24)
		layout.setSpacing(14)
		header_card = QFrame()
		header_card.setObjectName("panelCard")
		header_layout = QVBoxLayout(header_card)
		header_layout.setContentsMargins(18, 18, 18, 18)
		self.summary_label = QLabel("Security score and threat posture overview")
		self.summary_label.setObjectName("sectionHeader")
		header_layout.addWidget(self.summary_label)
		desc = QLabel("Live posture, event telemetry, and threat analytics in one command-center view.")
		desc.setObjectName("smallText")
		header_layout.addWidget(desc)
		layout.addWidget(header_card)

		metrics_row = QHBoxLayout()
		metrics_row.setSpacing(14)
		self.login_card = MetricCard("Logins", "0", "Tracked auth events")
		self.phishing_card = MetricCard("Phishing", "0", "Detected scans")
		self.threat_card = MetricCard("Threats", "0", "Live system anomalies")
		self.score_card = MetricCard("Security Score", "100", "Higher is better")
		for card in (self.login_card, self.phishing_card, self.threat_card, self.score_card):
			metrics_row.addWidget(card)
		layout.addLayout(metrics_row)

		self.chart = LineChartWidget("Security score trend")
		layout.addWidget(self.chart)

		self.terminal = CyberTerminal()
		self.terminal.setMinimumHeight(170)
		self.terminal.setPlaceholderText("Live security notes and system messages appear here...")
		layout.addWidget(self.terminal)

	def refresh(self) -> None:
		summary = self.analytics_service.summary()
		self.login_card.set_value(str(summary.login_count))
		self.phishing_card.set_value(str(summary.phishing_count))
		self.threat_card.set_value(str(summary.threat_count))
		self.score_card.set_value(str(summary.security_score))
		self.security_history.append(summary.security_score)
		self.chart.set_values(self.security_history)
		self.terminal.append_line(f"[{datetime.now().strftime('%H:%M:%S')}] Security score updated to {summary.security_score}")


class MonitoringPage(QWidget):
	def __init__(self, protection_service: ProtectionService) -> None:
		super().__init__()
		self.protection_service = protection_service
		self.samples: list[float] = []
		layout = QVBoxLayout(self)
		layout.setContentsMargins(24, 24, 24, 24)
		layout.setSpacing(14)
		header_card = QFrame()
		header_card.setObjectName("panelCard")
		header_layout = QVBoxLayout(header_card)
		header_layout.setContentsMargins(18, 18, 18, 18)
		header = QLabel("Live monitoring center")
		header.setObjectName("sectionHeader")
		header_layout.addWidget(header)
		status = QLabel("CPU, memory, process and network signals update continuously.")
		status.setObjectName("smallText")
		header_layout.addWidget(status)
		layout.addWidget(header_card)
		self.chart = LineChartWidget("CPU / risk signal")
		layout.addWidget(self.chart)
		self.live_stats = QLabel("Waiting for live metrics...")
		layout.addWidget(self.live_stats)
		self.emergency_button = QPushButton("Trigger Emergency Mode")
		self.emergency_button.setObjectName("dangerButton")
		self.emergency_button.clicked.connect(self.trigger_emergency)
		layout.addWidget(self.emergency_button)
		self.manual_quarantine_button = GlowButton("Manual Quarantine File")
		self.manual_quarantine_button.clicked.connect(self.manual_quarantine)
		layout.addWidget(self.manual_quarantine_button)

	def update_sample(self, payload: dict[str, object]) -> None:
		score = float(payload.get("threat_score", 0.0))
		self.samples.append(score * 100)
		self.chart.set_values(self.samples)
		self.live_stats.setText(
			f"CPU {payload.get('cpu', 0):.1f}% | RAM {payload.get('memory', 0):.1f}% | Threat {payload.get('severity', 'low')}"
		)

	def trigger_emergency(self) -> None:
		self.protection_service.simulate_emergency_mode("Manual emergency mode triggered from dashboard")

	def manual_quarantine(self) -> None:
		path, _ = QFileDialog.getOpenFileName(self, "Select file to quarantine")
		if not path:
			return
		try:
			res = self.protection_service.quarantine_file(path)
			QMessageBox.information(self, "Quarantined", f"Quarantined: {res.get('quarantine')}\nEncrypted: {res.get('encrypted')}")
		except Exception as exc:
			QMessageBox.warning(self, "Error", f"Failed to quarantine: {exc}")


class SimpleDataPage(QWidget):
	def __init__(self, title: str, headers: list[str]) -> None:
		super().__init__()
		layout = QVBoxLayout(self)
		layout.setContentsMargins(24, 24, 24, 24)
		layout.setSpacing(14)
		panel = QFrame()
		panel.setObjectName("panelCard")
		panel_layout = QVBoxLayout(panel)
		panel_layout.setContentsMargins(18, 18, 18, 18)
		header = QLabel(title)
		header.setObjectName("sectionHeader")
		panel_layout.addWidget(header)
		self.table = QTableWidget(0, len(headers))
		self.table.setHorizontalHeaderLabels(headers)
		self.table.horizontalHeader().setStretchLastSection(True)
		self.table.setAlternatingRowColors(True)
		self.table.setShowGrid(False)
		self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
		panel_layout.addWidget(self.table)
		layout.addWidget(panel)

	def set_rows(self, rows: list[tuple[object, ...]]) -> None:
		self.table.setRowCount(0)
		for row_data in rows:
			row = self.table.rowCount()
			self.table.insertRow(row)
			for column, value in enumerate(row_data):
				self.table.setItem(row, column, QTableWidgetItem(str(value)))


class ReportsPage(QWidget):
	def __init__(self, analytics_service: AnalyticsService) -> None:
		super().__init__()
		self.analytics_service = analytics_service
		layout = QVBoxLayout(self)
		layout.setContentsMargins(24, 24, 24, 24)
		layout.setSpacing(14)
		panel = QFrame()
		panel.setObjectName("panelCard")
		panel_layout = QVBoxLayout(panel)
		panel_layout.setContentsMargins(18, 18, 18, 18)
		header = QLabel("Reports and exports")
		header.setObjectName("sectionHeader")
		panel_layout.addWidget(header)
		self.summary_label = QLabel("")
		self.summary_label.setObjectName("smallText")
		panel_layout.addWidget(self.summary_label)
		self.export_button = GlowButton("Export CSV Report")
		self.export_button.clicked.connect(self.export_csv)
		panel_layout.addWidget(self.export_button)
		layout.addWidget(panel)
		layout.addStretch(1)
		self.refresh()

	def refresh(self) -> None:
		summary = self.analytics_service.summary()
		self.summary_label.setText(
			f"Logins: {summary.login_count} | Phishing: {summary.phishing_count} | Threats: {summary.threat_count} | Score: {summary.security_score}"
		)

	def export_csv(self) -> None:
		REPORTS_DIR.mkdir(parents=True, exist_ok=True)
		path = REPORTS_DIR / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
		summary = self.analytics_service.summary()
		with path.open("w", newline="", encoding="utf-8") as handle:
			writer = csv.writer(handle)
			writer.writerow(["metric", "value"])
			writer.writerow(["login_count", summary.login_count])
			writer.writerow(["phishing_count", summary.phishing_count])
			writer.writerow(["threat_count", summary.threat_count])
			writer.writerow(["protection_count", summary.protection_count])
			writer.writerow(["device_count", summary.device_count])
			writer.writerow(["security_score", summary.security_score])
		QMessageBox.information(self, "Export complete", f"Report saved to {path}")


class SettingsPage(QWidget):
	def __init__(self, main_window: "CyberDefenseWindow") -> None:
		super().__init__()
		self.main_window = main_window
		layout = QVBoxLayout(self)
		layout.setContentsMargins(24, 24, 24, 24)
		layout.setSpacing(14)
		panel = QFrame()
		panel.setObjectName("panelCard")
		panel_layout = QVBoxLayout(panel)
		panel_layout.setContentsMargins(18, 18, 18, 18)
		header = QLabel("Settings")
		header.setObjectName("sectionHeader")
		panel_layout.addWidget(header)

		self.autorun = QCheckBox("Run on Windows startup")
		self.autorun.stateChanged.connect(self.toggle_startup)
		panel_layout.addWidget(self.autorun)

		form = QFormLayout()
		self.anomaly_window_spin = QSpinBox()
		self.anomaly_window_spin.setRange(1, 20)
		self.anomaly_window_spin.setValue(self.main_window.monitoring_service.anomaly_window)
		form.addRow("Anomaly window (samples)", self.anomaly_window_spin)

		self.anomaly_threshold_spin = QDoubleSpinBox()
		self.anomaly_threshold_spin.setRange(0.0, 1.0)
		self.anomaly_threshold_spin.setSingleStep(0.05)
		self.anomaly_threshold_spin.setValue(self.main_window.monitoring_service.anomaly_threshold)
		form.addRow("Anomaly threshold", self.anomaly_threshold_spin)

		self.alert_cooldown_spin = QSpinBox()
		self.alert_cooldown_spin.setRange(5, 3600)
		self.alert_cooldown_spin.setValue(self.main_window.monitoring_service.alert_cooldown_seconds)
		form.addRow("Alert cooldown (s)", self.alert_cooldown_spin)

		self.auto_quarantine = QCheckBox("Enable auto-quarantine for watched folder")
		self.auto_quarantine.setChecked(self.main_window.monitoring_service.auto_quarantine_enabled)
		form.addRow(self.auto_quarantine)

		self.monitored_folder_input = QLineEdit(str(self.main_window.monitoring_service.monitored_folder))
		browse_btn = QPushButton("Browse")
		browse_btn.clicked.connect(self.browse_folder)
		folder_row = QHBoxLayout()
		folder_row.addWidget(self.monitored_folder_input)
		folder_row.addWidget(browse_btn)
		form.addRow("Monitored folder", folder_row)

		panel_layout.addLayout(form)
		apply_btn = GlowButton("Apply settings")
		apply_btn.clicked.connect(self.apply_settings)
		panel_layout.addWidget(apply_btn)

		self.launch_phishing = GlowButton("Open Standalone Phishing Module")
		self.launch_phishing.clicked.connect(self.main_window.open_standalone_phishing)
		panel_layout.addWidget(self.launch_phishing)
		layout.addWidget(panel)
		layout.addStretch(1)

	def toggle_startup(self) -> None:
		enabled = self.autorun.isChecked()
		app_path = str(Path(__file__).resolve().parents[1] / "main.py")
		set_startup(enabled, APP_SHORT_NAME, f'"{app_path}"')

	def browse_folder(self) -> None:
		path = QFileDialog.getExistingDirectory(self, "Select folder to monitor")
		if path:
			self.monitored_folder_input.setText(path)

	def apply_settings(self) -> None:
		try:
			self.main_window.monitoring_service.anomaly_window = int(self.anomaly_window_spin.value())
			self.main_window.monitoring_service.anomaly_threshold = float(self.anomaly_threshold_spin.value())
			self.main_window.monitoring_service.alert_cooldown_seconds = int(self.alert_cooldown_spin.value())
			self.main_window.monitoring_service.auto_quarantine_enabled = bool(self.auto_quarantine.isChecked())
			monitored_folder = Path(self.monitored_folder_input.text())
			if monitored_folder.exists():
				self.main_window.monitoring_service.monitored_folder = monitored_folder
			QMessageBox.information(self, "Settings applied", "Monitoring settings updated")
		except Exception as exc:
			QMessageBox.warning(self, "Error", f"Failed to apply settings: {exc}")


class DashboardShell(QWidget):
	def __init__(self, window: "CyberDefenseWindow") -> None:
		super().__init__()
		self.window = window
		self.sidebar_buttons: list[QPushButton] = []
		self.button_map: dict[str, QPushButton] = {}
		self._build_ui()

	def _build_ui(self) -> None:
		main_layout = QHBoxLayout(self)
		main_layout.setContentsMargins(20, 20, 20, 20)
		main_layout.setSpacing(16)

		sidebar = QFrame()
		sidebar.setObjectName("panelCard")
		sidebar.setMaximumWidth(220)
		sidebar_layout = QVBoxLayout(sidebar)
		sidebar_layout.setContentsMargins(18, 18, 18, 18)
		sidebar_layout.setSpacing(10)
		heading = QLabel(APP_NAME)
		heading.setObjectName("sectionHeader")
		sidebar_layout.addWidget(heading)

		nav_items = [
			("Home", "home"),
			("Live Monitoring", "monitoring"),
			("Threat Analytics", "analytics"),
			("Device Monitoring", "devices"),
			("Phishing Scanner", "phishing"),
			("Reports", "reports"),
			("Quarantine", "quarantine"),
			("Logs", "logs"),
			("Settings", "settings"),
		]
		for label, page_key in nav_items:
			button = QPushButton(label)
			button.setCheckable(True)
			button.setObjectName("navButton")
			button.clicked.connect(lambda checked=False, key=page_key: self.window.switch_page(key))
			self.sidebar_buttons.append(button)
			self.button_map[page_key] = button
			sidebar_layout.addWidget(button)
		sidebar_layout.addStretch(1)
		main_layout.addWidget(sidebar)

		self.stack = QStackedWidget()
		self.stack.setObjectName("panelCard")
		self.home_page = HomePage(self.window.analytics_service, self.window.phishing_service)
		self.monitoring_page = MonitoringPage(self.window.protection_service)
		self.analytics_page = SimpleDataPage("Threat analytics", ["Time", "Module", "Severity", "Message"])
		self.device_page = SimpleDataPage("Device monitoring", ["Time", "Device", "IP", "Status", "Details"])
		self.phishing_page = PhishingScannerWidget(self.window.phishing_service)
		self.quarantine_page = None
		self.reports_page = ReportsPage(self.window.analytics_service)
		self.logs_page = SimpleDataPage("Live logs", ["Time", "Module", "Severity", "Message"])
		self.settings_page = SettingsPage(self.window)

		self.pages: dict[str, QWidget | None] = {
			"home": self.home_page,
			"monitoring": self.monitoring_page,
			"analytics": self.analytics_page,
			"devices": self.device_page,
			"phishing": self.phishing_page,
			"quarantine": None,
			"reports": self.reports_page,
			"logs": self.logs_page,
			"settings": self.settings_page,
		}
		for page in self.pages.values():
			if page is not None:
				self.stack.addWidget(page)
		main_layout.addWidget(self.stack, 1)
		self.switch_page("home")

	def ensure_quarantine_page(self) -> None:
		if self.pages.get("quarantine") is None:
			class QuarantinePage(QWidget):
				def __init__(self, database: DatabaseManager, protection_service: ProtectionService) -> None:
					super().__init__()
					self.database = database
					self.protection_service = protection_service
					layout = QVBoxLayout(self)
					header = QLabel("Quarantine")
					header.setObjectName("sectionHeader")
					layout.addWidget(header)
					self.table = QTableWidget(0, 5)
					self.table.setHorizontalHeaderLabels(["ID", "Source Path", "Encrypted Path", "Status", "Created At"])
					self.table.horizontalHeader().setStretchLastSection(True)
					layout.addWidget(self.table)
					btn_row = QHBoxLayout()
					refresh = GlowButton("Refresh")
					refresh.clicked.connect(self.refresh)
					restore = GlowButton("Restore Selected")
					restore.clicked.connect(self.restore_selected)
					btn_row.addWidget(refresh)
					btn_row.addWidget(restore)
					layout.addLayout(btn_row)

				def refresh(self) -> None:
					rows = self.database.fetch_all("SELECT id, file_path, key_path, status, created_at FROM encrypted_files ORDER BY id DESC LIMIT 100")
					self.table.setRowCount(0)
					for row_data in rows:
						row = self.table.rowCount()
						self.table.insertRow(row)
						for column, value in enumerate(row_data):
							self.table.setItem(row, column, QTableWidgetItem(str(value)))

				def restore_selected(self) -> None:
					row = self.table.currentRow()
					if row < 0:
						QMessageBox.information(self, "Select", "Select a row to restore")
						return
					encrypted_path = self.table.item(row, 2).text()
					suggested = Path(encrypted_path).with_suffix("")
					out_path, _ = QFileDialog.getSaveFileName(self, "Restore to", str(suggested))
					if not out_path:
						return
					try:
						self.protection_service.encryption.decrypt_file(encrypted_path, out_path)
						self.database.log_protection("restore_file", out_path, "restored")
						QMessageBox.information(self, "Restored", f"Restored to {out_path}")
						self.refresh()
					except Exception as exc:
						QMessageBox.warning(self, "Failed", f"Restore failed: {exc}")

			page = QuarantinePage(self.window.database, self.window.protection_service)
			page.refresh()
			self.pages["quarantine"] = page
			self.stack.addWidget(page)

	def switch_page(self, page_key: str) -> None:
		if page_key == "quarantine":
			self.ensure_quarantine_page()
		page = self.pages[page_key]
		if page is not None:
			self.stack.setCurrentWidget(page)
		for key, button in self.button_map.items():
			button.setChecked(key == page_key)
		if hasattr(self.window, "dashboard_shell"):
			self.window.refresh_all()


class CyberDefenseWindow(QMainWindow):
	def __init__(self, database: DatabaseManager, event_bus: AppEventBus, auth_service: AuthService, phishing_service: PhishingService, protection_service: ProtectionService, analytics_service: AnalyticsService) -> None:
		super().__init__()
		self.database = database
		self.event_bus = event_bus
		self.auth_service = auth_service
		self.phishing_service = phishing_service
		self.protection_service = protection_service
		self.analytics_service = analytics_service
		self.monitoring_service = MonitoringService(database, event_bus, protection_service=self.protection_service)
		self.monitoring_service.sample_ready.connect(self.on_sample_ready)
		self._build_ui()
		self._connect_events()
		self.monitoring_service.start()
		self.refresh_timer = QTimer(self)
		self.refresh_timer.timeout.connect(self.refresh_all)
		self.refresh_timer.start(4000)

	def _build_ui(self) -> None:
		self.setWindowTitle(APP_NAME)
		self.resize(1400, 900)
		self.setMinimumSize(1180, 760)
		self.stack = QStackedWidget()
		self.landing_page = LandingPage(self.show_login_page)
		self.login_page = LoginPage(self.auth_service, self.handle_login_success)
		self.dashboard_shell = DashboardShell(self)
		self.stack.addWidget(self.landing_page)
		self.stack.addWidget(self.login_page)
		self.stack.addWidget(self.dashboard_shell)
		self.setCentralWidget(self.stack)
		self.stack.setCurrentWidget(self.landing_page)
		self.statusBar().showMessage("Initializing")
		self.tray_icon = QSystemTrayIcon(self._create_window_icon(), self)
		self.tray_icon.setToolTip(APP_NAME)
		tray_menu = self.menuBar().addMenu("Tray")
		show_action = QAction("Show", self)
		show_action.triggered.connect(self.showNormal)
		exit_action = QAction("Exit", self)
		exit_action.triggered.connect(self.close)
		tray_menu.addAction(show_action)
		tray_menu.addAction(exit_action)
		self.tray_icon.setContextMenu(tray_menu)
		self.tray_icon.show()

	def _create_window_icon(self) -> QIcon:
		pixmap = QPixmap(64, 64)
		pixmap.fill(QColor("transparent"))
		painter = QPainter(pixmap)
		painter.setRenderHint(QPainter.RenderHint.Antialiasing)
		painter.setBrush(QColor("#00e5ff"))
		painter.setPen(Qt.PenStyle.NoPen)
		painter.drawEllipse(8, 8, 48, 48)
		painter.setBrush(QColor("#0a1228"))
		painter.drawEllipse(18, 18, 28, 28)
		painter.end()
		return QIcon(pixmap)

	def _connect_events(self) -> None:
		self.event_bus.alert.connect(self.on_alert)
		self.event_bus.log.connect(self.on_log)
		self.event_bus.threat_detected.connect(self.on_threat)
		self.event_bus.phishing_detected.connect(self.on_phishing)
		self.event_bus.auth_event.connect(self.on_auth)
		self.event_bus.metrics_updated.connect(self.on_metrics)

	def show_login_page(self) -> None:
		self.stack.setCurrentWidget(self.login_page)
		self.statusBar().showMessage("Welcome — please sign in")

	def handle_login_success(self, username: str) -> None:
		snapshot = get_system_snapshot()
		self.database.log_device(snapshot.hostname, snapshot.ip_address, "trusted", f"Logged in as {username}")
		self.stack.setCurrentWidget(self.dashboard_shell)
		self.statusBar().showMessage(f"Welcome {username}")
		self.refresh_all()

	def switch_page(self, page_key: str) -> None:
		self.dashboard_shell.switch_page(page_key)

	def refresh_all(self) -> None:
		self.dashboard_shell.home_page.refresh()
		self.dashboard_shell.reports_page.refresh()
		self.refresh_devices()

	def refresh_devices(self) -> None:
		rows = self.database.fetch_all("SELECT created_at, device_name, ip_address, status, details FROM device_logs ORDER BY id DESC LIMIT 200")
		self.dashboard_shell.device_page.set_rows([tuple(row) for row in rows])

	def on_sample_ready(self, payload: dict[str, object]) -> None:
		self.dashboard_shell.monitoring_page.update_sample(payload)
		self.on_log({"module": "monitoring", "severity": payload.get("severity", "low"), "message": "Live sample received"})

	def on_alert(self, payload: dict[str, object]) -> None:
		title = str(payload.get("title", "Alert"))
		message = str(payload.get("message", ""))
		severity = str(payload.get("severity", "info"))
		self.tray_icon.showMessage(title, message, self.tray_icon.icon(), 4500)
		self.statusBar().showMessage(f"{severity.upper()}: {message}")

	def on_log(self, payload: dict[str, object]) -> None:
		timestamp = datetime.now().strftime("%H:%M:%S")
		module = str(payload.get("module", "system"))
		severity = str(payload.get("severity", "info"))
		message = str(payload.get("message", payload.get("description", "event")))
		self.dashboard_shell.logs_page.set_rows([(timestamp, module, severity, message)])
		self.dashboard_shell.home_page.terminal.append_line(f"[{timestamp}] {module.upper()} | {severity.upper()} | {message}")

	def on_threat(self, payload: dict[str, object]) -> None:
		timestamp = datetime.now().strftime("%H:%M:%S")
		self.dashboard_shell.analytics_page.set_rows([(timestamp, str(payload.get("module", "monitoring")), str(payload.get("severity", "high")), "Threat score updated")])

	def on_phishing(self, payload: dict[str, object]) -> None:
		timestamp = datetime.now().strftime("%H:%M:%S")
		self.dashboard_shell.analytics_page.set_rows([(timestamp, "phishing", str(payload.get("risk", "medium")), str(payload.get("prediction", "safe")))])
		prediction = str(payload.get("prediction", "safe")).title()
		risk = str(payload.get("risk", "low")).title()
		confidence = float(payload.get("confidence", 0.0))
		self.statusBar().showMessage(f"Phishing scan: {prediction} | {risk} | {(confidence * 100):.1f}%")

	def on_auth(self, payload: dict[str, object]) -> None:
		timestamp = datetime.now().strftime("%H:%M:%S")
		self.dashboard_shell.device_page.set_rows([(timestamp, str(payload.get("username", "user")), str(payload.get("ip_address", "")), str(payload.get("status", "login")), str(payload.get("message", "auth event")))])

	def on_metrics(self, payload: dict[str, object]) -> None:
		self.dashboard_shell.monitoring_page.update_sample(payload)

	def open_standalone_phishing(self) -> None:
		from phishing_detection.app import launch_phishing_app

		launch_phishing_app()

	def closeEvent(self, event) -> None:  # noqa: N802
		self.monitoring_service.stop()
		self.monitoring_service.wait(2000)
		super().closeEvent(event)


