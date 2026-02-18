"""
Main application window.
Implements the Nessus-like workflow:
  Scan Profiles -> Credentials -> Targets -> Run -> Results -> Reports
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QHBoxLayout, QLabel, QMainWindow,
    QMessageBox, QStatusBar, QTabWidget, QVBoxLayout, QWidget,
)

from .. import __app_name__, __version__
from ..core.config import AppSettings, get_exports_dir
from ..core.credentials import CredentialManager
from ..core.database import Database
from ..core.models import ScanProfile
from ..core.scan_engine import ScanEngine
from ..reporting.exporter import ReportExporter
from ..topology.graph_builder import TopologyBuilder
from .auth_dialog import AuthorizationDialog
from .styles import DARK_STYLESHEET
from .widgets.credentials_widget import CredentialsWidget
from .widgets.profile_widget import ProfileWidget
from .widgets.results_widget import ResultsWidget
from .widgets.scan_runner_widget import ScanRunnerWidget
from .widgets.topology_widget import TopologyWidget

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.settings = AppSettings()
        self.db = Database()
        self.cred_manager = CredentialManager()

        self.setWindowTitle(f"{__app_name__} v{__version__}")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        self._setup_ui()
        self._setup_menu()
        self._setup_statusbar()

        # Check authorization
        if not self.settings.is_authorized:
            self._show_auth_dialog()

    def _show_auth_dialog(self) -> None:
        """Show the authorization gate dialog."""
        def on_accept(name: str):
            self.settings.accept_authorization(name)
            self.statusbar.showMessage(f"Authorized by: {name}")

        dlg = AuthorizationDialog(on_accept, self)
        result = dlg.exec()
        if result != dlg.DialogCode.Accepted:
            QApplication.quit()

    def _setup_ui(self) -> None:
        """Set up the main UI layout."""
        self.setStyleSheet(DARK_STYLESHEET)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # Main tab widget
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Tab 1: Scan Profiles
        self.profile_widget = ProfileWidget(self.db, self)
        self.profile_widget.start_scan_requested.connect(self._on_start_scan)
        self.tabs.addTab(self.profile_widget, "Scan Profiles")

        # Tab 2: Credentials
        self.creds_widget = CredentialsWidget(self.db, self.cred_manager, self)
        self.tabs.addTab(self.creds_widget, "Credentials")

        # Tab 3: Scan Runner
        self.runner_widget = ScanRunnerWidget(self)
        self.runner_widget.scan_completed.connect(self._on_scan_completed)
        self.tabs.addTab(self.runner_widget, "Scan Progress")

        # Tab 4: Results
        self.results_widget = ResultsWidget(self.db, self)
        self.tabs.addTab(self.results_widget, "Results")

        # Tab 5: Topology
        self.topology_widget = TopologyWidget(self)
        self.tabs.addTab(self.topology_widget, "Topology")

        # Tab 6: History
        self.history_widget = self._build_history_widget()
        self.tabs.addTab(self.history_widget, "History")

        layout.addWidget(self.tabs)

    def _setup_menu(self) -> None:
        """Set up the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        export_action = QAction("Export Results...", self)
        export_action.triggered.connect(self._on_export)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Scan menu
        scan_menu = menubar.addMenu("Scan")

        new_scan = QAction("New Scan...", self)
        new_scan.triggered.connect(lambda: self.tabs.setCurrentIndex(0))
        scan_menu.addAction(new_scan)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_statusbar(self) -> None:
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage("Ready")

    def _build_history_widget(self) -> QWidget:
        """Build the scan history tab."""
        from PySide6.QtWidgets import (
            QTableWidget, QTableWidgetItem, QHeaderView,
        )

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("Scan History"))

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Profile", "Scanner", "Start", "End", "Status", "Devices",
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.history_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.history_table.cellDoubleClicked.connect(self._on_history_double_click)
        layout.addWidget(self.history_table)

        # Load history button
        from PySide6.QtWidgets import QPushButton
        btn_row = QHBoxLayout()
        btn_refresh = QPushButton("Refresh")
        btn_refresh.clicked.connect(self._refresh_history)
        btn_load = QPushButton("Load Selected Session")
        btn_load.clicked.connect(self._load_selected_session)
        btn_row.addWidget(btn_refresh)
        btn_row.addWidget(btn_load)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._refresh_history()
        return widget

    def _refresh_history(self) -> None:
        """Refresh the scan history table."""
        from PySide6.QtWidgets import QTableWidgetItem
        sessions = self.db.get_scan_sessions()
        self.history_table.setRowCount(len(sessions))
        for row, session in enumerate(sessions):
            self.history_table.setItem(row, 0, QTableWidgetItem(
                session.get("profile_name", "")))
            self.history_table.setItem(row, 1, QTableWidgetItem(
                session.get("scanner_host", "")))
            self.history_table.setItem(row, 2, QTableWidgetItem(
                session.get("start_time", "")[:19]))
            self.history_table.setItem(row, 3, QTableWidgetItem(
                session.get("end_time", "")[:19] if session.get("end_time") else ""))
            self.history_table.setItem(row, 4, QTableWidgetItem(
                session.get("status", "")))

            # Get device count from summary
            summary_json = session.get("summary_json", "{}")
            try:
                summary = json.loads(summary_json) if summary_json else {}
                total = summary.get("totals", {}).get("total_devices", 0)
            except Exception:
                total = 0
            self.history_table.setItem(row, 5, QTableWidgetItem(str(total)))

            # Store session_id
            self.history_table.item(row, 0).setData(
                Qt.ItemDataRole.UserRole, session.get("id", "")
            )

    def _on_history_double_click(self, row: int, _col: int) -> None:
        self._load_session_by_row(row)

    def _load_selected_session(self) -> None:
        row = self.history_table.currentRow()
        if row >= 0:
            self._load_session_by_row(row)

    def _load_session_by_row(self, row: int) -> None:
        item = self.history_table.item(row, 0)
        if item:
            session_id = item.data(Qt.ItemDataRole.UserRole)
            if session_id:
                self.results_widget.load_session(session_id)
                self.tabs.setCurrentIndex(3)  # Results tab
                self._current_session_id = session_id
                self.statusbar.showMessage(f"Loaded session: {session_id[:8]}...")

                # Try to load topology
                self._load_topology(session_id)

    def _on_start_scan(self, profile_dict: dict) -> None:
        """Handle scan start request from profile widget."""
        # Build ScanProfile from dict
        profile = ScanProfile()
        for key, value in profile_dict.items():
            if hasattr(profile, key):
                setattr(profile, key, value)

        # Get resolved credentials
        credentials = self.creds_widget.get_resolved_credentials()

        # Create scan engine
        engine = ScanEngine(
            profile=profile,
            db=self.db,
            credentials=credentials,
        )

        # Switch to scan runner tab and start
        self.tabs.setCurrentIndex(2)
        self.runner_widget.start_scan(engine)
        self.statusbar.showMessage(f"Scan started: {profile.name}")

    def _on_scan_completed(self, session_id: str) -> None:
        """Handle scan completion."""
        self._current_session_id = session_id
        self.results_widget.load_session(session_id)
        self._refresh_history()

        # Build topology
        self._load_topology(session_id)

        self.statusbar.showMessage(f"Scan complete: {session_id[:8]}...")
        QMessageBox.information(
            self, "Scan Complete",
            f"Scan finished successfully.\n"
            f"Switch to the Results tab to view discovered devices.",
        )

    def _load_topology(self, session_id: str) -> None:
        """Build and load topology for a scan session."""
        try:
            session = self.db.get_scan_session(session_id)
            if not session:
                return

            summary_json = session.get("summary_json", "{}")
            summary = json.loads(summary_json) if summary_json else {}

            devices_data = self.db.get_devices(session_id)
            if not devices_data:
                return

            # Build device records for topology
            from ..core.models import DeviceRecord
            devices = {}
            for dev in devices_data:
                full_json = dev.get("full_json", "{}")
                try:
                    full = json.loads(full_json) if full_json else {}
                except Exception:
                    continue

                record = DeviceRecord()
                record.ip_address.value = dev.get("ip_address", "")
                record.hostname.value = dev.get("hostname", "")
                record.mac_address.value = dev.get("mac_address", "")
                record.vendor.value = dev.get("vendor", "")
                record.snmp_sys_descr = full.get("snmp_sys_descr", "")
                record.snmp_sys_name = full.get("snmp_sys_name", "")

                from ..core.models import DeviceRole
                role_str = dev.get("device_role", "unknown")
                try:
                    record.device_role.value = DeviceRole(role_str)
                except ValueError:
                    record.device_role.value = DeviceRole.UNKNOWN

                record.lldp_neighbors = full.get("lldp_neighbors", []) if isinstance(full.get("lldp_neighbors"), list) else []
                record.cdp_neighbors = full.get("cdp_neighbors", []) if isinstance(full.get("cdp_neighbors"), list) else []

                sp = full.get("switch_port")
                if sp and isinstance(sp, dict):
                    from ..core.models import SwitchPortMapping
                    record.switch_port = SwitchPortMapping(
                        switch_ip=sp.get("switch_ip", ""),
                        switch_name=sp.get("switch_name", ""),
                        port_name=sp.get("port_name", ""),
                    )

                devices[dev.get("ip_address", "")] = record

            # Extract gateways
            gateways = [g.get("ip", "") for g in summary.get("gateways", [])]

            builder = TopologyBuilder()
            graph = builder.build_from_devices(devices, gateways)

            topo_json = builder.export_json_graph()
            self.topology_widget.load_topology(topo_json)
            self._topology_builder = builder

        except Exception as e:
            logger.warning("Failed to build topology: %s", e)

    def _on_export(self) -> None:
        """Export scan results."""
        session_id = getattr(self, "_current_session_id", "")
        if not session_id:
            QMessageBox.warning(self, "No Data",
                                "No scan session loaded. Run a scan or load from history.")
            return

        out_dir = QFileDialog.getExistingDirectory(
            self, "Select Export Directory",
            str(get_exports_dir()),
        )
        if not out_dir:
            return

        try:
            session = self.db.get_scan_session(session_id)
            summary_json = session.get("summary_json", "{}") if session else "{}"
            summary = json.loads(summary_json) if summary_json else {}

            devices = self.db.get_devices(session_id)
            device_dicts = []
            flat_dicts = []
            for dev in devices:
                try:
                    full = json.loads(dev.get("full_json", "{}"))
                    device_dicts.append(full)
                except Exception:
                    pass
                flat_dicts.append({
                    "ip_address": dev.get("ip_address", ""),
                    "hostname": dev.get("hostname", ""),
                    "mac_address": dev.get("mac_address", ""),
                    "vendor": dev.get("vendor", ""),
                    "device_role": dev.get("device_role", ""),
                    "os_hint": dev.get("os_hint", ""),
                    "ip_assignment": dev.get("ip_assignment", ""),
                    "domain": dev.get("domain", ""),
                    "overall_confidence": dev.get("overall_confidence", 0),
                })

            topo_graphml = ""
            topo_json = ""
            builder = getattr(self, "_topology_builder", None)
            if builder:
                topo_graphml = builder.export_graphml()
                topo_json = builder.export_json_graph()

            exporter = ReportExporter(
                session_id=session_id,
                devices=device_dicts,
                infra_summary=summary,
                topology_graphml=topo_graphml,
                topology_json=topo_json,
                flat_devices=flat_dicts,
            )
            results = exporter.export_all(Path(out_dir))

            files = [f for f in results.values() if f]
            QMessageBox.information(
                self, "Export Complete",
                f"Exported {len(files)} files to:\n{out_dir}",
            )

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))
            logger.exception("Export failed")

    def _show_about(self) -> None:
        QMessageBox.about(
            self, f"About {__app_name__}",
            f"<h2>{__app_name__} v{__version__}</h2>"
            f"<p>Network Technician Scanner & Mapper</p>"
            f"<p>A portable, GUI-based tool for producing high-fidelity "
            f"network inventory and topology maps.</p>"
            f"<p><b>AUTHORIZED USE ONLY</b></p>"
            f"<p>Built with Python + PySide6 (Qt)</p>"
        )
