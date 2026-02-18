"""
Scan runner widget.
Shows real-time scan progress with phase tracking, log output,
and cancel capability. Runs the scan engine in a background thread.
"""

from __future__ import annotations

import asyncio
import traceback
from typing import Optional

from PySide6.QtCore import Qt, Signal, QThread, QObject
from PySide6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QPlainTextEdit, QProgressBar,
    QPushButton, QVBoxLayout, QWidget,
)


class ScanWorkerSignals(QObject):
    """Signals from the scan worker thread."""
    progress = Signal(str, int, int, str)  # phase, current, total, detail
    log_message = Signal(str)
    finished = Signal(str)  # session_id
    error = Signal(str)


class ScanWorker(QThread):
    """Background thread for running the scan engine."""

    def __init__(self, scan_engine):
        super().__init__()
        self.scan_engine = scan_engine
        self.signals = ScanWorkerSignals()

        # Wire callbacks
        self.scan_engine._progress = self._on_progress
        self.scan_engine._log = self._on_log

    def _on_progress(self, phase, current, total, detail):
        self.signals.progress.emit(phase, current, total, detail)

    def _on_log(self, msg):
        self.signals.log_message.emit(msg)

    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            session_id = loop.run_until_complete(self.scan_engine.run())
            loop.close()
            self.signals.finished.emit(session_id)
        except Exception as e:
            self.signals.error.emit(f"{e}\n{traceback.format_exc()}")


class ScanRunnerWidget(QWidget):
    """Real-time scan progress and control."""

    scan_completed = Signal(str)  # session_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[ScanWorker] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Status header
        header = QHBoxLayout()
        self.status_label = QLabel("Ready to scan")
        self.status_label.setObjectName("titleLabel")
        header.addWidget(self.status_label)
        header.addStretch()

        self.btn_cancel = QPushButton("Cancel Scan")
        self.btn_cancel.setObjectName("dangerBtn")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_scan)
        header.addWidget(self.btn_cancel)
        layout.addLayout(header)

        # Phase progress
        phase_group = QGroupBox("Scan Progress")
        phase_layout = QVBoxLayout()

        self.phase_label = QLabel("Phase: Idle")
        self.phase_label.setStyleSheet("font-size: 14px; color: #3498db;")
        phase_layout.addWidget(self.phase_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        phase_layout.addWidget(self.progress_bar)

        self.detail_label = QLabel("")
        self.detail_label.setStyleSheet("color: #8888aa;")
        phase_layout.addWidget(self.detail_label)

        phase_group.setLayout(phase_layout)
        layout.addWidget(phase_group)

        # Phase summary grid
        self.phase_indicators = {}
        phases = [
            "Local Context", "DHCP Discovery", "Target Enumeration",
            "Windows Infrastructure", "ARP Collection", "Ping Sweep",
            "Port Scan", "DNS Resolution", "SNMP Collection", "Finalizing",
        ]
        phase_grid = QHBoxLayout()
        for phase in phases:
            indicator = QLabel(f"  {phase}  ")
            indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
            indicator.setStyleSheet(
                "background-color: #2a2a4a; border-radius: 3px; padding: 4px; "
                "font-size: 10px; color: #666;"
            )
            phase_grid.addWidget(indicator)
            self.phase_indicators[phase] = indicator
        layout.addLayout(phase_grid)

        # Log output
        log_group = QGroupBox("Scan Log")
        log_layout = QVBoxLayout()
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(5000)
        self.log_text.setStyleSheet(
            "font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 11px;"
        )
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group, 1)

    def start_scan(self, scan_engine):
        """Start a scan with the given engine."""
        self._worker = ScanWorker(scan_engine)
        self._worker.signals.progress.connect(self._on_progress)
        self._worker.signals.log_message.connect(self._on_log)
        self._worker.signals.finished.connect(self._on_finished)
        self._worker.signals.error.connect(self._on_error)

        self.status_label.setText("Scanning...")
        self.btn_cancel.setEnabled(True)
        self.log_text.clear()
        self.progress_bar.setValue(0)

        # Reset phase indicators
        for indicator in self.phase_indicators.values():
            indicator.setStyleSheet(
                "background-color: #2a2a4a; border-radius: 3px; padding: 4px; "
                "font-size: 10px; color: #666;"
            )

        self._worker.start()

    def _cancel_scan(self):
        if self._worker and self._worker.scan_engine:
            self._worker.scan_engine.cancel()
            self.status_label.setText("Cancelling...")
            self.btn_cancel.setEnabled(False)

    def _on_progress(self, phase: str, current: int, total: int, detail: str):
        self.phase_label.setText(f"Phase: {phase}")
        if total > 0:
            pct = int(current / total * 100)
            self.progress_bar.setValue(pct)
            self.progress_bar.setFormat(f"{phase}: {current}/{total} ({pct}%)")
        self.detail_label.setText(detail)

        # Update phase indicator
        if phase in self.phase_indicators:
            if current >= total and total > 0:
                self.phase_indicators[phase].setStyleSheet(
                    "background-color: #2ecc71; border-radius: 3px; padding: 4px; "
                    "font-size: 10px; color: white;"
                )
            else:
                self.phase_indicators[phase].setStyleSheet(
                    "background-color: #3498db; border-radius: 3px; padding: 4px; "
                    "font-size: 10px; color: white;"
                )

    def _on_log(self, msg: str):
        self.log_text.appendPlainText(msg)

    def _on_finished(self, session_id: str):
        self.status_label.setText("Scan Complete")
        self.status_label.setStyleSheet("color: #2ecc71; font-size: 18px; font-weight: bold;")
        self.btn_cancel.setEnabled(False)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("Complete")
        self.scan_completed.emit(session_id)

    def _on_error(self, error_msg: str):
        self.status_label.setText("Scan Error")
        self.status_label.setStyleSheet("color: #e74c3c; font-size: 18px; font-weight: bold;")
        self.btn_cancel.setEnabled(False)
        self.log_text.appendPlainText(f"\nERROR: {error_msg}")
