"""
Scan results viewer widget.
Shows device inventory in a sortable/filterable table with
an evidence detail panel for each device.
"""

from __future__ import annotations

import json
from typing import Optional

from PySide6.QtCore import Qt, Signal, QSortFilterProxyModel
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QComboBox, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QSplitter, QTableView, QTextEdit, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)


ROLE_COLORS = {
    "router": "#e74c3c",
    "firewall": "#c0392b",
    "switch": "#2980b9",
    "access_point": "#27ae60",
    "server": "#8e44ad",
    "domain_controller": "#d35400",
    "dhcp_server": "#16a085",
    "dns_server": "#2c3e50",
    "printer": "#7f8c8d",
    "camera": "#16a085",
    "nvr": "#1abc9c",
    "voip_phone": "#f39c12",
    "endpoint": "#34495e",
    "iot": "#e67e22",
    "nas": "#2ecc71",
    "unknown": "#555555",
}


class ResultsWidget(QWidget):
    """Device inventory results viewer."""

    device_selected = Signal(str)  # device_id

    def __init__(self, db, parent=None):
        super().__init__(parent)
        self.db = db
        self._current_session = ""
        self._devices_full: dict[str, dict] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Filter bar
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter by IP, hostname, vendor, MAC...")
        self.search_box.textChanged.connect(self._apply_filter)
        filter_row.addWidget(self.search_box, 1)

        filter_row.addWidget(QLabel("Role:"))
        self.role_filter = QComboBox()
        self.role_filter.addItem("All Roles", "")
        for role in sorted(ROLE_COLORS.keys()):
            self.role_filter.addItem(role.replace("_", " ").title(), role)
        self.role_filter.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self.role_filter)

        filter_row.addWidget(QLabel("Alive:"))
        self.alive_filter = QComboBox()
        self.alive_filter.addItems(["All", "Alive Only", "Dead Only"])
        self.alive_filter.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self.alive_filter)

        self.count_label = QLabel("0 devices")
        self.count_label.setStyleSheet("color: #3498db; font-weight: bold;")
        filter_row.addWidget(self.count_label)

        layout.addLayout(filter_row)

        # Splitter: table + detail panel
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Device table
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels([
            "IP Address", "Hostname", "MAC Address", "Vendor",
            "Role", "OS Hint", "Assignment", "Open Ports",
            "Switch Port", "Confidence",
        ])

        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)  # Search all columns

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.verticalHeader().setVisible(False)
        self.table.selectionModel().selectionChanged.connect(self._on_row_selected)

        splitter.addWidget(self.table)

        # Detail panel
        detail_widget = QWidget()
        detail_layout = QHBoxLayout(detail_widget)

        # Evidence tree
        evidence_group = QGroupBox("Evidence / Data Sources")
        ev_layout = QVBoxLayout()
        self.evidence_tree = QTreeWidget()
        self.evidence_tree.setHeaderLabels(["Field", "Value", "Source", "Confidence"])
        self.evidence_tree.setAlternatingRowColors(True)
        ev_layout.addWidget(self.evidence_tree)
        evidence_group.setLayout(ev_layout)
        detail_layout.addWidget(evidence_group, 1)

        # Ports & Services
        ports_group = QGroupBox("Ports & Services")
        ports_layout = QVBoxLayout()
        self.ports_text = QTextEdit()
        self.ports_text.setReadOnly(True)
        self.ports_text.setMaximumHeight(200)
        ports_layout.addWidget(self.ports_text)
        ports_group.setLayout(ports_layout)
        detail_layout.addWidget(ports_group, 1)

        splitter.addWidget(detail_widget)
        splitter.setSizes([400, 200])

        layout.addWidget(splitter)

    def load_session(self, session_id: str):
        """Load results for a scan session."""
        self._current_session = session_id
        self.model.removeRows(0, self.model.rowCount())
        self._devices_full.clear()

        devices = self.db.get_devices(session_id)
        for dev in devices:
            dev_id = dev.get("id", "")
            full = self.db.get_device_full(dev_id)
            if full:
                self._devices_full[dev_id] = full
            self._add_device_row(dev)

        # Auto-resize columns
        for i in range(self.model.columnCount()):
            self.table.resizeColumnToContents(i)

        self.count_label.setText(f"{len(devices)} devices")

    def _add_device_row(self, dev: dict):
        """Add a device row to the table."""
        role = dev.get("device_role", "unknown")
        color = QColor(ROLE_COLORS.get(role, "#555555"))

        items = [
            self._make_item(dev.get("ip_address", "")),
            self._make_item(dev.get("hostname", "")),
            self._make_item(dev.get("mac_address", "")),
            self._make_item(dev.get("vendor", "")),
            self._make_item(role.replace("_", " ").title(), color),
            self._make_item(dev.get("os_hint", "")[:50]),
            self._make_item(dev.get("ip_assignment", "")),
            self._make_item(self._format_ports(dev)),
            self._make_item(self._format_switch_port(dev)),
            self._make_item(f"{dev.get('overall_confidence', 0):.2f}"),
        ]

        # Store device ID in first item
        items[0].setData(dev.get("id", ""), Qt.ItemDataRole.UserRole)
        self.model.appendRow(items)

    def _make_item(self, text: str, color: QColor = None) -> QStandardItem:
        item = QStandardItem(str(text))
        item.setEditable(False)
        if color:
            item.setForeground(color)
        return item

    def _format_ports(self, dev: dict) -> str:
        try:
            ports_json = dev.get("open_ports_json", "[]")
            ports = json.loads(ports_json) if isinstance(ports_json, str) else ports_json
            return "; ".join(
                f"{p.get('port', '')}/{p.get('protocol', '')}({p.get('service', '')})"
                for p in ports[:10]
            )
        except Exception:
            return ""

    def _format_switch_port(self, dev: dict) -> str:
        try:
            sp = dev.get("switch_port_json", "null")
            if isinstance(sp, str):
                sp = json.loads(sp)
            if sp and isinstance(sp, dict):
                return f"{sp.get('switch_name', '')}:{sp.get('port_name', '')}"
        except Exception:
            pass
        return ""

    def _on_row_selected(self, selected, _deselected):
        indexes = selected.indexes()
        if not indexes:
            return
        source_index = self.proxy.mapToSource(indexes[0])
        item = self.model.item(source_index.row(), 0)
        if not item:
            return
        dev_id = item.data(Qt.ItemDataRole.UserRole)
        if dev_id and dev_id in self._devices_full:
            self._show_device_detail(self._devices_full[dev_id])
            self.device_selected.emit(dev_id)

    def _show_device_detail(self, full: dict):
        """Show evidence detail for a device."""
        self.evidence_tree.clear()

        tracked_fields = [
            ("IP Address", "ip_address"),
            ("MAC Address", "mac_address"),
            ("Vendor", "vendor"),
            ("Hostname", "hostname"),
            ("DNS Name", "dns_name"),
            ("NetBIOS Name", "netbios_name"),
            ("OS Hint", "os_hint"),
            ("Device Role", "device_role"),
            ("IP Assignment", "ip_assignment"),
            ("Is Alive", "is_alive"),
            ("Domain", "domain"),
        ]

        for label, key in tracked_fields:
            field_data = full.get(key, {})
            if not isinstance(field_data, dict):
                field_data = {"value": field_data, "sources": [], "confidence": ""}

            value = str(field_data.get("value", ""))
            sources = field_data.get("sources", [])
            confidence = field_data.get("confidence", "")
            evidence = field_data.get("evidence", [])

            parent = QTreeWidgetItem([label, value,
                                      ", ".join(sources), confidence])
            self.evidence_tree.addTopLevelItem(parent)

            for ev in evidence:
                child = QTreeWidgetItem(["", ev, "", ""])
                parent.addChild(child)

        self.evidence_tree.expandAll()
        for i in range(4):
            self.evidence_tree.resizeColumnToContents(i)

        # Show ports
        ports = full.get("open_ports", [])
        port_text = ""
        for p in ports:
            line = f"  {p.get('port', '')}/{p.get('protocol', 'tcp')} - {p.get('service', '')}"
            if p.get("banner"):
                line += f"\n    Banner: {p['banner'][:100]}"
            if p.get("version"):
                line += f" ({p['version']})"
            port_text += line + "\n"
        self.ports_text.setPlainText(port_text or "No open ports found")

    def _apply_filter(self):
        search = self.search_box.text()
        role = self.role_filter.currentData()
        alive_idx = self.alive_filter.currentIndex()

        # Text filter
        self.proxy.setFilterFixedString(search)

        # Count visible
        visible = 0
        for row in range(self.proxy.rowCount()):
            visible += 1
        self.count_label.setText(f"{visible} devices shown")
