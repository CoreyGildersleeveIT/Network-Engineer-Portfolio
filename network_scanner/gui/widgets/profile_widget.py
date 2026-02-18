"""
Scan Profile management widget -- Nessus-like workflow.

Left panel  : saved-profile list with New / Edit / Delete / Clone buttons
Right panel : scrollable profile editor (basic info, targets, intensity,
              tuning, options, SNMP settings, port selection)

Signals
-------
profile_selected(dict)     -- emitted when user selects a profile for scanning
start_scan_requested(dict) -- emitted when user clicks "Start Scan"
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QSpinBox,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...core.database import Database
from ...core.models import ScanProfile


# ---------------------------------------------------------------------------
# Helper: create a linked slider + spinbox pair
# ---------------------------------------------------------------------------

def _make_slider_spin(
    minimum: int,
    maximum: int,
    default: int,
    step: int = 1,
) -> tuple[QSlider, QSpinBox]:
    """Return a horizontal slider and spinbox that stay in sync."""
    slider = QSlider(Qt.Orientation.Horizontal)
    slider.setRange(minimum, maximum)
    slider.setValue(default)
    slider.setSingleStep(step)

    spin = QSpinBox()
    spin.setRange(minimum, maximum)
    spin.setValue(default)
    spin.setSingleStep(step)

    # Keep in sync
    slider.valueChanged.connect(spin.setValue)
    spin.valueChanged.connect(slider.setValue)

    return slider, spin


# ---------------------------------------------------------------------------
# Main widget
# ---------------------------------------------------------------------------

class ProfileWidget(QWidget):
    """Scan-profile management widget with a Nessus-like two-panel layout."""

    # Signals ---------------------------------------------------------------
    profile_selected = Signal(dict)
    start_scan_requested = Signal(dict)

    # -----------------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------------

    def __init__(self, database: Database, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._db = database

        # In-memory profile list (dicts matching ScanProfile.to_dict())
        self._profiles: list[dict] = []
        # The profile dict currently loaded into the editor (or None)
        self._current_profile: Optional[dict] = None
        # True while we are programmatically loading values into the editor
        self._loading = False

        self._build_ui()
        self._connect_signals()
        self.refresh_profile_list()

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self) -> None:
        root_layout = QHBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        root_layout.addWidget(splitter)

        # --- Left panel: profile list + action buttons ---------------------
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(6, 6, 6, 6)

        list_label = QLabel("Scan Profiles")
        list_label.setObjectName("titleLabel")
        left_layout.addWidget(list_label)

        self._profile_list = QListWidget()
        self._profile_list.setAlternatingRowColors(True)
        left_layout.addWidget(self._profile_list)

        btn_row = QHBoxLayout()

        self._btn_new = QPushButton("New")
        self._btn_edit = QPushButton("Edit")
        self._btn_edit.setObjectName("secondaryBtn")
        self._btn_clone = QPushButton("Clone")
        self._btn_clone.setObjectName("secondaryBtn")
        self._btn_delete = QPushButton("Delete")
        self._btn_delete.setObjectName("dangerBtn")

        for btn in (self._btn_new, self._btn_edit, self._btn_clone, self._btn_delete):
            btn_row.addWidget(btn)

        left_layout.addLayout(btn_row)
        left_panel.setMaximumWidth(280)

        splitter.addWidget(left_panel)

        # --- Right panel: profile editor inside a scroll area --------------
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._editor = QWidget()
        self._editor_layout = QVBoxLayout(self._editor)
        self._editor_layout.setContentsMargins(10, 10, 10, 10)
        self._editor_layout.setSpacing(12)

        self._build_basic_info_group()
        self._build_target_group()
        self._build_intensity_group()
        self._build_tuning_group()
        self._build_options_group()
        self._build_snmp_group()
        self._build_ports_group()

        # Bottom action buttons
        action_row = QHBoxLayout()
        self._btn_save = QPushButton("Save Profile")
        self._btn_save.setObjectName("successBtn")
        self._btn_start = QPushButton("Start Scan")
        self._btn_start.setMinimumHeight(38)
        action_row.addStretch()
        action_row.addWidget(self._btn_save)
        action_row.addWidget(self._btn_start)
        self._editor_layout.addLayout(action_row)

        self._editor_layout.addStretch()

        scroll.setWidget(self._editor)
        splitter.addWidget(scroll)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        # Disable editor until a profile is loaded
        self._set_editor_enabled(False)

    # -- Basic Info ---------------------------------------------------------

    def _build_basic_info_group(self) -> None:
        group = QGroupBox("Basic Info")
        form = QFormLayout(group)

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("Profile name")
        form.addRow("Name:", self._name_edit)

        self._desc_edit = QLineEdit()
        self._desc_edit.setPlaceholderText("Optional description")
        form.addRow("Description:", self._desc_edit)

        self._editor_layout.addWidget(group)

    # -- Target Selection ---------------------------------------------------

    def _build_target_group(self) -> None:
        group = QGroupBox("Target Selection")
        layout = QVBoxLayout(group)

        self._target_btn_group = QButtonGroup(self)
        self._radio_auto = QRadioButton("Auto-discover from local NICs")
        self._radio_dhcp = QRadioButton("Pull DHCP scopes (if available)")
        self._radio_manual = QRadioButton("Manual CIDR entry")
        self._radio_auto.setChecked(True)

        self._target_btn_group.addButton(self._radio_auto, 0)
        self._target_btn_group.addButton(self._radio_dhcp, 1)
        self._target_btn_group.addButton(self._radio_manual, 2)

        layout.addWidget(self._radio_auto)
        layout.addWidget(self._radio_dhcp)
        layout.addWidget(self._radio_manual)

        # Manual CIDRs
        self._cidr_label = QLabel("CIDRs (one per line):")
        self._cidr_edit = QTextEdit()
        self._cidr_edit.setPlaceholderText("e.g.  10.0.0.0/24\n       192.168.1.0/24")
        self._cidr_edit.setMaximumHeight(100)
        layout.addWidget(self._cidr_label)
        layout.addWidget(self._cidr_edit)

        # Exclude CIDRs
        self._exclude_label = QLabel("Exclude CIDRs (one per line):")
        self._exclude_edit = QTextEdit()
        self._exclude_edit.setPlaceholderText("e.g.  10.0.0.0/30")
        self._exclude_edit.setMaximumHeight(80)
        layout.addWidget(self._exclude_label)
        layout.addWidget(self._exclude_edit)

        self._chk_skip_high_risk = QCheckBox("Skip high-risk ranges")
        self._chk_skip_high_risk.setChecked(True)
        layout.addWidget(self._chk_skip_high_risk)

        self._editor_layout.addWidget(group)

        # Initial visibility
        self._update_target_mode_ui()

    # -- Scan Intensity -----------------------------------------------------

    def _build_intensity_group(self) -> None:
        group = QGroupBox("Scan Intensity")
        form = QFormLayout(group)

        self._intensity_combo = QComboBox()
        self._intensity_combo.addItem("Quick", "quick")
        self._intensity_combo.addItem("Normal", "normal")
        self._intensity_combo.addItem("Deep After-Hours", "deep_after_hours")
        self._intensity_combo.setCurrentIndex(1)

        form.addRow("Intensity:", self._intensity_combo)
        self._editor_layout.addWidget(group)

    # -- Tuning -------------------------------------------------------------

    def _build_tuning_group(self) -> None:
        group = QGroupBox("Tuning")
        form = QFormLayout(group)

        self._icmp_slider, self._icmp_spin = _make_slider_spin(1, 500, 100)
        form.addRow("ICMP concurrency:", self._make_slider_row(self._icmp_slider, self._icmp_spin))

        self._tcp_slider, self._tcp_spin = _make_slider_spin(1, 200, 50)
        form.addRow("TCP concurrency:", self._make_slider_row(self._tcp_slider, self._tcp_spin))

        self._snmp_slider, self._snmp_spin = _make_slider_spin(1, 100, 20)
        form.addRow("SNMP concurrency:", self._make_slider_row(self._snmp_slider, self._snmp_spin))

        self._timeout_slider, self._timeout_spin = _make_slider_spin(100, 10000, 2000, step=100)
        form.addRow("Timeout (ms):", self._make_slider_row(self._timeout_slider, self._timeout_spin))

        self._retries_slider, self._retries_spin = _make_slider_spin(0, 5, 1)
        form.addRow("Retries:", self._make_slider_row(self._retries_slider, self._retries_spin))

        self._max_errors_slider, self._max_errors_spin = _make_slider_spin(10, 5000, 500, step=10)
        form.addRow("Max errors before stop:", self._make_slider_row(self._max_errors_slider, self._max_errors_spin))

        self._editor_layout.addWidget(group)

    @staticmethod
    def _make_slider_row(slider: QSlider, spin: QSpinBox) -> QWidget:
        """Pack a slider and its spinbox into a single row widget."""
        w = QWidget()
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        slider.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        h.addWidget(slider)
        h.addWidget(spin)
        return w

    # -- Options ------------------------------------------------------------

    def _build_options_group(self) -> None:
        group = QGroupBox("Options")
        layout = QVBoxLayout(group)

        self._chk_scan_only_alive = QCheckBox("Scan only alive IPs")
        self._chk_scan_only_alive.setChecked(True)

        self._chk_ipv6 = QCheckBox("Include IPv6 discovery")
        self._chk_nmap = QCheckBox("Enable nmap integration")
        self._chk_snmp = QCheckBox("Enable SNMP")
        self._chk_zone_enum = QCheckBox("Enable zone enumeration (Deep only)")

        for chk in (
            self._chk_scan_only_alive,
            self._chk_ipv6,
            self._chk_nmap,
            self._chk_snmp,
            self._chk_zone_enum,
        ):
            layout.addWidget(chk)

        self._editor_layout.addWidget(group)

    # -- SNMP Settings ------------------------------------------------------

    def _build_snmp_group(self) -> None:
        self._snmp_group = QGroupBox("SNMP Settings")
        form = QFormLayout(self._snmp_group)

        self._snmp_version_combo = QComboBox()
        self._snmp_version_combo.addItem("v2c", "2c")
        self._snmp_version_combo.addItem("v3", "3")
        form.addRow("SNMP Version:", self._snmp_version_combo)

        self._snmp_group.setVisible(False)
        self._editor_layout.addWidget(self._snmp_group)

    # -- Port Selection -----------------------------------------------------

    def _build_ports_group(self) -> None:
        group = QGroupBox("Port Selection")
        layout = QVBoxLayout(group)

        self._port_btn_group = QButtonGroup(self)
        self._radio_ports_default = QRadioButton("Default")
        self._radio_ports_extended = QRadioButton("Extended")
        self._radio_ports_custom = QRadioButton("Custom")
        self._radio_ports_default.setChecked(True)

        self._port_btn_group.addButton(self._radio_ports_default, 0)
        self._port_btn_group.addButton(self._radio_ports_extended, 1)
        self._port_btn_group.addButton(self._radio_ports_custom, 2)

        layout.addWidget(self._radio_ports_default)
        layout.addWidget(self._radio_ports_extended)
        layout.addWidget(self._radio_ports_custom)

        self._custom_ports_label = QLabel("Custom ports (comma-separated):")
        self._custom_ports_edit = QLineEdit()
        self._custom_ports_edit.setPlaceholderText("e.g. 22,80,443,8080")
        layout.addWidget(self._custom_ports_label)
        layout.addWidget(self._custom_ports_edit)

        self._custom_ports_label.setVisible(False)
        self._custom_ports_edit.setVisible(False)

        self._editor_layout.addWidget(group)

    # -----------------------------------------------------------------------
    # Signal wiring
    # -----------------------------------------------------------------------

    def _connect_signals(self) -> None:
        # Left-panel actions
        self._profile_list.currentRowChanged.connect(self._on_profile_row_changed)
        self._btn_new.clicked.connect(self._on_new)
        self._btn_edit.clicked.connect(self._on_edit)
        self._btn_clone.clicked.connect(self._on_clone)
        self._btn_delete.clicked.connect(self._on_delete)

        # Target-mode radio buttons control CIDR field visibility
        self._target_btn_group.idToggled.connect(self._update_target_mode_ui)

        # SNMP checkbox shows/hides SNMP settings
        self._chk_snmp.toggled.connect(self._snmp_group.setVisible)

        # Port radio buttons control custom port field visibility
        self._port_btn_group.idToggled.connect(self._update_port_mode_ui)

        # Intensity combo -- zone enum only for Deep
        self._intensity_combo.currentIndexChanged.connect(self._update_zone_enum_availability)

        # Bottom buttons
        self._btn_save.clicked.connect(self._on_save)
        self._btn_start.clicked.connect(self._on_start_scan)

    # -----------------------------------------------------------------------
    # UI helpers
    # -----------------------------------------------------------------------

    def _set_editor_enabled(self, enabled: bool) -> None:
        """Enable or disable the right-panel editor."""
        self._editor.setEnabled(enabled)

    def _update_target_mode_ui(self) -> None:
        """Show/hide the manual-CIDR entry based on the selected radio."""
        manual = self._radio_manual.isChecked()
        self._cidr_label.setVisible(manual)
        self._cidr_edit.setVisible(manual)

    def _update_port_mode_ui(self) -> None:
        """Show/hide the custom-port entry based on the selected radio."""
        custom = self._radio_ports_custom.isChecked()
        self._custom_ports_label.setVisible(custom)
        self._custom_ports_edit.setVisible(custom)

    def _update_zone_enum_availability(self) -> None:
        """Zone enumeration is only available for 'Deep After-Hours'."""
        is_deep = self._intensity_combo.currentData() == "deep_after_hours"
        self._chk_zone_enum.setEnabled(is_deep)
        if not is_deep:
            self._chk_zone_enum.setChecked(False)

    # -----------------------------------------------------------------------
    # Profile list management
    # -----------------------------------------------------------------------

    def refresh_profile_list(self) -> None:
        """Reload profile list from the database."""
        self._profiles = self._db.get_profiles()
        self._profile_list.blockSignals(True)
        self._profile_list.clear()
        for p in self._profiles:
            item = QListWidgetItem(p.get("name", "(unnamed)"))
            item.setData(Qt.ItemDataRole.UserRole, p.get("id"))
            self._profile_list.addItem(item)
        self._profile_list.blockSignals(False)

        # If any profile was previously selected, try to re-select it
        if self._current_profile:
            self._select_profile_by_id(self._current_profile.get("id", ""))

    def _select_profile_by_id(self, profile_id: str) -> None:
        """Highlight the list-item with the given profile ID."""
        for idx in range(self._profile_list.count()):
            item = self._profile_list.item(idx)
            if item and item.data(Qt.ItemDataRole.UserRole) == profile_id:
                self._profile_list.setCurrentRow(idx)
                return

    def _find_profile_by_id(self, profile_id: str) -> Optional[dict]:
        for p in self._profiles:
            if p.get("id") == profile_id:
                return p
        return None

    # -----------------------------------------------------------------------
    # Load / Collect editor values
    # -----------------------------------------------------------------------

    def _load_profile_into_editor(self, profile: dict) -> None:
        """Populate every editor widget from a profile dict."""
        self._loading = True
        try:
            self._name_edit.setText(profile.get("name", ""))
            self._desc_edit.setText(profile.get("description", ""))

            # Target mode
            mode = profile.get("target_mode", "auto")
            if mode == "dhcp_scopes":
                self._radio_dhcp.setChecked(True)
            elif mode == "manual":
                self._radio_manual.setChecked(True)
            else:
                self._radio_auto.setChecked(True)
            self._update_target_mode_ui()

            self._cidr_edit.setPlainText(
                "\n".join(profile.get("manual_targets", []))
            )
            self._exclude_edit.setPlainText(
                "\n".join(profile.get("exclude_targets", []))
            )
            self._chk_skip_high_risk.setChecked(profile.get("skip_high_risk", True))

            # Intensity
            intensity = profile.get("intensity", "normal")
            idx = self._intensity_combo.findData(intensity)
            if idx >= 0:
                self._intensity_combo.setCurrentIndex(idx)

            # Tuning
            self._icmp_spin.setValue(profile.get("icmp_concurrency", 100))
            self._tcp_spin.setValue(profile.get("tcp_concurrency", 50))
            self._snmp_spin.setValue(profile.get("snmp_concurrency", 20))
            self._timeout_spin.setValue(profile.get("timeout_ms", 2000))
            self._retries_spin.setValue(profile.get("retries", 1))
            self._max_errors_spin.setValue(profile.get("max_errors_before_stop", 500))

            # Options
            self._chk_scan_only_alive.setChecked(profile.get("scan_only_alive", True))
            self._chk_ipv6.setChecked(profile.get("include_ipv6", False))
            self._chk_nmap.setChecked(profile.get("enable_nmap", False))
            self._chk_snmp.setChecked(profile.get("snmp_enabled", False))
            self._chk_zone_enum.setChecked(profile.get("enable_zone_enum", False))
            self._update_zone_enum_availability()

            # SNMP version
            snmp_v = profile.get("snmp_version", "2c")
            v_idx = self._snmp_version_combo.findData(snmp_v)
            if v_idx >= 0:
                self._snmp_version_combo.setCurrentIndex(v_idx)

            # Port selection
            port_list = profile.get("port_list", "default")
            if port_list == "extended":
                self._radio_ports_extended.setChecked(True)
            elif port_list == "custom":
                self._radio_ports_custom.setChecked(True)
            else:
                self._radio_ports_default.setChecked(True)
            self._update_port_mode_ui()

            custom_ports = profile.get("custom_ports", [])
            self._custom_ports_edit.setText(
                ", ".join(str(p) for p in custom_ports)
            )
        finally:
            self._loading = False

    def _collect_profile_from_editor(self) -> dict:
        """Build a profile dict from current editor values."""
        # Determine target mode
        if self._radio_dhcp.isChecked():
            target_mode = "dhcp_scopes"
        elif self._radio_manual.isChecked():
            target_mode = "manual"
        else:
            target_mode = "auto"

        # Parse manual CIDRs
        raw_cidrs = self._cidr_edit.toPlainText().strip()
        manual_targets = [
            c.strip() for c in raw_cidrs.splitlines() if c.strip()
        ]

        # Parse exclude CIDRs
        raw_excludes = self._exclude_edit.toPlainText().strip()
        exclude_targets = [
            c.strip() for c in raw_excludes.splitlines() if c.strip()
        ]

        # Parse custom ports
        custom_ports: list[int] = []
        if self._radio_ports_custom.isChecked():
            for token in self._custom_ports_edit.text().replace(";", ",").split(","):
                token = token.strip()
                if token.isdigit():
                    custom_ports.append(int(token))

        # Port list label
        if self._radio_ports_extended.isChecked():
            port_list = "extended"
        elif self._radio_ports_custom.isChecked():
            port_list = "custom"
        else:
            port_list = "default"

        now_iso = datetime.now().isoformat()
        profile_id = (
            self._current_profile["id"]
            if self._current_profile
            else str(uuid.uuid4())
        )
        created = (
            self._current_profile.get("created", now_iso)
            if self._current_profile
            else now_iso
        )

        return {
            "id": profile_id,
            "name": self._name_edit.text().strip() or "Unnamed Profile",
            "description": self._desc_edit.text().strip(),
            "created": created,
            "modified": now_iso,
            "target_mode": target_mode,
            "manual_targets": manual_targets,
            "exclude_targets": exclude_targets,
            "skip_high_risk": self._chk_skip_high_risk.isChecked(),
            "intensity": self._intensity_combo.currentData(),
            "icmp_concurrency": self._icmp_spin.value(),
            "tcp_concurrency": self._tcp_spin.value(),
            "snmp_concurrency": self._snmp_spin.value(),
            "timeout_ms": self._timeout_spin.value(),
            "retries": self._retries_spin.value(),
            "max_errors_before_stop": self._max_errors_spin.value(),
            "scan_only_alive": self._chk_scan_only_alive.isChecked(),
            "include_ipv6": self._chk_ipv6.isChecked(),
            "enable_nmap": self._chk_nmap.isChecked(),
            "enable_zone_enum": self._chk_zone_enum.isChecked(),
            "port_list": port_list,
            "custom_ports": custom_ports,
            "credential_ids": (
                self._current_profile.get("credential_ids", [])
                if self._current_profile
                else []
            ),
            "snmp_enabled": self._chk_snmp.isChecked(),
            "snmp_version": self._snmp_version_combo.currentData(),
        }

    # -----------------------------------------------------------------------
    # Slot handlers -- left panel
    # -----------------------------------------------------------------------

    def _on_profile_row_changed(self, row: int) -> None:
        if row < 0 or row >= len(self._profiles):
            self._current_profile = None
            self._set_editor_enabled(False)
            return
        profile = self._profiles[row]
        self._current_profile = profile
        self._load_profile_into_editor(profile)
        self._set_editor_enabled(True)
        self.profile_selected.emit(profile)

    def _on_new(self) -> None:
        """Create a blank profile and load it into the editor."""
        new_profile = ScanProfile()
        new_profile.name = "New Profile"
        profile_dict = new_profile.to_dict()
        self._db.save_profile(profile_dict)
        self.refresh_profile_list()
        self._select_profile_by_id(profile_dict["id"])
        # Manually trigger loading if not auto-selected
        if self._current_profile is None or self._current_profile.get("id") != profile_dict["id"]:
            self._current_profile = profile_dict
            self._load_profile_into_editor(profile_dict)
            self._set_editor_enabled(True)
        self._name_edit.setFocus()
        self._name_edit.selectAll()

    def _on_edit(self) -> None:
        """Ensure the editor is enabled for the selected profile."""
        if self._current_profile is None:
            QMessageBox.information(
                self, "No Selection", "Select a profile to edit first."
            )
            return
        self._set_editor_enabled(True)
        self._name_edit.setFocus()

    def _on_clone(self) -> None:
        """Duplicate the selected profile under a new ID."""
        if self._current_profile is None:
            QMessageBox.information(
                self, "No Selection", "Select a profile to clone first."
            )
            return
        cloned = copy.deepcopy(self._current_profile)
        cloned["id"] = str(uuid.uuid4())
        cloned["name"] = cloned.get("name", "") + " (Copy)"
        cloned["created"] = datetime.now().isoformat()
        cloned["modified"] = datetime.now().isoformat()
        self._db.save_profile(cloned)
        self.refresh_profile_list()
        self._select_profile_by_id(cloned["id"])

    def _on_delete(self) -> None:
        """Delete the selected profile after confirmation."""
        if self._current_profile is None:
            return
        name = self._current_profile.get("name", "this profile")
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Delete profile \"{name}\"?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._db.delete_profile(self._current_profile["id"])
            self._current_profile = None
            self._set_editor_enabled(False)
            self.refresh_profile_list()

    # -----------------------------------------------------------------------
    # Slot handlers -- editor bottom buttons
    # -----------------------------------------------------------------------

    def _on_save(self) -> None:
        """Persist the current editor contents to the database."""
        profile_dict = self._collect_profile_from_editor()
        if not profile_dict["name"]:
            QMessageBox.warning(
                self, "Validation", "Profile name cannot be empty."
            )
            self._name_edit.setFocus()
            return
        self._db.save_profile(profile_dict)
        self._current_profile = profile_dict
        self.refresh_profile_list()
        self._select_profile_by_id(profile_dict["id"])

    def _on_start_scan(self) -> None:
        """Emit start_scan_requested with the current editor values."""
        profile_dict = self._collect_profile_from_editor()
        if not profile_dict["name"]:
            QMessageBox.warning(
                self, "Validation", "Profile name cannot be empty."
            )
            self._name_edit.setFocus()
            return
        # Auto-save before scanning
        self._db.save_profile(profile_dict)
        self._current_profile = profile_dict
        self.start_scan_requested.emit(profile_dict)

    # -----------------------------------------------------------------------
    # Public helpers (for external callers)
    # -----------------------------------------------------------------------

    def save_current_profile(self) -> Optional[dict]:
        """Save whatever is in the editor and return the profile dict."""
        if not self._editor.isEnabled():
            return None
        profile_dict = self._collect_profile_from_editor()
        self._db.save_profile(profile_dict)
        self._current_profile = profile_dict
        self.refresh_profile_list()
        return profile_dict

    def load_profile(self, profile_id: str) -> bool:
        """Load a profile by ID from the database into the editor.

        Returns True if the profile was found and loaded.
        """
        profiles = self._db.get_profiles()
        for p in profiles:
            if p.get("id") == profile_id:
                self._current_profile = p
                self._load_profile_into_editor(p)
                self._set_editor_enabled(True)
                self.refresh_profile_list()
                self._select_profile_by_id(profile_id)
                return True
        return False

    def get_current_profile(self) -> Optional[dict]:
        """Return the profile dict currently loaded in the editor, or None."""
        if self._current_profile is None:
            return None
        return self._collect_profile_from_editor()
