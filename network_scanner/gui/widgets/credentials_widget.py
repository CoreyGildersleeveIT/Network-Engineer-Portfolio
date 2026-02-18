"""
Credentials management widget.
Allows adding/editing/deleting credential sets (domain, SNMP, SSH, etc.)
without storing secrets in plaintext.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QVBoxLayout, QWidget,
)


class CredentialsWidget(QWidget):
    """Widget for managing scan credentials."""

    credentials_changed = Signal()

    def __init__(self, db, cred_manager, parent=None):
        super().__init__(parent)
        self.db = db
        self.cred_manager = cred_manager
        self._setup_ui()
        self.refresh()

    def _setup_ui(self):
        layout = QHBoxLayout(self)

        # Left: credential list
        left = QVBoxLayout()
        left.addWidget(QLabel("Saved Credentials"))
        self.cred_list = QListWidget()
        self.cred_list.currentItemChanged.connect(self._on_selection_changed)
        left.addWidget(self.cred_list)

        btn_row = QHBoxLayout()
        self.btn_add = QPushButton("Add")
        self.btn_add.clicked.connect(self._on_add)
        self.btn_delete = QPushButton("Delete")
        self.btn_delete.setObjectName("dangerBtn")
        self.btn_delete.clicked.connect(self._on_delete)
        btn_row.addWidget(self.btn_add)
        btn_row.addWidget(self.btn_delete)
        left.addLayout(btn_row)

        left_widget = QWidget()
        left_widget.setLayout(left)
        left_widget.setMaximumWidth(280)

        # Right: credential details (read-only view)
        right = QVBoxLayout()
        self.detail_group = QGroupBox("Credential Details")
        detail_form = QFormLayout()
        self.lbl_name = QLabel("-")
        self.lbl_type = QLabel("-")
        self.lbl_user = QLabel("-")
        self.lbl_domain = QLabel("-")
        self.lbl_created = QLabel("-")
        detail_form.addRow("Name:", self.lbl_name)
        detail_form.addRow("Type:", self.lbl_type)
        detail_form.addRow("Username:", self.lbl_user)
        detail_form.addRow("Domain:", self.lbl_domain)
        detail_form.addRow("Created:", self.lbl_created)
        self.detail_group.setLayout(detail_form)
        right.addWidget(self.detail_group)

        info = QLabel(
            "Secrets are stored securely using Windows Credential Manager "
            "or encrypted storage. They are never saved in plaintext."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #8888aa; font-size: 11px;")
        right.addWidget(info)
        right.addStretch()

        right_widget = QWidget()
        right_widget.setLayout(right)

        layout.addWidget(left_widget)
        layout.addWidget(right_widget, 1)

    def refresh(self):
        self.cred_list.clear()
        creds = self.db.get_credentials()
        for cred in creds:
            item = QListWidgetItem(
                f"{cred.get('name', '')} [{cred.get('cred_type', '')}]"
            )
            item.setData(Qt.ItemDataRole.UserRole, cred)
            self.cred_list.addItem(item)

    def _on_selection_changed(self, current, _prev):
        if not current:
            return
        cred = current.data(Qt.ItemDataRole.UserRole)
        if cred:
            self.lbl_name.setText(cred.get("name", ""))
            self.lbl_type.setText(cred.get("cred_type", ""))
            self.lbl_user.setText(cred.get("username", ""))
            self.lbl_domain.setText(cred.get("domain", ""))
            self.lbl_created.setText(cred.get("created", ""))

    def _on_add(self):
        dlg = AddCredentialDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            data = dlg.get_data()
            if data:
                cred_id = str(uuid.uuid4())
                secret = data.pop("secret", "")
                secret_ref = ""
                if secret:
                    secret_ref = self.cred_manager.store_secret(cred_id, secret)

                cred_dict = {
                    "id": cred_id,
                    "name": data["name"],
                    "cred_type": data["cred_type"],
                    "username": data.get("username", ""),
                    "domain": data.get("domain", ""),
                    "secret_ref": secret_ref,
                    "created": datetime.now().isoformat(),
                }
                self.db.save_credential_meta(cred_dict)
                self.refresh()
                self.credentials_changed.emit()

    def _on_delete(self):
        item = self.cred_list.currentItem()
        if not item:
            return
        cred = item.data(Qt.ItemDataRole.UserRole)
        if not cred:
            return
        reply = QMessageBox.question(
            self, "Delete Credential",
            f"Delete credential '{cred.get('name', '')}'?",
        )
        if reply == QMessageBox.StandardButton.Yes:
            cred_id = cred.get("id", "")
            ref = cred.get("secret_ref", "")
            if ref:
                self.cred_manager.delete_secret(ref)
            self.db.delete_credential(cred_id)
            self.refresh()
            self.credentials_changed.emit()

    def get_resolved_credentials(self) -> dict:
        """Get all credentials with secrets resolved for scanning."""
        result = {}
        creds = self.db.get_credentials()
        for cred in creds:
            ctype = cred.get("cred_type", "")
            ref = cred.get("secret_ref", "")
            secret = self.cred_manager.retrieve_secret(ref) if ref else ""

            if ctype == "domain":
                result["domain"] = {
                    "username": cred.get("username", ""),
                    "password": secret,
                    "domain": cred.get("domain", ""),
                }
            elif ctype == "snmp_v2c":
                result.setdefault("snmp", {})["community"] = secret
                result["snmp"]["version"] = "2c"
            elif ctype == "snmp_v3":
                result.setdefault("snmp", {}).update({
                    "version": "3",
                    "v3_user": cred.get("username", ""),
                    "v3_auth_key": secret,
                })
            elif ctype == "ssh":
                result["ssh"] = {
                    "username": cred.get("username", ""),
                    "password": secret,
                }
        return result


class AddCredentialDialog(QDialog):
    """Dialog for adding a new credential."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Credential")
        self.setMinimumWidth(400)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        form = QFormLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g., Domain Admin, SNMP Community")
        form.addRow("Name:", self.name_edit)

        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "domain", "snmp_v2c", "snmp_v3", "ssh", "local_admin",
        ])
        self.type_combo.currentTextChanged.connect(self._on_type_changed)
        form.addRow("Type:", self.type_combo)

        self.user_edit = QLineEdit()
        form.addRow("Username:", self.user_edit)

        self.domain_edit = QLineEdit()
        form.addRow("Domain:", self.domain_edit)

        self.secret_edit = QLineEdit()
        self.secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_lbl = QLabel("Password:")
        form.addRow(self.secret_lbl, self.secret_edit)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_type_changed(self, ctype):
        if ctype == "snmp_v2c":
            self.secret_lbl.setText("Community:")
            self.user_edit.setEnabled(False)
            self.domain_edit.setEnabled(False)
        elif ctype == "snmp_v3":
            self.secret_lbl.setText("Auth Key:")
            self.user_edit.setEnabled(True)
            self.domain_edit.setEnabled(False)
        else:
            self.secret_lbl.setText("Password:")
            self.user_edit.setEnabled(True)
            self.domain_edit.setEnabled(ctype in ("domain", "local_admin"))

    def get_data(self) -> Optional[dict]:
        name = self.name_edit.text().strip()
        if not name:
            return None
        return {
            "name": name,
            "cred_type": self.type_combo.currentText(),
            "username": self.user_edit.text().strip(),
            "domain": self.domain_edit.text().strip(),
            "secret": self.secret_edit.text(),
        }
