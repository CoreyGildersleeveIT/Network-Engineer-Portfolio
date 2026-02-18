"""
Authorization dialog for first-run gate.

Requires the user to acknowledge that they are authorized to perform
active network scanning before the application will proceed.
"""

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QFrame,
    QSpacerItem,
    QSizePolicy,
)
from PySide6.QtCore import Qt


class AuthorizationDialog(QDialog):
    """Modal dialog that acts as a first-run authorization gate.

    The user must enter their name or initials and confirm via checkbox
    that they are authorized to scan the target network.  The *Accept*
    button stays disabled until both conditions are met.

    Parameters
    ----------
    accept_callback : callable
        Called with the entered name string when the user accepts the
        dialog.  The caller can use this to persist the authorization
        record.
    parent : QWidget or None
        Optional parent widget.
    """

    def __init__(self, accept_callback, parent=None):
        super().__init__(parent)
        self._accept_callback = accept_callback
        self._setup_window()
        self._build_ui()
        self._apply_style()

    # ------------------------------------------------------------------
    # Window configuration
    # ------------------------------------------------------------------

    def _setup_window(self):
        self.setWindowTitle("NetScanner Pro — Authorization Required")
        self.setFixedSize(520, 480)
        self.setWindowFlags(
            self.windowFlags()
            & ~Qt.WindowContextHelpButtonHint
        )

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(32, 28, 32, 24)
        root_layout.setSpacing(0)

        # ---- Header ---------------------------------------------------
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)

        app_name = QLabel("NetScanner Pro")
        app_name.setAlignment(Qt.AlignCenter)
        app_name.setObjectName("appNameLabel")
        header_layout.addWidget(app_name)

        subtitle = QLabel("Network Discovery & Analysis Tool")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setObjectName("subtitleLabel")
        header_layout.addWidget(subtitle)

        root_layout.addLayout(header_layout)
        root_layout.addSpacing(18)

        # ---- Divider --------------------------------------------------
        root_layout.addWidget(self._make_divider())
        root_layout.addSpacing(16)

        # ---- Warning icon + title -------------------------------------
        warning_row = QHBoxLayout()
        warning_row.setSpacing(8)

        warning_icon = QLabel("\u26a0")  # Unicode warning sign
        warning_icon.setObjectName("warningIcon")
        warning_row.addWidget(warning_icon)

        warning_title = QLabel("Authorization Notice")
        warning_title.setObjectName("warningTitle")
        warning_row.addWidget(warning_title)

        warning_row.addStretch()
        root_layout.addLayout(warning_row)
        root_layout.addSpacing(12)

        # ---- Notice text ----------------------------------------------
        notice_text = (
            "This tool performs <b>active network scanning</b>, including "
            "host discovery, port probing, and service enumeration. These "
            "actions generate network traffic that may be detected by "
            "security monitoring systems.\n\n"
            "You must only use this tool on networks for which you have "
            "<b>explicit written authorization</b> to perform scanning and "
            "testing activities.\n\n"
            "By proceeding you confirm that you have the required "
            "authorization and accept full responsibility for any scanning "
            "activity initiated by this application."
        )
        notice = QLabel(notice_text)
        notice.setWordWrap(True)
        notice.setObjectName("noticeLabel")
        notice.setTextFormat(Qt.RichText)
        root_layout.addWidget(notice)
        root_layout.addSpacing(18)

        # ---- Divider --------------------------------------------------
        root_layout.addWidget(self._make_divider())
        root_layout.addSpacing(16)

        # ---- Name / initials input ------------------------------------
        name_label = QLabel("Your Name or Initials")
        name_label.setObjectName("fieldLabel")
        root_layout.addWidget(name_label)
        root_layout.addSpacing(4)

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("e.g. Jane Smith or JS")
        self._name_edit.setMaxLength(100)
        self._name_edit.textChanged.connect(self._update_accept_state)
        root_layout.addWidget(self._name_edit)
        root_layout.addSpacing(14)

        # ---- Confirmation checkbox ------------------------------------
        self._confirm_check = QCheckBox(
            "I confirm I am authorized to scan this network"
        )
        self._confirm_check.stateChanged.connect(self._update_accept_state)
        root_layout.addWidget(self._confirm_check)

        # ---- Spacer before buttons ------------------------------------
        root_layout.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding)
        )

        # ---- Button row -----------------------------------------------
        button_layout = QHBoxLayout()
        button_layout.setSpacing(12)

        self._decline_btn = QPushButton("Decline")
        self._decline_btn.setObjectName("secondaryBtn")
        self._decline_btn.clicked.connect(self.reject)
        button_layout.addWidget(self._decline_btn)

        button_layout.addStretch()

        self._accept_btn = QPushButton("Accept && Continue")
        self._accept_btn.setEnabled(False)
        self._accept_btn.setObjectName("successBtn")
        self._accept_btn.clicked.connect(self._on_accept)
        button_layout.addWidget(self._accept_btn)

        root_layout.addLayout(button_layout)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_divider():
        """Return a thin horizontal line styled as a divider."""
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Plain)
        line.setObjectName("divider")
        return line

    # ------------------------------------------------------------------
    # Slot: enable / disable the accept button
    # ------------------------------------------------------------------

    def _update_accept_state(self):
        name_filled = bool(self._name_edit.text().strip())
        checked = self._confirm_check.isChecked()
        self._accept_btn.setEnabled(name_filled and checked)

    # ------------------------------------------------------------------
    # Slot: user accepted
    # ------------------------------------------------------------------

    def _on_accept(self):
        name = self._name_edit.text().strip()
        if self._accept_callback is not None:
            self._accept_callback(name)
        self.accept()

    # ------------------------------------------------------------------
    # Stylesheet (dark theme, consistent with app palette)
    # ------------------------------------------------------------------

    def _apply_style(self):
        self.setStyleSheet("""
            /* Dialog background */
            QDialog {
                background-color: #1a1a2e;
            }

            /* App name header */
            QLabel#appNameLabel {
                font-size: 22px;
                font-weight: bold;
                color: #3498db;
                padding: 0;
            }

            /* Subtitle */
            QLabel#subtitleLabel {
                font-size: 13px;
                color: #8888aa;
                padding: 0;
            }

            /* Warning icon (unicode) */
            QLabel#warningIcon {
                font-size: 22px;
                color: #e67e22;
            }

            /* Warning section title */
            QLabel#warningTitle {
                font-size: 15px;
                font-weight: bold;
                color: #e67e22;
            }

            /* Notice body text */
            QLabel#noticeLabel {
                font-size: 12px;
                color: #c0c0d0;
                line-height: 1.5;
                padding: 0;
            }

            /* Field label above the input */
            QLabel#fieldLabel {
                font-size: 12px;
                font-weight: bold;
                color: #e0e0e0;
            }

            /* Divider line */
            QFrame#divider {
                border: none;
                background-color: #2a2a4a;
                max-height: 1px;
            }

            /* Text input */
            QLineEdit {
                background-color: #0f0f23;
                border: 1px solid #2a2a4a;
                border-radius: 4px;
                padding: 8px 10px;
                color: #e0e0e0;
                font-size: 13px;
                selection-background-color: #3498db;
            }
            QLineEdit:focus {
                border-color: #3498db;
            }

            /* Checkbox */
            QCheckBox {
                spacing: 8px;
                color: #e0e0e0;
                font-size: 13px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                border: 1px solid #2a2a4a;
                border-radius: 3px;
                background-color: #0f0f23;
            }
            QCheckBox::indicator:checked {
                background-color: #3498db;
                border-color: #3498db;
            }

            /* Buttons — shared */
            QPushButton {
                border: none;
                padding: 9px 22px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 13px;
                min-height: 30px;
                color: white;
            }

            /* Accept / Continue */
            QPushButton#successBtn {
                background-color: #2ecc71;
            }
            QPushButton#successBtn:hover {
                background-color: #27ae60;
            }
            QPushButton#successBtn:disabled {
                background-color: #2c3e50;
                color: #555555;
            }

            /* Decline */
            QPushButton#secondaryBtn {
                background-color: #34495e;
            }
            QPushButton#secondaryBtn:hover {
                background-color: #2c3e50;
            }
        """)
