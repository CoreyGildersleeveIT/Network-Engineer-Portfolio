"""
Modern dark theme stylesheet for the application.
Inspired by Nessus/professional security tool UIs.
"""

DARK_STYLESHEET = """
/* Global */
QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #1a1a2e;
}

/* Menu Bar */
QMenuBar {
    background-color: #0f0f23;
    border-bottom: 1px solid #2a2a4a;
    padding: 2px;
}
QMenuBar::item:selected {
    background-color: #3498db;
    border-radius: 3px;
}
QMenu {
    background-color: #16213e;
    border: 1px solid #2a2a4a;
}
QMenu::item:selected {
    background-color: #3498db;
}

/* Tab Widget */
QTabWidget::pane {
    background-color: #16213e;
    border: 1px solid #2a2a4a;
    border-radius: 4px;
}
QTabBar::tab {
    background-color: #0f0f23;
    color: #8888aa;
    padding: 10px 20px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    min-width: 100px;
}
QTabBar::tab:selected {
    background-color: #16213e;
    color: #3498db;
    border-bottom: 2px solid #3498db;
}
QTabBar::tab:hover:!selected {
    background-color: #1a1a3e;
    color: #e0e0e0;
}

/* Buttons */
QPushButton {
    background-color: #3498db;
    color: white;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: bold;
    min-height: 30px;
}
QPushButton:hover {
    background-color: #2980b9;
}
QPushButton:pressed {
    background-color: #2471a3;
}
QPushButton:disabled {
    background-color: #2c3e50;
    color: #666;
}
QPushButton#dangerBtn {
    background-color: #e74c3c;
}
QPushButton#dangerBtn:hover {
    background-color: #c0392b;
}
QPushButton#successBtn {
    background-color: #2ecc71;
}
QPushButton#successBtn:hover {
    background-color: #27ae60;
}
QPushButton#secondaryBtn {
    background-color: #34495e;
}
QPushButton#secondaryBtn:hover {
    background-color: #2c3e50;
}

/* Input Fields */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {
    background-color: #0f0f23;
    border: 1px solid #2a2a4a;
    border-radius: 4px;
    padding: 6px 10px;
    color: #e0e0e0;
    selection-background-color: #3498db;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #3498db;
}

/* ComboBox */
QComboBox {
    background-color: #0f0f23;
    border: 1px solid #2a2a4a;
    border-radius: 4px;
    padding: 6px 10px;
    min-height: 28px;
}
QComboBox:hover {
    border-color: #3498db;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background-color: #16213e;
    border: 1px solid #2a2a4a;
    selection-background-color: #3498db;
}

/* Tables */
QTableView, QTableWidget {
    background-color: #16213e;
    alternate-background-color: #1a1a3e;
    border: 1px solid #2a2a4a;
    border-radius: 4px;
    gridline-color: #2a2a4a;
    selection-background-color: rgba(52, 152, 219, 0.3);
    selection-color: #e0e0e0;
}
QTableView::item, QTableWidget::item {
    padding: 4px 8px;
}
QHeaderView::section {
    background-color: #0f3460;
    color: white;
    padding: 8px;
    border: none;
    border-right: 1px solid #2a2a4a;
    border-bottom: 1px solid #2a2a4a;
    font-weight: bold;
    font-size: 12px;
}

/* Tree View */
QTreeView, QTreeWidget {
    background-color: #16213e;
    border: 1px solid #2a2a4a;
    border-radius: 4px;
    alternate-background-color: #1a1a3e;
}
QTreeView::item:selected, QTreeWidget::item:selected {
    background-color: rgba(52, 152, 219, 0.3);
}

/* Scroll Bars */
QScrollBar:vertical {
    background: #0f0f23;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #34495e;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #3498db;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar:horizontal {
    background: #0f0f23;
    height: 10px;
}
QScrollBar::handle:horizontal {
    background: #34495e;
    border-radius: 5px;
    min-width: 30px;
}

/* Progress Bar */
QProgressBar {
    background-color: #0f0f23;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    text-align: center;
    color: white;
    height: 20px;
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #3498db, stop:1 #2ecc71);
    border-radius: 5px;
}

/* Group Box */
QGroupBox {
    background-color: #16213e;
    border: 1px solid #2a2a4a;
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 15px;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #3498db;
}

/* Check Box */
QCheckBox {
    spacing: 8px;
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

/* Radio Button */
QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #2a2a4a;
    border-radius: 8px;
    background-color: #0f0f23;
}
QRadioButton::indicator:checked {
    background-color: #3498db;
    border-color: #3498db;
}

/* Slider */
QSlider::groove:horizontal {
    background: #2a2a4a;
    height: 6px;
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background: #3498db;
    width: 16px;
    height: 16px;
    margin: -5px 0;
    border-radius: 8px;
}
QSlider::sub-page:horizontal {
    background: #3498db;
    border-radius: 3px;
}

/* Splitter */
QSplitter::handle {
    background-color: #2a2a4a;
}
QSplitter::handle:horizontal {
    width: 3px;
}
QSplitter::handle:vertical {
    height: 3px;
}

/* Status Bar */
QStatusBar {
    background-color: #0f0f23;
    border-top: 1px solid #2a2a4a;
    color: #8888aa;
}

/* Tooltip */
QToolTip {
    background-color: #16213e;
    border: 1px solid #3498db;
    color: #e0e0e0;
    padding: 4px;
    border-radius: 3px;
}

/* Labels */
QLabel#titleLabel {
    font-size: 18px;
    font-weight: bold;
    color: #3498db;
}
QLabel#subtitleLabel {
    font-size: 14px;
    color: #8888aa;
}
QLabel#warningLabel {
    color: #e74c3c;
    font-weight: bold;
}
QLabel#successLabel {
    color: #2ecc71;
    font-weight: bold;
}
"""
