"""
Entry point for NetScanner Pro.

Usage:
    python -m network_scanner
"""

import sys
import logging
from pathlib import Path

from PySide6.QtWidgets import QApplication

from . import __app_name__, __version__
from .gui.main_window import MainWindow


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger = logging.getLogger(__name__)
    logger.info("Starting %s v%s", __app_name__, __version__)

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
