"""
Application configuration and settings management.
Stores settings in a JSON file in the user's app data directory.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from typing import Any, Optional


def get_app_data_dir() -> Path:
    """Get the application data directory."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")))
    app_dir = base / "NetScannerPro"
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir


def get_db_path() -> Path:
    """Get the SQLite database path."""
    return get_app_data_dir() / "netscanner.db"


def get_exports_dir() -> Path:
    """Get the default exports directory."""
    exports = get_app_data_dir() / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    return exports


class AppSettings:
    """Application settings stored as JSON."""

    DEFAULT_SETTINGS = {
        "authorization_accepted": False,
        "authorization_timestamp": "",
        "authorization_user": "",
        "theme": "dark",
        "default_intensity": "normal",
        "icmp_concurrency": 100,
        "tcp_concurrency": 50,
        "snmp_concurrency": 20,
        "default_timeout_ms": 2000,
        "default_retries": 1,
        "max_errors_before_stop": 500,
        "scan_only_alive": True,
        "include_ipv6": False,
        "enable_nmap": False,
        "nmap_path": "",
        "default_export_dir": "",
        "recent_profiles": [],
        "window_geometry": None,
    }

    def __init__(self) -> None:
        self._path = get_app_data_dir() / "settings.json"
        self._settings: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path, "r") as f:
                    self._settings = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._settings = {}
        for k, v in self.DEFAULT_SETTINGS.items():
            if k not in self._settings:
                self._settings[k] = v

    def save(self) -> None:
        with open(self._path, "w") as f:
            json.dump(self._settings, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        return self._settings.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._settings[key] = value
        self.save()

    @property
    def is_authorized(self) -> bool:
        return bool(self._settings.get("authorization_accepted", False))

    def accept_authorization(self, username: str) -> None:
        from datetime import datetime
        self._settings["authorization_accepted"] = True
        self._settings["authorization_timestamp"] = datetime.now().isoformat()
        self._settings["authorization_user"] = username
        self.save()
