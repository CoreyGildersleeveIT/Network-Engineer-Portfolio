"""
Credential manager with platform-appropriate secure storage.

Windows: Uses Windows Credential Manager via ctypes/keyring.
Other platforms: Uses Fernet encryption with PBKDF2-derived key stored
in user-protected file (fallback when DPAPI is unavailable).

NEVER stores plaintext secrets in config files or databases.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import platform
import secrets
from pathlib import Path
from typing import Optional

from .config import get_app_data_dir

logger = logging.getLogger(__name__)

# Credential target prefix for Windows Credential Manager
_WIN_TARGET_PREFIX = "NetScannerPro:"


class CredentialManager:
    """Secure credential storage abstraction."""

    def __init__(self) -> None:
        self._backend: _CredBackend
        if platform.system() == "Windows":
            try:
                self._backend = _WindowsCredBackend()
                logger.info("Using Windows Credential Manager for secrets")
                return
            except Exception as e:
                logger.warning(
                    "Windows Credential Manager unavailable (%s), "
                    "falling back to encrypted file", e
                )
        self._backend = _EncryptedFileBackend()
        logger.info("Using encrypted file backend for secrets")

    def store_secret(self, key: str, secret: str) -> str:
        """Store a secret, return a reference key."""
        ref = f"{_WIN_TARGET_PREFIX}{key}"
        self._backend.write(ref, secret)
        return ref

    def retrieve_secret(self, ref: str) -> Optional[str]:
        """Retrieve a secret by reference key."""
        return self._backend.read(ref)

    def delete_secret(self, ref: str) -> None:
        """Delete a stored secret."""
        self._backend.delete(ref)

    def list_keys(self) -> list[str]:
        """List all stored secret references."""
        return self._backend.list_keys()


class _CredBackend:
    """Base class for credential backends."""

    def write(self, key: str, value: str) -> None:
        raise NotImplementedError

    def read(self, key: str) -> Optional[str]:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def list_keys(self) -> list[str]:
        raise NotImplementedError


class _WindowsCredBackend(_CredBackend):
    """Windows Credential Manager via keyring library."""

    def __init__(self) -> None:
        import keyring
        self._kr = keyring

    def write(self, key: str, value: str) -> None:
        self._kr.set_password("NetScannerPro", key, value)

    def read(self, key: str) -> Optional[str]:
        return self._kr.get_password("NetScannerPro", key)

    def delete(self, key: str) -> None:
        try:
            self._kr.delete_password("NetScannerPro", key)
        except Exception:
            pass

    def list_keys(self) -> list[str]:
        # keyring doesn't provide list functionality natively;
        # we track keys in a sidecar file
        keys_file = get_app_data_dir() / "cred_keys.json"
        if keys_file.exists():
            try:
                return json.loads(keys_file.read_text())
            except Exception:
                return []
        return []


class _EncryptedFileBackend(_CredBackend):
    """
    Cross-platform fallback using Fernet symmetric encryption.
    The encryption key is derived from a random salt stored alongside.
    """

    def __init__(self) -> None:
        self._store_dir = get_app_data_dir() / "credentials"
        self._store_dir.mkdir(parents=True, exist_ok=True)
        self._store_file = self._store_dir / "vault.enc"
        self._salt_file = self._store_dir / "vault.salt"
        self._key = self._load_or_create_key()

    def _load_or_create_key(self) -> bytes:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        if self._salt_file.exists():
            salt = self._salt_file.read_bytes()
        else:
            salt = secrets.token_bytes(32)
            self._salt_file.write_bytes(salt)
            # Restrict permissions on non-Windows
            if platform.system() != "Windows":
                os.chmod(self._salt_file, 0o600)

        # Derive key from machine-specific info + salt
        machine_id = (
            platform.node() + os.environ.get("USERNAME", os.environ.get("USER", ""))
        ).encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt + machine_id,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(salt))
        return key

    def _load_vault(self) -> dict[str, str]:
        if not self._store_file.exists():
            return {}
        from cryptography.fernet import Fernet
        f = Fernet(self._key)
        try:
            data = f.decrypt(self._store_file.read_bytes())
            return json.loads(data)
        except Exception:
            logger.error("Failed to decrypt credential vault")
            return {}

    def _save_vault(self, vault: dict[str, str]) -> None:
        from cryptography.fernet import Fernet
        f = Fernet(self._key)
        data = json.dumps(vault).encode()
        self._store_file.write_bytes(f.encrypt(data))
        if platform.system() != "Windows":
            os.chmod(self._store_file, 0o600)

    def write(self, key: str, value: str) -> None:
        vault = self._load_vault()
        vault[key] = value
        self._save_vault(vault)

    def read(self, key: str) -> Optional[str]:
        vault = self._load_vault()
        return vault.get(key)

    def delete(self, key: str) -> None:
        vault = self._load_vault()
        vault.pop(key, None)
        self._save_vault(vault)

    def list_keys(self) -> list[str]:
        vault = self._load_vault()
        return list(vault.keys())
