"""
ARP / Neighbor table collector.
Uses Get-NetNeighbor (Windows) or ip neigh (Linux) to gather IP-to-MAC mappings.
Re-samples periodically during scan to catch transient entries.
"""

from __future__ import annotations

import json
import logging
import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Optional

from ..core.models import DataSource
from ..core.oui import lookup_vendor, normalize_mac

logger = logging.getLogger(__name__)


@dataclass
class ARPEntry:
    """A single ARP/NDP table entry."""
    ip_address: str = ""
    mac_address: str = ""
    interface: str = ""
    state: str = ""  # reachable, stale, delay, etc.
    is_ipv6: bool = False
    source: DataSource = DataSource.ARP_TABLE


def collect_arp_table() -> list[ARPEntry]:
    """Collect ARP table from the local system."""
    if platform.system() == "Windows":
        return _collect_windows_arp()
    return _collect_linux_arp()


def collect_ndp_table() -> list[ARPEntry]:
    """Collect IPv6 NDP neighbor table."""
    if platform.system() == "Windows":
        return _collect_windows_ndp()
    return _collect_linux_ndp()


def _collect_windows_arp() -> list[ARPEntry]:
    """Collect ARP via PowerShell Get-NetNeighbor."""
    entries = []
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command",
             "Get-NetNeighbor -AddressFamily IPv4 | "
             "Where-Object {$_.State -ne 'Unreachable' -and $_.LinkLayerAddress -ne ''} | "
             "Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, State | "
             "ConvertTo-Json -Depth 2"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            for item in data:
                ip = item.get("IPAddress", "")
                mac = item.get("LinkLayerAddress", "")
                if not ip or not mac or mac == "00-00-00-00-00-00":
                    continue
                if ip.startswith("224.") or ip.startswith("239.") or ip == "255.255.255.255":
                    continue
                entry = ARPEntry(
                    ip_address=ip,
                    mac_address=normalize_mac(mac),
                    interface=item.get("InterfaceAlias", ""),
                    state=item.get("State", ""),
                    source=DataSource.ARP_TABLE,
                )
                entries.append(entry)
    except FileNotFoundError:
        # Fallback to arp -a
        entries = _collect_arp_cmd()
    except Exception as e:
        logger.warning("Windows ARP collection failed: %s", e)
        entries = _collect_arp_cmd()
    logger.info("Collected %d ARP entries", len(entries))
    return entries


def _collect_arp_cmd() -> list[ARPEntry]:
    """Fallback ARP collection using arp -a command."""
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                # Windows: 192.168.1.1    00-aa-bb-cc-dd-ee   dynamic
                # Linux:   host (192.168.1.1) at 00:aa:bb:cc:dd:ee [ether] on eth0
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F][-:][0-9a-fA-F][-:]"
                    r"[0-9a-fA-F][-:][0-9a-fA-F][-:][0-9a-fA-F][-:][0-9a-fA-F]"
                    r"[-:][0-9a-fA-F][-:][0-9a-fA-F][-:][0-9a-fA-F][-:]"
                    r"[0-9a-fA-F][-:][0-9a-fA-F][-:][0-9a-fA-F])",
                    line,
                )
                if not m:
                    # Try simpler pattern
                    m = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]"
                        r"[0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:]"
                        r"[0-9a-fA-F]{2})",
                        line,
                    )
                if m:
                    ip = m.group(1)
                    mac = normalize_mac(m.group(2))
                    if mac != "FF:FF:FF:FF:FF:FF" and mac != "00:00:00:00:00:00":
                        entries.append(ARPEntry(
                            ip_address=ip,
                            mac_address=mac,
                            source=DataSource.ARP_TABLE,
                        ))
    except Exception as e:
        logger.warning("arp -a fallback failed: %s", e)
    return entries


def _collect_linux_arp() -> list[ARPEntry]:
    """Collect ARP on Linux using ip neigh."""
    entries = []
    try:
        result = subprocess.run(
            ["ip", "-j", "neigh", "show"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            for item in data:
                ip = item.get("dst", "")
                mac = item.get("lladdr", "")
                state = " ".join(item.get("state", []))
                if not ip or not mac or "FAILED" in state:
                    continue
                if ":" in ip:  # skip IPv6
                    continue
                entries.append(ARPEntry(
                    ip_address=ip,
                    mac_address=normalize_mac(mac),
                    interface=item.get("dev", ""),
                    state=state,
                    source=DataSource.ARP_TABLE,
                ))
    except FileNotFoundError:
        entries = _collect_arp_cmd()
    except Exception as e:
        logger.warning("Linux ARP collection failed: %s", e)
        entries = _collect_arp_cmd()
    logger.info("Collected %d ARP entries", len(entries))
    return entries


def _collect_windows_ndp() -> list[ARPEntry]:
    """Collect IPv6 NDP table on Windows."""
    entries = []
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command",
             "Get-NetNeighbor -AddressFamily IPv6 | "
             "Where-Object {$_.State -ne 'Unreachable' -and $_.LinkLayerAddress -ne ''} | "
             "Select-Object IPAddress, LinkLayerAddress, InterfaceAlias, State | "
             "ConvertTo-Json -Depth 2"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            if isinstance(data, dict):
                data = [data]
            for item in data:
                ip = item.get("IPAddress", "")
                mac = item.get("LinkLayerAddress", "")
                if not ip or not mac or ip.startswith("ff02:") or ip.startswith("fe80::"):
                    continue
                entries.append(ARPEntry(
                    ip_address=ip,
                    mac_address=normalize_mac(mac),
                    interface=item.get("InterfaceAlias", ""),
                    state=item.get("State", ""),
                    is_ipv6=True,
                    source=DataSource.NDP_TABLE,
                ))
    except Exception as e:
        logger.debug("Windows NDP collection failed: %s", e)
    return entries


def _collect_linux_ndp() -> list[ARPEntry]:
    """Collect IPv6 NDP table on Linux."""
    entries = []
    try:
        result = subprocess.run(
            ["ip", "-6", "-j", "neigh", "show"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            for item in data:
                ip = item.get("dst", "")
                mac = item.get("lladdr", "")
                if not ip or not mac or ip.startswith("ff02:") or ip.startswith("fe80::"):
                    continue
                entries.append(ARPEntry(
                    ip_address=ip,
                    mac_address=normalize_mac(mac),
                    interface=item.get("dev", ""),
                    is_ipv6=True,
                    source=DataSource.NDP_TABLE,
                ))
    except Exception as e:
        logger.debug("Linux NDP collection failed: %s", e)
    return entries
