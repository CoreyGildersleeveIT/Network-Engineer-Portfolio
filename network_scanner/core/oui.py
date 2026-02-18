"""
OUI (Organizationally Unique Identifier) lookup for MAC address vendor identification.
Uses a bundled dictionary of common OUI prefixes.
"""

from __future__ import annotations

import re
from typing import Optional

# Comprehensive OUI prefix table (first 3 octets -> vendor)
# This covers the most common network equipment vendors encountered in enterprise LANs.
_OUI_TABLE: dict[str, str] = {
    # Cisco
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:43": "Cisco",
    "00:01:63": "Cisco", "00:01:64": "Cisco", "00:01:96": "Cisco",
    "00:01:97": "Cisco", "00:02:16": "Cisco", "00:02:17": "Cisco",
    "00:02:3D": "Cisco", "00:02:4A": "Cisco", "00:02:4B": "Cisco",
    "00:02:B9": "Cisco", "00:02:BA": "Cisco", "00:02:FC": "Cisco",
    "00:02:FD": "Cisco", "00:03:31": "Cisco", "00:03:32": "Cisco",
    "00:03:6B": "Cisco", "00:03:6C": "Cisco", "00:03:9F": "Cisco",
    "00:03:A0": "Cisco", "00:03:E3": "Cisco", "00:03:E4": "Cisco",
    "00:03:FD": "Cisco", "00:03:FE": "Cisco", "00:04:27": "Cisco",
    "00:04:28": "Cisco", "00:04:4D": "Cisco", "00:04:4E": "Cisco",
    "00:04:6D": "Cisco", "00:04:6E": "Cisco", "00:04:9A": "Cisco",
    "00:04:9B": "Cisco", "00:04:C0": "Cisco", "00:04:C1": "Cisco",
    "00:04:DD": "Cisco", "00:04:DE": "Cisco", "00:05:00": "Cisco",
    "00:05:01": "Cisco", "00:05:31": "Cisco", "00:05:32": "Cisco",
    "00:05:5E": "Cisco", "00:05:5F": "Cisco", "00:05:73": "Cisco",
    "00:05:74": "Cisco", "00:05:9B": "Cisco", "00:05:DC": "Cisco",
    "00:05:DD": "Cisco",
    # Meraki
    "00:18:0A": "Cisco Meraki", "AC:17:C8": "Cisco Meraki",
    "0C:8D:DB": "Cisco Meraki", "34:56:FE": "Cisco Meraki",
    "E0:55:3D": "Cisco Meraki", "E8:26:89": "Cisco Meraki",
    # HP / Aruba
    "00:0B:CD": "HP", "00:0D:9D": "HP", "00:0E:7F": "HP",
    "00:0F:20": "HP", "00:10:83": "HP", "00:11:0A": "HP",
    "00:11:85": "HP", "00:12:79": "HP", "00:13:21": "HP",
    "00:14:38": "HP", "00:15:60": "HP", "00:16:35": "HP",
    "00:17:08": "HP", "00:18:71": "HP", "00:19:BB": "HP",
    "00:1A:4B": "HP", "00:1B:78": "HP", "00:1C:C4": "HP",
    "00:1E:0B": "HP", "00:1F:29": "HP", "00:21:5A": "HP",
    "00:22:64": "HP", "00:23:7D": "HP", "00:24:81": "HP",
    "00:25:B3": "HP", "00:26:55": "HP",
    "00:0B:86": "Aruba Networks", "24:DE:C6": "Aruba Networks",
    "40:E3:D6": "Aruba Networks", "6C:F3:7F": "Aruba Networks",
    "9C:1C:12": "Aruba Networks", "AC:A3:1E": "Aruba Networks",
    "D8:C7:C8": "Aruba Networks",
    # Dell
    "00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell",
    "00:0D:56": "Dell", "00:0F:1F": "Dell", "00:11:43": "Dell",
    "00:12:3F": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
    "00:15:C5": "Dell", "00:16:F0": "Dell", "00:18:8B": "Dell",
    "00:19:B9": "Dell", "00:1A:A0": "Dell", "00:1C:23": "Dell",
    "00:1D:09": "Dell", "00:1E:4F": "Dell", "00:1E:C9": "Dell",
    "00:21:70": "Dell", "00:21:9B": "Dell", "00:22:19": "Dell",
    "00:23:AE": "Dell", "00:24:E8": "Dell", "00:25:64": "Dell",
    "00:26:B9": "Dell",
    # Juniper
    "00:05:85": "Juniper", "00:10:DB": "Juniper", "00:12:1E": "Juniper",
    "00:14:F6": "Juniper", "00:17:CB": "Juniper", "00:19:E2": "Juniper",
    "00:1D:B5": "Juniper", "00:21:59": "Juniper", "00:22:83": "Juniper",
    "00:23:9C": "Juniper", "00:24:DC": "Juniper", "00:26:88": "Juniper",
    "28:8A:1C": "Juniper", "28:C0:DA": "Juniper",
    "2C:21:72": "Juniper", "2C:6B:F5": "Juniper",
    # Fortinet
    "00:09:0F": "Fortinet", "08:5B:0E": "Fortinet",
    "70:4C:A5": "Fortinet", "90:6C:AC": "Fortinet",
    "E8:1C:BA": "Fortinet",
    # Palo Alto
    "00:1B:17": "Palo Alto Networks", "00:86:9C": "Palo Alto Networks",
    "08:66:1F": "Palo Alto Networks", "B4:0C:25": "Palo Alto Networks",
    # SonicWall
    "00:06:B1": "SonicWall", "00:17:C5": "SonicWall",
    "C0:EA:E4": "SonicWall",
    # Ubiquiti
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti",
    "04:18:D6": "Ubiquiti", "18:E8:29": "Ubiquiti",
    "24:5A:4C": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    # Ruckus
    "00:13:92": "Ruckus Wireless", "00:1F:41": "Ruckus Wireless",
    "00:22:7F": "Ruckus Wireless", "00:25:C4": "Ruckus Wireless",
    "58:B6:33": "Ruckus Wireless", "74:91:1A": "Ruckus Wireless",
    "A8:BD:27": "Ruckus Wireless", "C4:01:7C": "Ruckus Wireless",
    # Apple
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple",
    "00:0A:95": "Apple", "00:0D:93": "Apple", "00:10:FA": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple",
    "00:17:F2": "Apple", "00:19:E3": "Apple", "00:1B:63": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:1E:52": "Apple",
    "00:1E:C2": "Apple", "00:1F:5B": "Apple", "00:1F:F3": "Apple",
    "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
    "00:23:32": "Apple", "00:23:6C": "Apple", "00:23:DF": "Apple",
    "00:24:36": "Apple", "00:25:00": "Apple", "00:25:4B": "Apple",
    "00:25:BC": "Apple", "00:26:08": "Apple", "00:26:4A": "Apple",
    "00:26:B0": "Apple", "00:26:BB": "Apple",
    # Microsoft
    "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft",
    "00:12:5A": "Microsoft", "00:15:5D": "Microsoft (Hyper-V)",
    "00:17:FA": "Microsoft", "00:1D:D8": "Microsoft",
    "00:22:48": "Microsoft", "00:25:AE": "Microsoft",
    "28:18:78": "Microsoft", "30:59:B7": "Microsoft",
    "48:50:73": "Microsoft", "50:1A:C5": "Microsoft",
    "60:45:BD": "Microsoft", "7C:1E:52": "Microsoft",
    "98:5F:D3": "Microsoft", "B8:31:B5": "Microsoft",
    "C8:3F:26": "Microsoft", "DC:B4:C4": "Microsoft",
    # VMware
    "00:05:69": "VMware", "00:0C:29": "VMware", "00:1C:14": "VMware",
    "00:50:56": "VMware",
    # Intel
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:07:E9": "Intel", "00:0C:F1": "Intel", "00:0E:0C": "Intel",
    "00:0E:35": "Intel", "00:11:11": "Intel", "00:12:F0": "Intel",
    "00:13:02": "Intel", "00:13:20": "Intel", "00:13:CE": "Intel",
    "00:13:E8": "Intel", "00:15:00": "Intel", "00:15:17": "Intel",
    "00:16:6F": "Intel", "00:16:76": "Intel", "00:16:EA": "Intel",
    "00:16:EB": "Intel", "00:18:DE": "Intel", "00:19:D1": "Intel",
    "00:19:D2": "Intel", "00:1B:21": "Intel", "00:1B:77": "Intel",
    "00:1C:BF": "Intel", "00:1C:C0": "Intel", "00:1D:E0": "Intel",
    "00:1D:E1": "Intel", "00:1E:64": "Intel", "00:1E:65": "Intel",
    "00:1E:67": "Intel", "00:1F:3B": "Intel", "00:1F:3C": "Intel",
    "00:20:7B": "Intel", "00:21:5C": "Intel", "00:21:5D": "Intel",
    "00:21:6A": "Intel", "00:21:6B": "Intel", "00:22:FA": "Intel",
    "00:22:FB": "Intel", "00:23:14": "Intel", "00:23:15": "Intel",
    "00:24:D6": "Intel", "00:24:D7": "Intel",
    # Realtek
    "00:E0:4C": "Realtek", "52:54:00": "Realtek (QEMU)",
    # Broadcom
    "00:10:18": "Broadcom", "00:0A:F7": "Broadcom",
    # Samsung
    "00:07:AB": "Samsung", "00:0D:E5": "Samsung",
    "00:12:47": "Samsung", "00:12:FB": "Samsung",
    "00:15:99": "Samsung", "00:16:32": "Samsung",
    "00:17:C9": "Samsung", "00:17:D5": "Samsung",
    "00:18:AF": "Samsung", "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung", "00:1C:43": "Samsung",
    "00:1D:25": "Samsung", "00:1E:7D": "Samsung",
    "00:1F:CC": "Samsung", "00:21:19": "Samsung",
    "00:21:D1": "Samsung", "00:21:D2": "Samsung",
    "00:23:39": "Samsung", "00:23:3A": "Samsung",
    "00:23:99": "Samsung", "00:23:D6": "Samsung",
    "00:23:D7": "Samsung", "00:24:54": "Samsung",
    "00:24:90": "Samsung", "00:24:91": "Samsung",
    "00:25:66": "Samsung", "00:25:67": "Samsung",
    "00:26:37": "Samsung", "00:26:5D": "Samsung",
    # Printer vendors
    "00:00:48": "Epson", "00:00:74": "Ricoh", "00:00:85": "Canon",
    "00:00:F0": "Samsung (Printer)", "00:01:E6": "Hewlett-Packard (Printer)",
    "00:04:00": "Lexmark", "00:06:0D": "Xerox", "00:15:99": "Samsung",
    "00:17:A4": "HP (Printer)", "00:1B:A9": "Brother",
    "00:80:77": "Brother", "00:80:87": "OKI",
    # Network cameras / NVR
    "00:01:F1": "Axis Communications", "00:40:8C": "Axis Communications",
    "AC:CC:8E": "Axis Communications",
    "00:0F:7C": "ACTi", "00:12:06": "iCanTek",
    "00:80:F0": "Panasonic", "4C:BD:8F": "Hikvision",
    "54:C4:15": "Hikvision", "C0:56:E3": "Hikvision",
    "28:57:BE": "Hangzhou Hikvision",
    "9C:8E:CD": "Amcrest", "E0:50:8B": "Zhejiang Dahua",
    "3C:EF:8C": "Dahua", "A0:BD:1D": "Dahua",
    # VoIP
    "00:04:F2": "Polycom", "00:04:13": "Snom",
    "00:08:5D": "Aastra", "00:09:6E": "HTEK",
    "00:0B:82": "Grandstream", "00:0E:08": "Sipura",
    "00:0F:34": "Cisco (VoIP)", "00:15:65": "Yealink",
    "00:1F:82": "Cal-Comp (VoIP)",
    "80:5E:C0": "Yealink", "80:5E:C0": "Yealink",
    # APC/UPS
    "00:C0:B7": "APC/Schneider", "00:06:23": "MGE UPS Systems",
    "00:20:85": "Eaton",
    # Synology / QNAP (NAS)
    "00:11:32": "Synology", "00:11:32": "Synology",
    "24:5E:BE": "QNAP",
    # IoT / misc
    "00:17:88": "Philips Hue", "B0:CE:18": "Honeywell",
    "00:1A:22": "eQ-3 (Smart Home)", "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs", "D8:EB:46": "Google (Nest)",
    "30:52:CB": "Liteon (IoT)", "44:07:0B": "Google",
    "48:D6:D5": "Google", "54:60:09": "Google",
    "F4:F5:D8": "Google", "F4:F5:E8": "Google",
    # Amazon
    "00:FC:8B": "Amazon", "0C:47:C9": "Amazon",
    "10:CE:A9": "Amazon", "14:91:82": "Amazon",
    "18:74:2E": "Amazon", "34:D2:70": "Amazon",
    "38:F7:3D": "Amazon", "40:B4:CD": "Amazon",
    "44:65:0D": "Amazon", "4C:EF:C0": "Amazon",
    "50:F5:DA": "Amazon", "68:54:FD": "Amazon",
    "68:9C:E2": "Amazon", "74:C2:46": "Amazon",
    "84:D6:D0": "Amazon", "A4:08:EA": "Amazon",
    "AC:63:BE": "Amazon", "B4:7C:9C": "Amazon",
    "F0:27:2D": "Amazon", "F0:D2:F1": "Amazon",
    "FC:65:DE": "Amazon",
}


def lookup_vendor(mac_address: str) -> Optional[str]:
    """Look up the vendor for a MAC address using OUI prefix."""
    if not mac_address:
        return None
    # Normalize MAC: uppercase, colon-separated
    mac_clean = re.sub(r"[^0-9A-Fa-f]", "", mac_address).upper()
    if len(mac_clean) < 6:
        return None
    # Build prefix in XX:XX:XX format
    prefix = f"{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}"
    return _OUI_TABLE.get(prefix)


def normalize_mac(mac: str) -> str:
    """Normalize MAC to uppercase colon-separated format."""
    mac_clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(mac_clean) != 12:
        return mac.upper()
    return ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
