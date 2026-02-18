"""
Rule-based device role classification.
No AI/ML - uses deterministic rules based on open ports,
SNMP data, vendor, banners, and OS hints.
"""

from __future__ import annotations

from typing import Optional

from .models import DeviceRecord, DeviceRole, PortInfo


def classify_device(device: DeviceRecord) -> DeviceRole:
    """
    Classify a device role based on available evidence.
    Returns the most likely role using rule precedence.
    """
    # Collect evidence
    ports = {p.port for p in device.open_ports}
    port_services = {p.service.lower() for p in device.open_ports if p.service}
    vendor = (device.vendor.value or "").lower()
    hostname = (device.hostname.value or "").lower()
    dns_name = (device.dns_name.value or "").lower()
    os_hint = (device.os_hint.value or "").lower()
    sys_descr = (device.snmp_sys_descr or "").lower()
    sys_oid = device.snmp_sys_object_id or ""
    banners = _collect_banners(device)

    # Rule 1: SNMP-identified network equipment
    if sys_descr:
        if any(kw in sys_descr for kw in ("cisco ios", "cisco nx-os", "cisco adaptive",
                                            "junos", "juniper", "arista eos",
                                            "extreme", "brocade")):
            if "adaptive" in sys_descr or "asa" in sys_descr or "firewall" in sys_descr:
                return DeviceRole.FIREWALL
            if "switch" in sys_descr or "catalyst" in sys_descr:
                return DeviceRole.SWITCH
            if "router" in sys_descr or "isr" in sys_descr or "asr" in sys_descr:
                return DeviceRole.ROUTER
            # Default Cisco/Juniper to switch
            return DeviceRole.SWITCH

        if any(kw in sys_descr for kw in ("fortigate", "fortios")):
            return DeviceRole.FIREWALL
        if any(kw in sys_descr for kw in ("palo alto", "pan-os")):
            return DeviceRole.FIREWALL
        if any(kw in sys_descr for kw in ("sonicwall", "sonic")):
            return DeviceRole.FIREWALL
        if "pfsense" in sys_descr or "opnsense" in sys_descr:
            return DeviceRole.FIREWALL

        if any(kw in sys_descr for kw in ("access point", "wireless", "aironet",
                                            "aruba ap", "unifi ap", "ruckus")):
            return DeviceRole.ACCESS_POINT

        if any(kw in sys_descr for kw in ("synology", "qnap", "readynas", "netgear readynas")):
            return DeviceRole.NAS

        if any(kw in sys_descr for kw in ("apc ", "ups ", "schneider", "eaton", "liebert")):
            return DeviceRole.UPS

    # Rule 2: Vendor-based network equipment
    if vendor:
        if any(v in vendor for v in ("ubiquiti", "unifi")):
            if device.lldp_neighbors or device.cdp_neighbors:
                return DeviceRole.SWITCH
            return DeviceRole.ACCESS_POINT  # Ubiquiti is usually APs
        if any(v in vendor for v in ("ruckus", "aruba")):
            return DeviceRole.ACCESS_POINT
        if "meraki" in vendor:
            if 8443 in ports or any("meraki" in b and "switch" in b for b in banners):
                return DeviceRole.SWITCH
            return DeviceRole.ACCESS_POINT

    # Rule 3: Firewall patterns
    if any(v in vendor for v in ("fortinet", "palo alto", "sonicwall", "watchguard")):
        return DeviceRole.FIREWALL

    # Rule 4: Domain Controller (port 88 + 389 + 445 + 53)
    dc_ports = {88, 389, 445, 53, 636, 3268}
    if len(ports & dc_ports) >= 4:
        return DeviceRole.DOMAIN_CONTROLLER

    # Rule 5: Printer
    if 9100 in ports or 515 in ports or 631 in ports:
        return DeviceRole.PRINTER
    if any(v in vendor for v in ("hp (printer)", "hewlett-packard (printer)",
                                  "brother", "epson", "canon", "ricoh",
                                  "lexmark", "xerox", "oki", "samsung (printer)")):
        return DeviceRole.PRINTER
    if "printer" in hostname or "printer" in dns_name:
        return DeviceRole.PRINTER

    # Rule 6: Camera / NVR
    if 554 in ports:  # RTSP
        if any(v in vendor for v in ("hikvision", "dahua", "axis", "amcrest",
                                      "acti", "icantek")):
            return DeviceRole.CAMERA
        # Could be NVR if it has many RTSP streams or management ports
        if 8000 in ports or 37777 in ports:
            return DeviceRole.NVR
        return DeviceRole.CAMERA
    if any(v in vendor for v in ("hikvision", "dahua", "axis", "amcrest")):
        return DeviceRole.CAMERA

    # Rule 7: VoIP phone
    if 5060 in ports or 5061 in ports:
        return DeviceRole.VOIP_PHONE
    if any(v in vendor for v in ("polycom", "yealink", "grandstream", "snom",
                                  "aastra", "htek", "cisco (voip)")):
        return DeviceRole.VOIP_PHONE

    # Rule 8: Hypervisor
    if "esxi" in os_hint or "vmware" in os_hint or "hyper-v" in os_hint:
        return DeviceRole.HYPERVISOR
    if "vmware" in vendor and (443 in ports or 902 in ports):
        return DeviceRole.HYPERVISOR

    # Rule 9: UPS
    if any(v in vendor for v in ("apc", "schneider", "eaton")):
        return DeviceRole.UPS

    # Rule 10: NAS
    if any(v in vendor for v in ("synology", "qnap")):
        return DeviceRole.NAS

    # Rule 11: IoT
    if any(v in vendor for v in ("philips hue", "nest", "honeywell", "smart home",
                                  "eq-3")):
        return DeviceRole.IOT
    if any(v in vendor for v in ("amazon",)) and not (445 in ports or 3389 in ports):
        return DeviceRole.IOT

    # Rule 12: Router (gateway IP or routing-related ports)
    if 179 in ports:  # BGP
        return DeviceRole.ROUTER

    # Rule 13: Server (many service ports open)
    server_ports = {22, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                    1433, 1521, 3306, 5432, 8080, 8443}
    if len(ports & server_ports) >= 3:
        return DeviceRole.SERVER
    if "server" in os_hint:
        return DeviceRole.SERVER
    if "server" in hostname or "srv" in hostname:
        return DeviceRole.SERVER

    # Rule 14: Endpoint (Windows workstation indicators)
    if 3389 in ports and 445 in ports and len(ports) < 8:
        return DeviceRole.ENDPOINT
    if "windows" in os_hint and "server" not in os_hint:
        return DeviceRole.ENDPOINT

    # Rule 15: Switch (LLDP/CDP neighbors present)
    if device.lldp_neighbors or device.cdp_neighbors:
        return DeviceRole.SWITCH

    return DeviceRole.UNKNOWN


def _collect_banners(device: DeviceRecord) -> list[str]:
    """Collect all banner strings from port info."""
    banners = []
    for p in device.open_ports:
        if p.banner:
            banners.append(p.banner.lower())
        if p.http_server:
            banners.append(p.http_server.lower())
        if p.http_title:
            banners.append(p.http_title.lower())
    return banners
