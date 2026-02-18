"""
Data models for the Network Scanner & Mapper.

Every field tracks: value, source(s), timestamp, confidence.
The correlation engine merges records using these tracked fields.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Optional


class DataSource(Enum):
    """Where a piece of data originated."""
    DHCP_LEASE = "dhcp_lease"
    DHCP_SCOPE = "dhcp_scope"
    DHCP_RESERVATION = "dhcp_reservation"
    DHCP_OFFER = "dhcp_offer"
    ARP_TABLE = "arp_table"
    NDP_TABLE = "ndp_table"
    DNS_FORWARD = "dns_forward"
    DNS_REVERSE = "dns_reverse"
    ICMP_PING = "icmp_ping"
    TCP_PROBE = "tcp_probe"
    PORT_SCAN = "port_scan"
    HTTP_BANNER = "http_banner"
    HTTPS_BANNER = "https_banner"
    SSH_BANNER = "ssh_banner"
    SMB_AUTH = "smb_auth"
    RDP_PROBE = "rdp_probe"
    SNMP_SYSTEM = "snmp_system"
    SNMP_INTERFACES = "snmp_interfaces"
    SNMP_LLDP = "snmp_lldp"
    SNMP_CDP = "snmp_cdp"
    SNMP_FDB = "snmp_fdb"
    SNMP_ARP = "snmp_arp"
    SNMP_VLAN = "snmp_vlan"
    AD_COMPUTER = "ad_computer"
    AD_DC = "ad_dc"
    OUI_LOOKUP = "oui_lookup"
    NETBIOS = "netbios"
    MDNS = "mdns"
    LOCAL_NIC = "local_nic"
    LOCAL_ROUTE = "local_route"
    NMAP = "nmap"
    TLS_CERT = "tls_cert"
    MANUAL = "manual"


class DeviceRole(Enum):
    """Inferred device role (rule-based, no AI)."""
    UNKNOWN = "unknown"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    SERVER = "server"
    DOMAIN_CONTROLLER = "domain_controller"
    DHCP_SERVER = "dhcp_server"
    DNS_SERVER = "dns_server"
    PRINTER = "printer"
    CAMERA = "camera"
    NVR = "nvr"
    VOIP_PHONE = "voip_phone"
    ENDPOINT = "endpoint"
    IOT = "iot"
    NAS = "nas"
    UPS = "ups"
    HYPERVISOR = "hypervisor"


class ScanIntensity(Enum):
    """Scan intensity presets."""
    QUICK = "quick"
    NORMAL = "normal"
    DEEP = "deep_after_hours"


class ConfidenceLevel(Enum):
    """Confidence rating for a data point."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    AUTHORITATIVE = 4


@dataclass
class TrackedField:
    """A single data field with provenance tracking."""
    value: Any
    sources: list[DataSource] = field(default_factory=list)
    timestamps: list[datetime] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    raw_evidence: list[str] = field(default_factory=list)

    def add_evidence(self, value: Any, source: DataSource,
                     confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM,
                     evidence: str = "") -> None:
        if value is not None:
            self.value = value
            if source not in self.sources:
                self.sources.append(source)
            self.timestamps.append(datetime.now())
            if confidence.value > self.confidence.value:
                self.confidence = confidence
            if evidence:
                self.raw_evidence.append(evidence)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "sources": [s.value for s in self.sources],
            "confidence": self.confidence.name,
            "evidence": self.raw_evidence,
        }


@dataclass
class PortInfo:
    """Information about an open port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    banner: str = ""
    version: str = ""
    source: DataSource = DataSource.PORT_SCAN
    tls_subject: str = ""
    tls_issuer: str = ""
    tls_expiry: str = ""
    http_status: int = 0
    http_server: str = ""
    http_title: str = ""


@dataclass
class SwitchPortMapping:
    """Maps a MAC address to a physical switch port."""
    switch_ip: str = ""
    switch_name: str = ""
    port_name: str = ""
    port_index: int = 0
    vlan_id: int = 0
    vlan_name: str = ""
    source: DataSource = DataSource.SNMP_FDB


@dataclass
class DeviceRecord:
    """Full device record with tracked fields and evidence."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    mac_address: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    vendor: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    hostname: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    dns_name: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    netbios_name: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    os_hint: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    device_role: TrackedField = field(default_factory=lambda: TrackedField(value=DeviceRole.UNKNOWN))
    is_alive: TrackedField = field(default_factory=lambda: TrackedField(value=False))
    ip_assignment: TrackedField = field(default_factory=lambda: TrackedField(value="unknown"))  # static/dhcp
    domain: TrackedField = field(default_factory=lambda: TrackedField(value=""))
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)

    # Detailed collections
    open_ports: list[PortInfo] = field(default_factory=list)
    switch_port: Optional[SwitchPortMapping] = None
    snmp_sys_descr: str = ""
    snmp_sys_name: str = ""
    snmp_sys_object_id: str = ""
    snmp_uptime: str = ""
    snmp_interfaces: list[dict] = field(default_factory=list)
    lldp_neighbors: list[dict] = field(default_factory=list)
    cdp_neighbors: list[dict] = field(default_factory=list)

    # AD correlation
    ad_os: str = ""
    ad_last_logon: str = ""
    ad_dn: str = ""

    # DHCP correlation
    dhcp_lease_expiry: str = ""
    dhcp_scope_id: str = ""

    # IPv6
    ipv6_addresses: list[str] = field(default_factory=list)

    @property
    def overall_confidence(self) -> float:
        """Compute weighted average confidence across tracked fields."""
        tracked = [
            self.ip_address, self.mac_address, self.vendor,
            self.hostname, self.dns_name, self.os_hint, self.device_role,
        ]
        weights = [3, 3, 1, 2, 2, 1, 1]
        total_w = 0
        total_score = 0
        for tf, w in zip(tracked, weights):
            if tf.value and tf.value != "" and tf.value != DeviceRole.UNKNOWN:
                total_score += tf.confidence.value * w
                total_w += w * 4  # max confidence is 4
        return round(total_score / total_w, 2) if total_w > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip_address": self.ip_address.to_dict(),
            "mac_address": self.mac_address.to_dict(),
            "vendor": self.vendor.to_dict(),
            "hostname": self.hostname.to_dict(),
            "dns_name": self.dns_name.to_dict(),
            "netbios_name": self.netbios_name.to_dict(),
            "os_hint": self.os_hint.to_dict(),
            "device_role": {
                "value": self.device_role.value.value
                if isinstance(self.device_role.value, DeviceRole) else str(self.device_role.value),
                "sources": [s.value for s in self.device_role.sources],
                "confidence": self.device_role.confidence.name,
            },
            "is_alive": self.is_alive.to_dict(),
            "ip_assignment": self.ip_assignment.to_dict(),
            "domain": self.domain.to_dict(),
            "open_ports": [
                {"port": p.port, "protocol": p.protocol, "service": p.service,
                 "banner": p.banner, "version": p.version}
                for p in self.open_ports
            ],
            "switch_port": {
                "switch_ip": self.switch_port.switch_ip,
                "switch_name": self.switch_port.switch_name,
                "port_name": self.switch_port.port_name,
                "vlan_id": self.switch_port.vlan_id,
            } if self.switch_port else None,
            "snmp_sys_descr": self.snmp_sys_descr,
            "overall_confidence": self.overall_confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

    def to_flat_dict(self) -> dict:
        """Flat dictionary for CSV export."""
        role = self.device_role.value
        if isinstance(role, DeviceRole):
            role = role.value
        return {
            "id": self.id,
            "ip_address": self.ip_address.value,
            "mac_address": self.mac_address.value,
            "vendor": self.vendor.value,
            "hostname": self.hostname.value,
            "dns_name": self.dns_name.value,
            "netbios_name": self.netbios_name.value,
            "os_hint": self.os_hint.value,
            "device_role": role,
            "is_alive": self.is_alive.value,
            "ip_assignment": self.ip_assignment.value,
            "domain": self.domain.value,
            "open_ports": ";".join(
                f"{p.port}/{p.protocol}({p.service})" for p in self.open_ports
            ),
            "switch_port": (
                f"{self.switch_port.switch_name}:{self.switch_port.port_name}"
                if self.switch_port else ""
            ),
            "overall_confidence": self.overall_confidence,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


@dataclass
class SubnetInfo:
    """Discovered subnet information."""
    network: str = ""  # CIDR notation
    gateway: str = ""
    dhcp_server: str = ""
    dns_servers: list[str] = field(default_factory=list)
    domain_name: str = ""
    vlan_id: int = 0
    vlan_name: str = ""
    total_hosts: int = 0
    active_hosts: int = 0
    dhcp_range_start: str = ""
    dhcp_range_end: str = ""
    utilization_pct: float = 0.0
    source: DataSource = DataSource.LOCAL_NIC


@dataclass
class InfrastructureSummary:
    """Summary of discovered network infrastructure."""
    scan_id: str = ""
    scan_start: str = ""
    scan_end: str = ""
    scanner_hostname: str = ""
    scanner_ip: str = ""

    dhcp_servers: list[dict] = field(default_factory=list)
    dns_servers: list[dict] = field(default_factory=list)
    domain_controllers: list[dict] = field(default_factory=list)
    gateways: list[dict] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)
    subnets: list[dict] = field(default_factory=list)

    rogue_dhcp_detected: bool = False
    rogue_dhcp_details: list[dict] = field(default_factory=list)

    total_devices: int = 0
    total_alive: int = 0
    total_with_snmp: int = 0
    total_switches: int = 0
    total_aps: int = 0

    data_sources_used: list[str] = field(default_factory=list)
    data_source_success: dict = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_info": {
                "scan_id": self.scan_id,
                "scan_start": self.scan_start,
                "scan_end": self.scan_end,
                "scanner_hostname": self.scanner_hostname,
                "scanner_ip": self.scanner_ip,
            },
            "dhcp_servers": self.dhcp_servers,
            "dns_servers": self.dns_servers,
            "domain_controllers": self.domain_controllers,
            "gateways": self.gateways,
            "ntp_servers": self.ntp_servers,
            "subnets": self.subnets,
            "rogue_dhcp": {
                "detected": self.rogue_dhcp_detected,
                "details": self.rogue_dhcp_details,
            },
            "totals": {
                "total_devices": self.total_devices,
                "total_alive": self.total_alive,
                "total_with_snmp": self.total_with_snmp,
                "total_switches": self.total_switches,
                "total_aps": self.total_aps,
            },
            "data_quality": {
                "sources_used": self.data_sources_used,
                "source_success": self.data_source_success,
                "limitations": self.limitations,
            },
        }


@dataclass
class ScanProfile:
    """Saved scan profile / site configuration."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    created: str = field(default_factory=lambda: datetime.now().isoformat())
    modified: str = field(default_factory=lambda: datetime.now().isoformat())

    # Target selection
    target_mode: str = "auto"  # auto / dhcp_scopes / manual
    manual_targets: list[str] = field(default_factory=list)  # CIDRs
    exclude_targets: list[str] = field(default_factory=list)
    skip_high_risk: bool = True

    # Scan settings
    intensity: str = ScanIntensity.NORMAL.value
    icmp_concurrency: int = 100
    tcp_concurrency: int = 50
    snmp_concurrency: int = 20
    timeout_ms: int = 2000
    retries: int = 1
    max_errors_before_stop: int = 500
    scan_only_alive: bool = True
    include_ipv6: bool = False
    enable_nmap: bool = False
    enable_zone_enum: bool = False

    # Port selection
    port_list: str = "default"  # default / extended / custom
    custom_ports: list[int] = field(default_factory=list)

    # Credential references (IDs, not secrets)
    credential_ids: list[str] = field(default_factory=list)

    # SNMP settings
    snmp_enabled: bool = False
    snmp_version: str = "2c"  # 2c / 3

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created": self.created,
            "modified": self.modified,
            "target_mode": self.target_mode,
            "manual_targets": self.manual_targets,
            "exclude_targets": self.exclude_targets,
            "skip_high_risk": self.skip_high_risk,
            "intensity": self.intensity,
            "icmp_concurrency": self.icmp_concurrency,
            "tcp_concurrency": self.tcp_concurrency,
            "snmp_concurrency": self.snmp_concurrency,
            "timeout_ms": self.timeout_ms,
            "retries": self.retries,
            "max_errors_before_stop": self.max_errors_before_stop,
            "scan_only_alive": self.scan_only_alive,
            "include_ipv6": self.include_ipv6,
            "enable_nmap": self.enable_nmap,
            "enable_zone_enum": self.enable_zone_enum,
            "port_list": self.port_list,
            "custom_ports": self.custom_ports,
            "credential_ids": self.credential_ids,
            "snmp_enabled": self.snmp_enabled,
            "snmp_version": self.snmp_version,
        }


@dataclass
class CredentialEntry:
    """Credential reference (no secrets stored in memory beyond initial use)."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cred_type: str = ""  # domain, snmp_v2c, snmp_v3, ssh, local_admin
    username: str = ""  # stored plaintext (non-secret)
    domain: str = ""
    # Secret is stored in Windows Credential Manager or encrypted DPAPI blob
    # This field is only populated transiently during entry, then cleared
    secret_ref: str = ""  # reference key in credential store
    snmp_community: str = ""  # for SNMPv2c (stored encrypted)
    snmp_auth_protocol: str = ""  # MD5/SHA for v3
    snmp_priv_protocol: str = ""  # DES/AES for v3
    created: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "cred_type": self.cred_type,
            "username": self.username,
            "domain": self.domain,
            "secret_ref": self.secret_ref,
            "created": self.created,
        }


# Default port lists
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143,
    161, 162, 389, 443, 445, 465, 554, 587, 636, 993, 995,
    1433, 1521, 2049, 3268, 3306, 3389, 5060, 5061, 5432,
    5900, 5985, 5986, 8000, 8080, 8443, 9100,
]

EXTENDED_PORTS = DEFAULT_PORTS + [
    69, 111, 137, 138, 179, 199, 427, 500, 514, 515, 520,
    548, 623, 631, 902, 1080, 1194, 1434, 1723, 1883,
    2000, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3260,
    3478, 3479, 4443, 4444, 4500, 4786, 4848, 5000, 5001,
    5004, 5005, 5050, 5353, 5500, 5632, 5672, 5800, 5901,
    6000, 6379, 6443, 6514, 6667, 7443, 7547, 8001, 8008,
    8081, 8088, 8181, 8291, 8443, 8444, 8445, 8888, 8899,
    9000, 9001, 9090, 9091, 9200, 9443, 9999, 10000,
    11211, 27017, 49152,
]
