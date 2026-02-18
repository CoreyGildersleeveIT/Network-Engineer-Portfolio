"""
Correlation / Truth Engine.

Merges data from all collectors into unified DeviceRecords.
Each field tracks: value, source(s), timestamp, confidence.

Merge precedence:
- DHCP leases are authoritative for IP<->MAC<->hostname (when present)
- ARP is authoritative for IP<->MAC on local subnet
- DNS is authoritative for hostname<->IP
- SNMP is authoritative for device identity/role/topology
- Port scan results are evidence, not authoritative for identity
- AD is high-confidence for hostname, OS, domain membership
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from .models import (
    ConfidenceLevel, DataSource, DeviceRecord, DeviceRole,
    InfrastructureSummary, PortInfo, SubnetInfo, SwitchPortMapping,
    TrackedField,
)
from .oui import lookup_vendor, normalize_mac
from .role_classifier import classify_device

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Merges data from multiple sources into correlated device records."""

    def __init__(self) -> None:
        self.devices: dict[str, DeviceRecord] = {}  # keyed by IP address
        self._mac_to_ip: dict[str, str] = {}
        self.infrastructure = InfrastructureSummary()
        self.subnets: list[SubnetInfo] = []

    def _get_or_create(self, ip: str) -> DeviceRecord:
        """Get existing device by IP or create new."""
        if ip in self.devices:
            return self.devices[ip]
        device = DeviceRecord()
        device.ip_address.add_evidence(
            ip, DataSource.MANUAL, ConfidenceLevel.HIGH, f"First seen as {ip}"
        )
        self.devices[ip] = device
        return device

    def _find_by_mac(self, mac: str) -> Optional[DeviceRecord]:
        """Find a device by MAC address."""
        mac = normalize_mac(mac)
        ip = self._mac_to_ip.get(mac)
        if ip and ip in self.devices:
            return self.devices[ip]
        for dev in self.devices.values():
            if normalize_mac(dev.mac_address.value or "") == mac:
                return dev
        return None

    # --- Ingest methods for each data source ---

    def ingest_arp_entries(self, entries: list) -> int:
        """Ingest ARP table entries. Authoritative for IP<->MAC on local subnet."""
        count = 0
        for entry in entries:
            ip = entry.ip_address
            mac = normalize_mac(entry.mac_address)
            if not ip or not mac:
                continue

            device = self._get_or_create(ip)
            device.mac_address.add_evidence(
                mac, DataSource.ARP_TABLE, ConfidenceLevel.HIGH,
                f"ARP: {ip} -> {mac} (state={entry.state})"
            )
            device.is_alive.add_evidence(
                True, DataSource.ARP_TABLE, ConfidenceLevel.HIGH,
                "Present in ARP table"
            )
            self._mac_to_ip[mac] = ip

            # OUI vendor lookup
            vendor = lookup_vendor(mac)
            if vendor:
                device.vendor.add_evidence(
                    vendor, DataSource.OUI_LOOKUP, ConfidenceLevel.MEDIUM,
                    f"OUI: {mac[:8]} -> {vendor}"
                )
            count += 1
        logger.info("Ingested %d ARP entries", count)
        return count

    def ingest_dhcp_leases(self, leases: list, source_server: str = "") -> int:
        """Ingest DHCP lease data. Authoritative for IP<->MAC<->hostname."""
        count = 0
        for lease in leases:
            ip = str(lease.ip_address)
            mac = normalize_mac(str(lease.mac_address))
            hostname = lease.hostname or ""

            if not ip:
                continue

            device = self._get_or_create(ip)
            if mac:
                device.mac_address.add_evidence(
                    mac, DataSource.DHCP_LEASE, ConfidenceLevel.AUTHORITATIVE,
                    f"DHCP lease from {source_server}: {ip} -> {mac}"
                )
                self._mac_to_ip[mac] = ip
                vendor = lookup_vendor(mac)
                if vendor:
                    device.vendor.add_evidence(
                        vendor, DataSource.OUI_LOOKUP, ConfidenceLevel.MEDIUM,
                        f"OUI: {mac[:8]} -> {vendor}"
                    )

            if hostname:
                device.hostname.add_evidence(
                    hostname, DataSource.DHCP_LEASE, ConfidenceLevel.AUTHORITATIVE,
                    f"DHCP lease hostname: {hostname}"
                )

            device.ip_assignment.add_evidence(
                "dhcp", DataSource.DHCP_LEASE, ConfidenceLevel.AUTHORITATIVE,
                f"Active DHCP lease from {source_server}"
            )
            device.is_alive.add_evidence(
                True, DataSource.DHCP_LEASE, ConfidenceLevel.HIGH,
                "Active DHCP lease"
            )

            if hasattr(lease, 'lease_expiry'):
                device.dhcp_lease_expiry = str(lease.lease_expiry)
            if hasattr(lease, 'scope_id'):
                device.dhcp_scope_id = str(lease.scope_id)

            count += 1
        logger.info("Ingested %d DHCP leases from %s", count, source_server)
        return count

    def ingest_dhcp_reservations(self, reservations: list, source_server: str = "") -> int:
        """Ingest DHCP reservations."""
        count = 0
        for res in reservations:
            ip = str(res.ip_address)
            mac = normalize_mac(str(res.mac_address))
            name = getattr(res, 'name', '') or ""

            if not ip:
                continue

            device = self._get_or_create(ip)
            if mac:
                device.mac_address.add_evidence(
                    mac, DataSource.DHCP_RESERVATION, ConfidenceLevel.AUTHORITATIVE,
                    f"DHCP reservation: {ip} -> {mac}"
                )
                self._mac_to_ip[mac] = ip
                vendor = lookup_vendor(mac)
                if vendor:
                    device.vendor.add_evidence(
                        vendor, DataSource.OUI_LOOKUP, ConfidenceLevel.MEDIUM,
                        f"OUI: {mac[:8]} -> {vendor}"
                    )

            if name:
                device.hostname.add_evidence(
                    name, DataSource.DHCP_RESERVATION, ConfidenceLevel.HIGH,
                    f"DHCP reservation name: {name}"
                )

            device.ip_assignment.add_evidence(
                "dhcp_reservation", DataSource.DHCP_RESERVATION,
                ConfidenceLevel.AUTHORITATIVE,
                f"DHCP reservation on {source_server}"
            )
            count += 1
        logger.info("Ingested %d DHCP reservations", count)
        return count

    def ingest_dns_results(self, dns_map: dict[str, str], is_reverse: bool = True) -> int:
        """Ingest DNS resolution results."""
        count = 0
        for key, value in dns_map.items():
            if is_reverse:
                ip, hostname = key, value
            else:
                hostname, ip = key, value

            if ip in self.devices:
                device = self.devices[ip]
            else:
                continue

            source = DataSource.DNS_REVERSE if is_reverse else DataSource.DNS_FORWARD
            device.dns_name.add_evidence(
                hostname, source, ConfidenceLevel.HIGH,
                f"DNS {'PTR' if is_reverse else 'A'}: {key} -> {value}"
            )
            if not device.hostname.value:
                device.hostname.add_evidence(
                    hostname.split(".")[0], source, ConfidenceLevel.MEDIUM,
                    f"Hostname from DNS: {hostname}"
                )
            count += 1
        logger.info("Ingested %d DNS results", count)
        return count

    def ingest_ping_results(self, alive_ips: set[str]) -> int:
        """Ingest ICMP ping results."""
        count = 0
        for ip in alive_ips:
            device = self._get_or_create(ip)
            device.is_alive.add_evidence(
                True, DataSource.ICMP_PING, ConfidenceLevel.HIGH,
                "Responded to ICMP ping"
            )
            count += 1
        logger.info("Ingested %d ping results", count)
        return count

    def ingest_port_results(self, ip: str, ports: list[PortInfo]) -> None:
        """Ingest port scan results for a specific IP."""
        device = self._get_or_create(ip)
        device.is_alive.add_evidence(
            True, DataSource.PORT_SCAN, ConfidenceLevel.HIGH,
            f"Open ports found: {len(ports)}"
        )
        for port in ports:
            existing = [p for p in device.open_ports if p.port == port.port
                        and p.protocol == port.protocol]
            if existing:
                ep = existing[0]
                if port.banner and not ep.banner:
                    ep.banner = port.banner
                if port.service and not ep.service:
                    ep.service = port.service
                if port.http_server and not ep.http_server:
                    ep.http_server = port.http_server
                if port.http_title and not ep.http_title:
                    ep.http_title = port.http_title
                if port.tls_subject and not ep.tls_subject:
                    ep.tls_subject = port.tls_subject
                    ep.tls_issuer = port.tls_issuer
                    ep.tls_expiry = port.tls_expiry
            else:
                device.open_ports.append(port)

        # OS hints from banners
        for port in ports:
            if port.http_server:
                if "microsoft" in port.http_server.lower() or "iis" in port.http_server.lower():
                    device.os_hint.add_evidence(
                        "Windows", DataSource.HTTP_BANNER, ConfidenceLevel.MEDIUM,
                        f"HTTP Server: {port.http_server}"
                    )
                elif "apache" in port.http_server.lower() or "nginx" in port.http_server.lower():
                    device.os_hint.add_evidence(
                        "Linux/Unix", DataSource.HTTP_BANNER, ConfidenceLevel.LOW,
                        f"HTTP Server: {port.http_server}"
                    )
            if port.banner and port.port == 22:
                if "ubuntu" in port.banner.lower():
                    device.os_hint.add_evidence(
                        "Ubuntu Linux", DataSource.SSH_BANNER, ConfidenceLevel.MEDIUM,
                        f"SSH: {port.banner}"
                    )
                elif "debian" in port.banner.lower():
                    device.os_hint.add_evidence(
                        "Debian Linux", DataSource.SSH_BANNER, ConfidenceLevel.MEDIUM,
                        f"SSH: {port.banner}"
                    )

    def ingest_snmp_data(self, snmp_data) -> None:
        """Ingest SNMP collected data."""
        if not snmp_data.reachable:
            return

        ip = snmp_data.ip_address
        device = self._get_or_create(ip)
        device.is_alive.add_evidence(
            True, DataSource.SNMP_SYSTEM, ConfidenceLevel.HIGH,
            "SNMP reachable"
        )

        si = snmp_data.system_info
        if si.sys_name:
            device.hostname.add_evidence(
                si.sys_name, DataSource.SNMP_SYSTEM, ConfidenceLevel.HIGH,
                f"SNMP sysName: {si.sys_name}"
            )
        device.snmp_sys_descr = si.sys_descr
        device.snmp_sys_name = si.sys_name
        device.snmp_sys_object_id = si.sys_object_id
        device.snmp_uptime = si.sys_uptime

        if si.sys_descr:
            device.os_hint.add_evidence(
                si.sys_descr[:200], DataSource.SNMP_SYSTEM, ConfidenceLevel.HIGH,
                f"SNMP sysDescr: {si.sys_descr[:200]}"
            )

        device.snmp_interfaces = [
            {"index": i.index, "name": i.name, "description": i.description,
             "speed": i.speed, "status": i.oper_status}
            for i in snmp_data.interfaces
        ]

        device.lldp_neighbors = [
            {"local_port": n.local_port, "remote_sys_name": n.remote_sys_name,
             "remote_port": n.remote_port_id, "remote_desc": n.remote_sys_desc,
             "mgmt_addr": n.remote_mgmt_addr}
            for n in snmp_data.lldp_neighbors
        ]

        device.cdp_neighbors = [
            {"device_id": n.device_id, "device_port": n.device_port,
             "address": n.device_address, "platform": n.platform}
            for n in snmp_data.cdp_neighbors
        ]

    def ingest_ad_computers(self, computers: list) -> int:
        """Ingest Active Directory computer records."""
        count = 0
        for comp in computers:
            ip = comp.ipv4_address
            if not ip:
                if comp.dns_hostname:
                    import socket
                    try:
                        ip = socket.gethostbyname(comp.dns_hostname)
                    except Exception:
                        continue
                else:
                    continue

            device = self._get_or_create(ip)
            if comp.dns_hostname:
                device.dns_name.add_evidence(
                    comp.dns_hostname, DataSource.AD_COMPUTER, ConfidenceLevel.HIGH,
                    f"AD computer: {comp.dns_hostname}"
                )
                device.hostname.add_evidence(
                    comp.name, DataSource.AD_COMPUTER, ConfidenceLevel.HIGH,
                    f"AD sAMAccountName: {comp.name}"
                )
            if comp.operating_system:
                device.os_hint.add_evidence(
                    comp.operating_system, DataSource.AD_COMPUTER, ConfidenceLevel.HIGH,
                    f"AD OS: {comp.operating_system}"
                )
                device.ad_os = comp.operating_system
            if comp.last_logon:
                device.ad_last_logon = comp.last_logon
            if comp.distinguished_name:
                device.ad_dn = comp.distinguished_name
                dn_parts = comp.distinguished_name.split(",")
                for part in dn_parts:
                    if part.strip().upper().startswith("DC="):
                        domain_parts = [p.split("=")[1] for p in dn_parts
                                        if p.strip().upper().startswith("DC=")]
                        device.domain.add_evidence(
                            ".".join(domain_parts), DataSource.AD_COMPUTER,
                            ConfidenceLevel.HIGH,
                            f"AD DN: {comp.distinguished_name}"
                        )
                        break
            count += 1
        logger.info("Ingested %d AD computers", count)
        return count

    def ingest_dhcp_offers(self, offers: list) -> None:
        """Ingest DHCP offer data for infrastructure summary."""
        for offer in offers:
            self.infrastructure.dhcp_servers.append({
                "ip": offer.server_ip,
                "offered_ip": offer.offered_ip,
                "subnet_mask": offer.subnet_mask,
                "router": offer.router,
                "dns_servers": offer.dns_servers,
                "domain_name": offer.domain_name,
                "lease_time": offer.lease_time,
                "source": "dhcp_discover",
            })
            if offer.router:
                gw = {"ip": offer.router, "source": "dhcp_option_003"}
                if gw not in self.infrastructure.gateways:
                    self.infrastructure.gateways.append(gw)
            for dns in offer.dns_servers:
                entry = {"ip": dns, "source": "dhcp_option_006"}
                if entry not in self.infrastructure.dns_servers:
                    self.infrastructure.dns_servers.append(entry)
            for ntp in offer.ntp_servers:
                if ntp not in self.infrastructure.ntp_servers:
                    self.infrastructure.ntp_servers.append(ntp)

        servers = set(o.server_ip for o in offers)
        if len(servers) > 1:
            self.infrastructure.rogue_dhcp_detected = True
            self.infrastructure.rogue_dhcp_details = [
                {"server_ip": o.server_ip, "offered_ip": o.offered_ip}
                for o in offers
            ]

    def ingest_fdb_mappings(self, switch_ip: str, switch_name: str,
                            fdb_entries: list, if_names: dict[int, str]) -> int:
        """Map FDB entries to device records (MAC -> switch port)."""
        count = 0
        for entry in fdb_entries:
            mac = normalize_mac(entry.mac_address)
            device = self._find_by_mac(mac)
            if device:
                port_name = if_names.get(entry.if_index, f"port{entry.port_index}")
                device.switch_port = SwitchPortMapping(
                    switch_ip=switch_ip,
                    switch_name=switch_name,
                    port_name=port_name,
                    port_index=entry.port_index,
                    vlan_id=entry.vlan_id,
                    source=DataSource.SNMP_FDB,
                )
                count += 1
        logger.info("Mapped %d FDB entries for switch %s", count, switch_name)
        return count

    # --- Finalize ---

    def classify_all_roles(self) -> None:
        """Run role classification on all devices."""
        for device in self.devices.values():
            role = classify_device(device)
            if role != DeviceRole.UNKNOWN:
                device.device_role.add_evidence(
                    role, DataSource.MANUAL, ConfidenceLevel.MEDIUM,
                    f"Rule-based classification: {role.value}"
                )

        # Mark IPs without DHCP leases as potentially static
        for device in self.devices.values():
            if (device.ip_assignment.value == "unknown"
                    and device.is_alive.value):
                device.ip_assignment.add_evidence(
                    "likely_static", DataSource.MANUAL, ConfidenceLevel.LOW,
                    "No DHCP lease found - may be statically assigned"
                )

    def build_infrastructure_summary(self) -> InfrastructureSummary:
        """Build the final infrastructure summary."""
        infra = self.infrastructure
        infra.total_devices = len(self.devices)
        infra.total_alive = sum(
            1 for d in self.devices.values() if d.is_alive.value
        )
        infra.total_with_snmp = sum(
            1 for d in self.devices.values() if d.snmp_sys_descr
        )
        infra.total_switches = sum(
            1 for d in self.devices.values()
            if isinstance(d.device_role.value, DeviceRole)
            and d.device_role.value == DeviceRole.SWITCH
        )
        infra.total_aps = sum(
            1 for d in self.devices.values()
            if isinstance(d.device_role.value, DeviceRole)
            and d.device_role.value == DeviceRole.ACCESS_POINT
        )

        # Add subnet info
        infra.subnets = [
            {
                "network": s.network, "gateway": s.gateway,
                "dhcp_server": s.dhcp_server, "vlan_id": s.vlan_id,
                "active_hosts": s.active_hosts, "utilization_pct": s.utilization_pct,
            }
            for s in self.subnets
        ]

        return infra

    def get_all_device_dicts(self) -> list[dict]:
        """Get all devices as dictionaries."""
        return [d.to_dict() for d in self.devices.values()]

    def get_all_device_flat(self) -> list[dict]:
        """Get all devices as flat dictionaries for CSV."""
        return [d.to_flat_dict() for d in self.devices.values()]
