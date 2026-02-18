"""
Scan orchestrator / engine.
Coordinates all collectors, manages concurrency, and drives
the correlation engine. Emits progress signals for the GUI.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Optional

from .config import AppSettings
from .correlation import CorrelationEngine
from .database import Database
from .models import (
    DEFAULT_PORTS, EXTENDED_PORTS, DataSource, InfrastructureSummary,
    PortInfo, ScanIntensity, ScanProfile,
)

logger = logging.getLogger(__name__)


class ScanEngine:
    """
    Main scan orchestrator.
    Runs collectors in sequence/parallel and feeds results to correlation engine.
    """

    def __init__(self, profile: ScanProfile, db: Database,
                 credentials: Optional[dict] = None,
                 progress_callback: Optional[Callable] = None,
                 log_callback: Optional[Callable] = None) -> None:
        self.profile = profile
        self.db = db
        self.credentials = credentials or {}
        self._progress = progress_callback or (lambda *a: None)
        self._log = log_callback or (lambda msg: logger.info(msg))
        self.correlation = CorrelationEngine()
        self.session_id = ""
        self._cancelled = False
        self._errors = 0
        self._max_errors = profile.max_errors_before_stop

    def cancel(self) -> None:
        self._cancelled = True

    def _check_cancel(self) -> None:
        if self._cancelled:
            raise ScanCancelled("Scan cancelled by user")

    def _emit(self, phase: str, current: int, total: int, detail: str = "") -> None:
        self._progress(phase, current, total, detail)

    def _record_error(self) -> bool:
        self._errors += 1
        if self._errors >= self._max_errors:
            self._log(f"Max errors ({self._max_errors}) reached, stopping scan")
            return True
        return False

    async def run(self) -> str:
        """Execute the full scan. Returns session_id."""
        start_time = datetime.now()
        hostname = socket.gethostname()
        scanner_ip = ""

        self._log(f"=== Scan starting: {self.profile.name} ===")
        self._log(f"Intensity: {self.profile.intensity}")

        # Create DB session
        self.session_id = self.db.create_scan_session(
            self.profile.id, self.profile.name, hostname, scanner_ip,
        )
        self.correlation.infrastructure.scan_id = self.session_id
        self.correlation.infrastructure.scan_start = start_time.isoformat()
        self.correlation.infrastructure.scanner_hostname = hostname

        try:
            # Phase 1: Local context
            await self._phase_local_context()
            self._check_cancel()

            # Phase 2: DHCP discovery
            await self._phase_dhcp_discovery()
            self._check_cancel()

            # Phase 3: Target enumeration
            targets = await self._phase_enumerate_targets()
            self._check_cancel()

            if not targets:
                self._log("No targets to scan!")
                return self.session_id

            # Phase 4: Windows infrastructure (if creds)
            await self._phase_windows_infra()
            self._check_cancel()

            # Phase 5: ARP collection
            await self._phase_arp_collection()
            self._check_cancel()

            # Phase 6: Liveness scan (ping)
            alive = await self._phase_ping_sweep(targets)
            self._check_cancel()

            # Phase 7: Port scanning
            scan_targets = alive if self.profile.scan_only_alive else targets
            await self._phase_port_scan(scan_targets)
            self._check_cancel()

            # Phase 8: DNS resolution
            await self._phase_dns_resolution()
            self._check_cancel()

            # Phase 9: SNMP collection
            if self.profile.snmp_enabled:
                await self._phase_snmp_collection(scan_targets)
                self._check_cancel()

            # Phase 10: Classify and finalize
            await self._phase_finalize()

        except ScanCancelled:
            self._log("Scan cancelled by user")
            self.db.finish_scan_session(self.session_id, "cancelled")
            return self.session_id
        except Exception as e:
            self._log(f"Scan error: {e}")
            logger.exception("Scan failed")
            self.db.finish_scan_session(self.session_id, "error")
            return self.session_id

        # Save results
        end_time = datetime.now()
        self.correlation.infrastructure.scan_end = end_time.isoformat()
        duration = (end_time - start_time).total_seconds()

        summary = self.correlation.build_infrastructure_summary()
        self.correlation.infrastructure.scanner_ip = scanner_ip

        # Save all devices to DB
        devices = self.correlation.get_all_device_dicts()
        for dev_dict in devices:
            self.db.upsert_device(self.session_id, dev_dict)

        self.db.finish_scan_session(
            self.session_id, "completed",
            json.dumps(summary.to_dict()),
        )

        self._log(f"=== Scan complete in {duration:.1f}s ===")
        self._log(f"Devices found: {summary.total_devices}, "
                   f"Alive: {summary.total_alive}")

        return self.session_id

    # --- Phases ---

    async def _phase_local_context(self) -> None:
        """Phase 1: Collect local host network context."""
        self._emit("Local Context", 0, 1, "Collecting NIC and route info...")
        self._log("Phase 1: Collecting local network context")

        try:
            from ..collectors.local_context import collect_local_context
            ctx = collect_local_context()
            self.correlation.infrastructure.scanner_ip = (
                ctx.nics[0].ip_address if ctx.nics else ""
            )

            for nic in ctx.nics:
                self._log(f"  NIC: {nic.name} - {nic.ip_address}/{nic.subnet_mask} "
                          f"GW: {nic.gateway}")

            # Store subnets for target enumeration
            self._local_context = ctx
            self.correlation.infrastructure.data_sources_used.append("local_context")
            self.correlation.infrastructure.data_source_success["local_context"] = True
        except Exception as e:
            self._log(f"  Local context error: {e}")
            self._local_context = None
            self.correlation.infrastructure.data_source_success["local_context"] = False
            self.correlation.infrastructure.limitations.append(
                "Failed to collect local network context"
            )

        self._emit("Local Context", 1, 1, "Done")

    async def _phase_dhcp_discovery(self) -> None:
        """Phase 2: DHCP discover / rogue detection."""
        self._emit("DHCP Discovery", 0, 1, "Sending DHCP DISCOVER...")
        self._log("Phase 2: DHCP rogue detection")

        try:
            from ..collectors.dhcp_listener import detect_dhcp_servers, is_admin
            if not is_admin():
                self._log("  Skipping DHCP detection (not running as admin)")
                self.correlation.infrastructure.limitations.append(
                    "DHCP rogue detection skipped - requires admin privileges"
                )
                self._emit("DHCP Discovery", 1, 1, "Skipped (no admin)")
                return

            offers = detect_dhcp_servers(timeout=8.0)
            if offers:
                self.correlation.ingest_dhcp_offers(offers)
                for o in offers:
                    self._log(f"  DHCP server: {o.server_ip} offered {o.offered_ip} "
                              f"GW={o.router} DNS={o.dns_servers}")
                if len(set(o.server_ip for o in offers)) > 1:
                    self._log("  WARNING: Multiple DHCP servers detected!")

            self.correlation.infrastructure.data_sources_used.append("dhcp_discover")
            self.correlation.infrastructure.data_source_success["dhcp_discover"] = True
        except Exception as e:
            self._log(f"  DHCP detection error: {e}")
            self.correlation.infrastructure.data_source_success["dhcp_discover"] = False

        self._emit("DHCP Discovery", 1, 1, "Done")

    async def _phase_enumerate_targets(self) -> list[str]:
        """Phase 3: Build target IP list."""
        self._emit("Target Enumeration", 0, 1, "Building target list...")
        self._log("Phase 3: Enumerating targets")

        targets = []

        if self.profile.target_mode == "auto":
            # Auto-discover from local NICs
            if self._local_context:
                for subnet_cidr in self._local_context.discovered_subnets:
                    try:
                        net = ipaddress.IPv4Network(subnet_cidr, strict=False)
                        for host in net.hosts():
                            targets.append(str(host))
                    except Exception:
                        pass
        elif self.profile.target_mode == "manual":
            for cidr in self.profile.manual_targets:
                try:
                    net = ipaddress.IPv4Network(cidr.strip(), strict=False)
                    for host in net.hosts():
                        targets.append(str(host))
                except Exception as e:
                    self._log(f"  Invalid CIDR: {cidr} ({e})")

        # Apply exclusions
        exclude_nets = []
        for exc in self.profile.exclude_targets:
            try:
                exclude_nets.append(ipaddress.IPv4Network(exc.strip(), strict=False))
            except Exception:
                pass

        if exclude_nets:
            targets = [
                t for t in targets
                if not any(ipaddress.IPv4Address(t) in net for net in exclude_nets)
            ]

        # Deduplicate
        targets = list(dict.fromkeys(targets))

        self._log(f"  Target count: {len(targets)} IPs")
        self._emit("Target Enumeration", 1, 1, f"{len(targets)} targets")
        return targets

    async def _phase_windows_infra(self) -> None:
        """Phase 4: Query Windows DHCP/DNS/AD if credentials provided."""
        domain_creds = self.credentials.get("domain")
        if not domain_creds:
            self._log("Phase 4: Skipping Windows infrastructure (no domain creds)")
            return

        self._emit("Windows Infrastructure", 0, 3, "Querying AD...")
        self._log("Phase 4: Windows infrastructure collection")

        username = domain_creds.get("username", "")
        password = domain_creds.get("password", "")
        domain = domain_creds.get("domain", "")

        # AD
        try:
            from ..collectors.windows_infra import collect_ad_data
            ad = collect_ad_data(username, password, domain)
            if ad:
                self.correlation.ingest_ad_computers(ad.computers)
                for dc in ad.domain_controllers:
                    self.correlation.infrastructure.domain_controllers.append({
                        "hostname": dc.hostname,
                        "ip": dc.ip_address,
                        "site": dc.site,
                        "roles": dc.roles,
                    })
                    self._log(f"  DC: {dc.hostname} ({dc.ip_address})")
                self.correlation.infrastructure.data_sources_used.append("active_directory")
                self.correlation.infrastructure.data_source_success["active_directory"] = True
        except Exception as e:
            self._log(f"  AD collection error: {e}")
            self.correlation.infrastructure.data_source_success["active_directory"] = False

        self._emit("Windows Infrastructure", 1, 3, "Querying DHCP...")

        # DHCP
        dhcp_servers = self.credentials.get("dhcp_servers", [])
        if not dhcp_servers:
            try:
                from ..collectors.windows_infra import discover_dhcp_servers_from_ad
                dhcp_servers = discover_dhcp_servers_from_ad(username, password, domain)
                self._log(f"  Discovered DHCP servers from AD: {dhcp_servers}")
            except Exception:
                pass

        for server_ip in dhcp_servers:
            try:
                from ..collectors.windows_infra import collect_dhcp_server
                dhcp_data = collect_dhcp_server(server_ip, username, password, domain)
                if dhcp_data:
                    self.correlation.ingest_dhcp_leases(
                        dhcp_data.leases, source_server=server_ip
                    )
                    self.correlation.ingest_dhcp_reservations(
                        dhcp_data.reservations, source_server=server_ip
                    )
                    self._log(f"  DHCP {server_ip}: {len(dhcp_data.leases)} leases, "
                              f"{len(dhcp_data.reservations)} reservations")
                    self.correlation.infrastructure.data_sources_used.append("dhcp_server")
                    self.correlation.infrastructure.data_source_success["dhcp_server"] = True
            except Exception as e:
                self._log(f"  DHCP {server_ip} error: {e}")

        self._emit("Windows Infrastructure", 2, 3, "Querying DNS...")

        # DNS
        dns_servers = self.credentials.get("dns_servers", [])
        for server_ip in dns_servers:
            try:
                from ..collectors.windows_infra import collect_dns_server
                dns_data = collect_dns_server(server_ip, username, password, domain)
                if dns_data:
                    self._log(f"  DNS {server_ip}: forwarders={dns_data.forwarders}")
            except Exception as e:
                self._log(f"  DNS {server_ip} error: {e}")

        self._emit("Windows Infrastructure", 3, 3, "Done")

    async def _phase_arp_collection(self) -> None:
        """Phase 5: Collect ARP/NDP tables."""
        self._emit("ARP Collection", 0, 1, "Reading ARP table...")
        self._log("Phase 5: ARP table collection")

        try:
            from ..collectors.arp_collector import collect_arp_table, collect_ndp_table
            entries = collect_arp_table()
            self.correlation.ingest_arp_entries(entries)
            self._log(f"  ARP: {len(entries)} entries")
            self.correlation.infrastructure.data_sources_used.append("arp_table")
            self.correlation.infrastructure.data_source_success["arp_table"] = True

            if self.profile.include_ipv6:
                ndp = collect_ndp_table()
                self._log(f"  NDP: {len(ndp)} entries")
        except Exception as e:
            self._log(f"  ARP collection error: {e}")
            self.correlation.infrastructure.data_source_success["arp_table"] = False

        self._emit("ARP Collection", 1, 1, "Done")

    async def _phase_ping_sweep(self, targets: list[str]) -> list[str]:
        """Phase 6: ICMP ping sweep."""
        self._emit("Ping Sweep", 0, len(targets), "Pinging...")
        self._log(f"Phase 6: Ping sweep ({len(targets)} targets)")

        alive = set()
        sem = asyncio.Semaphore(self.profile.icmp_concurrency)
        timeout_s = self.profile.timeout_ms / 1000.0

        from ..collectors.active_prober import async_ping

        completed = 0

        async def _ping_one(ip: str) -> None:
            nonlocal completed
            async with sem:
                if self._cancelled:
                    return
                try:
                    is_alive = await async_ping(ip, timeout=timeout_s)
                    if is_alive:
                        alive.add(ip)
                except Exception:
                    pass
                completed += 1
                if completed % 50 == 0:
                    self._emit("Ping Sweep", completed, len(targets),
                               f"{len(alive)} alive")

        tasks = [_ping_one(ip) for ip in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.correlation.ingest_ping_results(alive)
        self._log(f"  Ping: {len(alive)}/{len(targets)} alive")
        self.correlation.infrastructure.data_sources_used.append("icmp_ping")
        self.correlation.infrastructure.data_source_success["icmp_ping"] = True

        self._emit("Ping Sweep", len(targets), len(targets), f"{len(alive)} alive")
        return list(alive)

    async def _phase_port_scan(self, targets: list[str]) -> None:
        """Phase 7: TCP port scanning and service fingerprinting."""
        intensity = ScanIntensity(self.profile.intensity)
        if intensity == ScanIntensity.QUICK:
            ports = DEFAULT_PORTS[:20]  # Top 20 for quick
        elif intensity == ScanIntensity.DEEP:
            ports = EXTENDED_PORTS
        else:
            ports = DEFAULT_PORTS

        if self.profile.port_list == "custom" and self.profile.custom_ports:
            ports = self.profile.custom_ports

        total_work = len(targets) * len(ports)
        self._emit("Port Scan", 0, total_work, f"Scanning {len(targets)} hosts...")
        self._log(f"Phase 7: Port scan ({len(targets)} hosts, {len(ports)} ports)")

        from ..collectors.active_prober import scan_host_ports

        sem = asyncio.Semaphore(self.profile.tcp_concurrency)
        completed = 0

        async def _scan_one(ip: str) -> None:
            nonlocal completed
            async with sem:
                if self._cancelled:
                    return
                try:
                    timeout_s = self.profile.timeout_ms / 1000.0
                    open_ports = await scan_host_ports(
                        ip, ports, timeout=timeout_s,
                        grab_banners=(intensity != ScanIntensity.QUICK),
                    )
                    if open_ports:
                        self.correlation.ingest_port_results(ip, open_ports)
                except Exception as e:
                    logger.debug("Port scan error for %s: %s", ip, e)
                    self._record_error()
                completed += 1
                if completed % 10 == 0:
                    self._emit("Port Scan", completed * len(ports), total_work,
                               f"{completed}/{len(targets)} hosts")

        tasks = [_scan_one(ip) for ip in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.correlation.infrastructure.data_sources_used.append("port_scan")
        self.correlation.infrastructure.data_source_success["port_scan"] = True
        self._log(f"  Port scan complete")
        self._emit("Port Scan", total_work, total_work, "Done")

    async def _phase_dns_resolution(self) -> None:
        """Phase 8: DNS forward and reverse lookups."""
        ips = list(self.correlation.devices.keys())
        self._emit("DNS Resolution", 0, len(ips), "Resolving hostnames...")
        self._log(f"Phase 8: DNS resolution ({len(ips)} IPs)")

        try:
            from ..collectors.dns_collector import batch_reverse_dns
            dns_map = await batch_reverse_dns(ips, concurrency=50, timeout=3.0)
            self.correlation.ingest_dns_results(dns_map, is_reverse=True)
            self._log(f"  Reverse DNS: {len(dns_map)} resolved")
            self.correlation.infrastructure.data_sources_used.append("dns_reverse")
            self.correlation.infrastructure.data_source_success["dns_reverse"] = True
        except Exception as e:
            self._log(f"  DNS resolution error: {e}")
            self.correlation.infrastructure.data_source_success["dns_reverse"] = False

        self._emit("DNS Resolution", len(ips), len(ips), "Done")

    async def _phase_snmp_collection(self, targets: list[str]) -> None:
        """Phase 9: SNMP data collection."""
        self._emit("SNMP Collection", 0, len(targets), "Querying SNMP...")
        self._log(f"Phase 9: SNMP collection ({len(targets)} targets)")

        snmp_creds = self.credentials.get("snmp", {})
        community = snmp_creds.get("community", "public")
        version = snmp_creds.get("version", self.profile.snmp_version)

        from ..collectors.snmp_collector import SNMPCollector

        collector = SNMPCollector(
            community=community,
            version=version,
            v3_user=snmp_creds.get("v3_user", ""),
            v3_auth_key=snmp_creds.get("v3_auth_key", ""),
            v3_priv_key=snmp_creds.get("v3_priv_key", ""),
            v3_auth_proto=snmp_creds.get("v3_auth_proto", "SHA"),
            v3_priv_proto=snmp_creds.get("v3_priv_proto", "AES"),
            timeout=self.profile.timeout_ms / 1000.0,
            retries=self.profile.retries,
        )

        intensity = ScanIntensity(self.profile.intensity)
        include_fdb = intensity == ScanIntensity.DEEP
        include_lldp = True

        sem = asyncio.Semaphore(self.profile.snmp_concurrency)
        completed = 0
        snmp_devices = []

        async def _snmp_one(ip: str) -> None:
            nonlocal completed
            async with sem:
                if self._cancelled:
                    return
                try:
                    data = await collector.collect_all(
                        ip, include_fdb=include_fdb,
                        include_lldp_cdp=include_lldp,
                    )
                    if data.reachable:
                        self.correlation.ingest_snmp_data(data)
                        snmp_devices.append(data)
                except Exception as e:
                    logger.debug("SNMP error for %s: %s", ip, e)
                completed += 1
                if completed % 10 == 0:
                    self._emit("SNMP Collection", completed, len(targets),
                               f"{len(snmp_devices)} SNMP devices")

        tasks = [_snmp_one(ip) for ip in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Process FDB mappings
        for data in snmp_devices:
            if data.fdb_entries:
                if_names = {i.index: i.name for i in data.interfaces}
                self.correlation.ingest_fdb_mappings(
                    data.ip_address,
                    data.system_info.sys_name,
                    data.fdb_entries,
                    if_names,
                )

        self.correlation.infrastructure.data_sources_used.append("snmp")
        self.correlation.infrastructure.data_source_success["snmp"] = True
        self._log(f"  SNMP: {len(snmp_devices)} devices responded")
        self._emit("SNMP Collection", len(targets), len(targets), "Done")

    async def _phase_finalize(self) -> None:
        """Phase 10: Classify roles and finalize."""
        self._emit("Finalizing", 0, 1, "Classifying devices...")
        self._log("Phase 10: Finalizing results")

        self.correlation.classify_all_roles()

        # Re-collect ARP to catch new entries
        try:
            from ..collectors.arp_collector import collect_arp_table
            entries = collect_arp_table()
            self.correlation.ingest_arp_entries(entries)
        except Exception:
            pass

        self._emit("Finalizing", 1, 1, "Done")
        self._log("  Finalization complete")


class ScanCancelled(Exception):
    """Raised when a scan is cancelled."""
    pass
