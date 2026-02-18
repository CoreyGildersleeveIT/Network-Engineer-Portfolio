"""
SNMP collector module.
Supports SNMPv2c and SNMPv3 for device discovery, LLDP/CDP neighbors,
bridge FDB (MAC tables), interface enumeration, and VLAN discovery.

Uses pysnmp library for SNMP operations.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Standard OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# Interface OIDs (table walk)
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"

# IP Address table
OID_IP_ADDR_TABLE = "1.3.6.1.2.1.4.20.1.1"

# ARP table from IP-MIB (ipNetToMediaTable)
OID_IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22.1"

# LLDP MIBs
OID_LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1.1"
OID_LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_SYS_DESC = "1.0.8802.1.1.2.1.4.1.1.10"
OID_LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.4"

# CDP MIBs (Cisco)
OID_CDP_CACHE_TABLE = "1.3.6.1.4.1.9.9.23.1.2.1.1"
OID_CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
OID_CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# Bridge FDB (MAC address table)
OID_DOT1D_TP_FDB = "1.3.6.1.2.1.17.4.3.1"
OID_DOT1D_TP_FDB_ADDRESS = "1.3.6.1.2.1.17.4.3.1.1"
OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"

# Q-BRIDGE VLAN MIB
OID_DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"
OID_DOT1Q_TP_FDB = "1.3.6.1.2.1.17.7.1.2.2.1"


@dataclass
class SNMPSystemInfo:
    """SNMP system group information."""
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_name: str = ""
    sys_uptime: str = ""
    sys_contact: str = ""
    sys_location: str = ""


@dataclass
class SNMPInterface:
    """SNMP interface information."""
    index: int = 0
    name: str = ""
    description: str = ""
    if_type: int = 0
    speed: int = 0
    oper_status: int = 0  # 1=up, 2=down


@dataclass
class LLDPNeighbor:
    """LLDP discovered neighbor."""
    local_port: str = ""
    remote_chassis_id: str = ""
    remote_port_id: str = ""
    remote_port_desc: str = ""
    remote_sys_name: str = ""
    remote_sys_desc: str = ""
    remote_mgmt_addr: str = ""


@dataclass
class CDPNeighbor:
    """CDP discovered neighbor."""
    local_port: str = ""
    device_id: str = ""
    device_port: str = ""
    device_address: str = ""
    platform: str = ""


@dataclass
class FDBEntry:
    """Forwarding database (MAC table) entry."""
    mac_address: str = ""
    port_index: int = 0
    port_name: str = ""
    vlan_id: int = 0
    if_index: int = 0


@dataclass
class SNMPDeviceData:
    """Complete SNMP data collected from a device."""
    ip_address: str = ""
    system_info: SNMPSystemInfo = field(default_factory=SNMPSystemInfo)
    interfaces: list[SNMPInterface] = field(default_factory=list)
    lldp_neighbors: list[LLDPNeighbor] = field(default_factory=list)
    cdp_neighbors: list[CDPNeighbor] = field(default_factory=list)
    fdb_entries: list[FDBEntry] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    arp_entries: list[dict] = field(default_factory=list)
    vlans: dict[int, str] = field(default_factory=dict)
    reachable: bool = False


class SNMPCollector:
    """Async SNMP data collector."""

    def __init__(self, community: str = "public", version: str = "2c",
                 v3_user: str = "", v3_auth_key: str = "",
                 v3_priv_key: str = "", v3_auth_proto: str = "SHA",
                 v3_priv_proto: str = "AES",
                 timeout: float = 2.0, retries: int = 1) -> None:
        self.community = community
        self.version = version
        self.v3_user = v3_user
        self.v3_auth_key = v3_auth_key
        self.v3_priv_key = v3_priv_key
        self.v3_auth_proto = v3_auth_proto
        self.v3_priv_proto = v3_priv_proto
        self.timeout = timeout
        self.retries = retries

    def _get_auth(self):
        """Build pysnmp authentication object."""
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                CommunityData, UsmUserData,
            )
            if self.version == "3":
                from pysnmp.hlapi.v3arch.asyncio import (
                    usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
                    usmAesCfb128Protocol, usmDESPrivProtocol,
                )
                auth_proto = (usmHMACSHAAuthProtocol if self.v3_auth_proto.upper() == "SHA"
                              else usmHMACMD5AuthProtocol)
                priv_proto = (usmAesCfb128Protocol if self.v3_priv_proto.upper() == "AES"
                              else usmDESPrivProtocol)
                return UsmUserData(
                    self.v3_user, self.v3_auth_key, self.v3_priv_key,
                    authProtocol=auth_proto, privProtocol=priv_proto,
                )
            return CommunityData(self.community)
        except ImportError:
            return None

    async def _snmp_get(self, target: str, *oids) -> dict[str, str]:
        """SNMP GET for specific OIDs."""
        results = {}
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                SnmpEngine, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, get_cmd,
            )
            auth = self._get_auth()
            if not auth:
                return results

            engine = SnmpEngine()
            transport = await UdpTransportTarget.create((target, 161),
                                                         timeout=self.timeout,
                                                         retries=self.retries)
            obj_types = [ObjectType(ObjectIdentity(oid)) for oid in oids]

            error_indication, error_status, _, var_binds = await get_cmd(
                engine, auth, transport, ContextData(), *obj_types,
            )

            if error_indication or error_status:
                return results

            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                val = var_bind[1]
                results[oid_str] = str(val) if val else ""

        except ImportError:
            logger.debug("pysnmp not available - SNMP collection disabled")
        except Exception as e:
            logger.debug("SNMP GET to %s failed: %s", target, e)
        return results

    async def _snmp_walk(self, target: str, oid: str) -> list[tuple[str, str]]:
        """SNMP WALK (GETBULK) for a table OID."""
        results = []
        try:
            from pysnmp.hlapi.v3arch.asyncio import (
                SnmpEngine, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, bulk_cmd,
            )
            auth = self._get_auth()
            if not auth:
                return results

            engine = SnmpEngine()
            transport = await UdpTransportTarget.create((target, 161),
                                                         timeout=self.timeout,
                                                         retries=self.retries)

            kwargs = dict(
                lexicographicMode=False,
            )

            async for (error_indication, error_status, _, var_binds) in bulk_cmd(
                engine, auth, transport, ContextData(),
                0, 25,  # nonRepeaters, maxRepetitions
                ObjectType(ObjectIdentity(oid)),
                **kwargs,
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    if not oid_str.startswith(oid):
                        break
                    val = var_bind[1]
                    val_str = ""
                    if hasattr(val, 'prettyPrint'):
                        val_str = val.prettyPrint()
                    else:
                        val_str = str(val) if val else ""
                    results.append((oid_str, val_str))

        except ImportError:
            logger.debug("pysnmp not available")
        except Exception as e:
            logger.debug("SNMP WALK %s on %s failed: %s", oid, target, e)
        return results

    async def collect_system_info(self, target: str) -> Optional[SNMPSystemInfo]:
        """Collect SNMP system group from a device."""
        data = await self._snmp_get(
            target,
            OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME,
            OID_SYS_UPTIME, OID_SYS_CONTACT, OID_SYS_LOCATION,
        )
        if not data:
            return None

        return SNMPSystemInfo(
            sys_descr=data.get(OID_SYS_DESCR, ""),
            sys_object_id=data.get(OID_SYS_OBJECT_ID, ""),
            sys_name=data.get(OID_SYS_NAME, ""),
            sys_uptime=data.get(OID_SYS_UPTIME, ""),
            sys_contact=data.get(OID_SYS_CONTACT, ""),
            sys_location=data.get(OID_SYS_LOCATION, ""),
        )

    async def collect_interfaces(self, target: str) -> list[SNMPInterface]:
        """Collect interface information."""
        interfaces = []
        names = await self._snmp_walk(target, OID_IF_NAME)
        descrs = await self._snmp_walk(target, OID_IF_DESCR)
        types = await self._snmp_walk(target, OID_IF_TYPE)
        speeds = await self._snmp_walk(target, OID_IF_SPEED)
        statuses = await self._snmp_walk(target, OID_IF_OPER_STATUS)

        name_map = {oid.split(".")[-1]: val for oid, val in names}
        descr_map = {oid.split(".")[-1]: val for oid, val in descrs}
        type_map = {oid.split(".")[-1]: val for oid, val in types}
        speed_map = {oid.split(".")[-1]: val for oid, val in speeds}
        status_map = {oid.split(".")[-1]: val for oid, val in statuses}

        all_indices = set(name_map.keys()) | set(descr_map.keys())
        for idx in all_indices:
            iface = SNMPInterface(
                index=int(idx) if idx.isdigit() else 0,
                name=name_map.get(idx, ""),
                description=descr_map.get(idx, ""),
                if_type=int(type_map.get(idx, "0")) if type_map.get(idx, "0").isdigit() else 0,
                speed=int(speed_map.get(idx, "0")) if speed_map.get(idx, "0").isdigit() else 0,
                oper_status=int(status_map.get(idx, "0")) if status_map.get(idx, "0").isdigit() else 0,
            )
            interfaces.append(iface)
        return interfaces

    async def collect_lldp_neighbors(self, target: str) -> list[LLDPNeighbor]:
        """Collect LLDP neighbor information."""
        neighbors = []
        chassis_ids = await self._snmp_walk(target, OID_LLDP_REM_CHASSIS_ID)
        port_ids = await self._snmp_walk(target, OID_LLDP_REM_PORT_ID)
        port_descs = await self._snmp_walk(target, OID_LLDP_REM_PORT_DESC)
        sys_names = await self._snmp_walk(target, OID_LLDP_REM_SYS_NAME)
        sys_descs = await self._snmp_walk(target, OID_LLDP_REM_SYS_DESC)
        mgmt_addrs = await self._snmp_walk(target, OID_LLDP_REM_MAN_ADDR)

        def _key(oid: str) -> str:
            parts = oid.split(".")
            return ".".join(parts[-3:]) if len(parts) >= 3 else oid

        chassis_map = {_key(oid): val for oid, val in chassis_ids}
        port_map = {_key(oid): val for oid, val in port_ids}
        desc_map = {_key(oid): val for oid, val in port_descs}
        name_map = {_key(oid): val for oid, val in sys_names}
        sdesc_map = {_key(oid): val for oid, val in sys_descs}

        mgmt_map = {}
        for oid, val in mgmt_addrs:
            key = _key(oid)
            mgmt_map[key] = val

        for key in chassis_map:
            neighbor = LLDPNeighbor(
                local_port=key.split(".")[0] if "." in key else "",
                remote_chassis_id=chassis_map.get(key, ""),
                remote_port_id=port_map.get(key, ""),
                remote_port_desc=desc_map.get(key, ""),
                remote_sys_name=name_map.get(key, ""),
                remote_sys_desc=sdesc_map.get(key, ""),
                remote_mgmt_addr=mgmt_map.get(key, ""),
            )
            neighbors.append(neighbor)
        return neighbors

    async def collect_cdp_neighbors(self, target: str) -> list[CDPNeighbor]:
        """Collect CDP neighbor information (Cisco)."""
        neighbors = []
        device_ids = await self._snmp_walk(target, OID_CDP_CACHE_DEVICE_ID)
        device_ports = await self._snmp_walk(target, OID_CDP_CACHE_DEVICE_PORT)
        addresses = await self._snmp_walk(target, OID_CDP_CACHE_ADDRESS)
        platforms = await self._snmp_walk(target, OID_CDP_CACHE_PLATFORM)

        def _key(oid: str) -> str:
            parts = oid.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else oid

        id_map = {_key(oid): val for oid, val in device_ids}
        port_map = {_key(oid): val for oid, val in device_ports}
        addr_map = {_key(oid): val for oid, val in addresses}
        plat_map = {_key(oid): val for oid, val in platforms}

        for key in id_map:
            addr = addr_map.get(key, "")
            if addr and len(addr) >= 8 and all(c in "0123456789abcdefABCDEF " for c in addr):
                try:
                    octets = addr.replace(" ", "")
                    if len(octets) == 8:
                        addr = ".".join(str(int(octets[i:i+2], 16)) for i in range(0, 8, 2))
                except Exception:
                    pass

            neighbor = CDPNeighbor(
                local_port=key.split(".")[0] if "." in key else "",
                device_id=id_map.get(key, ""),
                device_port=port_map.get(key, ""),
                device_address=addr,
                platform=plat_map.get(key, ""),
            )
            neighbors.append(neighbor)
        return neighbors

    async def collect_fdb(self, target: str) -> list[FDBEntry]:
        """Collect bridge forwarding database (MAC address table)."""
        entries = []
        port_to_if = {}
        bridge_port_map = await self._snmp_walk(target, OID_DOT1D_BASE_PORT_IF_INDEX)
        for oid, val in bridge_port_map:
            port_idx = oid.split(".")[-1]
            port_to_if[port_idx] = val

        fdb_addresses = await self._snmp_walk(target, OID_DOT1D_TP_FDB_ADDRESS)
        fdb_ports = await self._snmp_walk(target, OID_DOT1D_TP_FDB_PORT)

        def _mac_suffix(oid: str) -> str:
            parts = oid.split(".")
            return ".".join(parts[-6:]) if len(parts) >= 6 else oid

        port_map = {_mac_suffix(oid): val for oid, val in fdb_ports}

        for oid, val in fdb_addresses:
            suffix = _mac_suffix(oid)
            port = port_map.get(suffix, "0")
            mac_hex = val.replace("0x", "").replace(" ", "")
            if len(mac_hex) == 12:
                mac = ":".join(mac_hex[i:i+2].upper() for i in range(0, 12, 2))
            else:
                mac = val
            if_index = port_to_if.get(str(port), "0")

            entries.append(FDBEntry(
                mac_address=mac,
                port_index=int(port) if str(port).isdigit() else 0,
                if_index=int(if_index) if str(if_index).isdigit() else 0,
            ))
        return entries

    async def collect_vlans(self, target: str) -> dict[int, str]:
        """Collect VLAN names from Q-BRIDGE-MIB."""
        vlans = {}
        vlan_names = await self._snmp_walk(target, OID_DOT1Q_VLAN_STATIC_NAME)
        for oid, val in vlan_names:
            vlan_id = oid.split(".")[-1]
            if vlan_id.isdigit():
                vlans[int(vlan_id)] = val
        return vlans

    async def collect_arp_table(self, target: str) -> list[dict]:
        """Collect ARP table from SNMP (IP-MIB ipNetToMediaTable)."""
        entries = []
        arp_data = await self._snmp_walk(target, OID_IP_NET_TO_MEDIA)
        # Group by index: .1 = ifIndex, .2 = physAddr, .3 = netAddr
        by_index: dict[str, dict] = {}
        for oid, val in arp_data:
            parts = oid.split(".")
            col = parts[10] if len(parts) > 10 else ""
            key = ".".join(parts[11:]) if len(parts) > 11 else ""
            if key not in by_index:
                by_index[key] = {}
            by_index[key][col] = val

        for key, cols in by_index.items():
            mac_hex = cols.get("2", "").replace("0x", "").replace(" ", "")
            if len(mac_hex) == 12:
                mac = ":".join(mac_hex[i:i+2].upper() for i in range(0, 12, 2))
            else:
                mac = cols.get("2", "")
            ip = cols.get("3", key.replace(".", ".", 3))
            if mac and ip:
                entries.append({"ip": ip, "mac": mac})
        return entries

    async def collect_all(self, target: str, include_fdb: bool = True,
                          include_lldp_cdp: bool = True) -> SNMPDeviceData:
        """Collect all SNMP data from a device."""
        data = SNMPDeviceData(ip_address=target)

        # System info first to check reachability
        sys_info = await self.collect_system_info(target)
        if not sys_info:
            data.reachable = False
            return data
        data.system_info = sys_info
        data.reachable = True

        # Collect remaining data in parallel
        tasks = [self.collect_interfaces(target)]
        if include_lldp_cdp:
            tasks.append(self.collect_lldp_neighbors(target))
            tasks.append(self.collect_cdp_neighbors(target))
        if include_fdb:
            tasks.append(self.collect_fdb(target))
            tasks.append(self.collect_vlans(target))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        idx = 0
        if idx < len(results) and not isinstance(results[idx], Exception):
            data.interfaces = results[idx]
        idx += 1

        if include_lldp_cdp:
            if idx < len(results) and not isinstance(results[idx], Exception):
                data.lldp_neighbors = results[idx]
            idx += 1
            if idx < len(results) and not isinstance(results[idx], Exception):
                data.cdp_neighbors = results[idx]
            idx += 1

        if include_fdb:
            if idx < len(results) and not isinstance(results[idx], Exception):
                data.fdb_entries = results[idx]
            idx += 1
            if idx < len(results) and not isinstance(results[idx], Exception):
                data.vlans = results[idx]
            idx += 1

        logger.info(
            "SNMP %s: %s, %d ifaces, %d LLDP, %d CDP, %d FDB, %d VLANs",
            target, sys_info.sys_name,
            len(data.interfaces), len(data.lldp_neighbors),
            len(data.cdp_neighbors), len(data.fdb_entries), len(data.vlans),
        )
        return data
