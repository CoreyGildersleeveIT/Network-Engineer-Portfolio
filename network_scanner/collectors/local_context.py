"""
Local host network context collector.
Captures NIC configuration, routes, DNS settings, default gateways.
Works on both Windows and Linux.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import platform
import re
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NICInfo:
    """Network interface information."""
    name: str = ""
    description: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    cidr: str = ""
    gateway: str = ""
    mac_address: str = ""
    dns_servers: list[str] = field(default_factory=list)
    dns_suffix: str = ""
    dhcp_enabled: bool = False
    dhcp_server: str = ""
    vlan_id: int = 0
    is_up: bool = True
    speed_mbps: int = 0


@dataclass
class RouteEntry:
    """Routing table entry."""
    destination: str = ""
    mask: str = ""
    gateway: str = ""
    interface: str = ""
    metric: int = 0


@dataclass
class LocalContext:
    """Complete local host network context."""
    hostname: str = ""
    domain: str = ""
    nics: list[NICInfo] = field(default_factory=list)
    routes: list[RouteEntry] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    default_gateways: list[str] = field(default_factory=list)
    discovered_subnets: list[str] = field(default_factory=list)


def _run_ps(command: str) -> Optional[str]:
    """Run a PowerShell command and return stdout."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-Command", command],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        logger.debug("PS command failed: %s -> %s", command, result.stderr.strip())
    except FileNotFoundError:
        logger.debug("PowerShell not available")
    except subprocess.TimeoutExpired:
        logger.debug("PS command timed out: %s", command)
    except Exception as e:
        logger.debug("PS error: %s", e)
    return None


def _run_cmd(args: list[str]) -> Optional[str]:
    """Run a system command and return stdout."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception as e:
        logger.debug("Command error (%s): %s", args, e)
    return None


def collect_local_context() -> LocalContext:
    """Collect local host network context."""
    ctx = LocalContext()
    ctx.hostname = socket.gethostname()
    try:
        ctx.domain = socket.getfqdn()
    except Exception:
        ctx.domain = ctx.hostname

    if platform.system() == "Windows":
        _collect_windows(ctx)
    else:
        _collect_linux(ctx)

    # Derive subnets from NIC info
    for nic in ctx.nics:
        if nic.ip_address and nic.subnet_mask and nic.is_up:
            try:
                iface = ipaddress.IPv4Interface(f"{nic.ip_address}/{nic.subnet_mask}")
                network = str(iface.network)
                if network not in ctx.discovered_subnets:
                    ctx.discovered_subnets.append(network)
                nic.cidr = network
            except Exception:
                pass

    # Collect default gateways
    for nic in ctx.nics:
        if nic.gateway and nic.gateway not in ctx.default_gateways:
            ctx.default_gateways.append(nic.gateway)

    # Collect DNS servers
    for nic in ctx.nics:
        for dns in nic.dns_servers:
            if dns and dns not in ctx.dns_servers:
                ctx.dns_servers.append(dns)

    logger.info("Local context: %d NICs, %d subnets, %d gateways",
                len(ctx.nics), len(ctx.discovered_subnets), len(ctx.default_gateways))
    return ctx


def _collect_windows(ctx: LocalContext) -> None:
    """Collect network context on Windows using PowerShell."""
    # Get adapter info via PowerShell JSON
    ps_cmd = (
        "Get-NetIPConfiguration -Detailed | "
        "Select-Object InterfaceAlias, InterfaceDescription, "
        "  @{N='IPv4';E={($_.IPv4Address.IPAddress -join ',')}}, "
        "  @{N='Mask';E={($_.IPv4Address.PrefixLength -join ',')}}, "
        "  @{N='Gateway';E={($_.IPv4DefaultGateway.NextHop -join ',')}}, "
        "  @{N='DNS';E={($_.DNSServer.ServerAddresses -join ',')}}, "
        "  @{N='DNSSuffix';E={$_.NetProfile.Name}}, "
        "  @{N='DHCP';E={$_.NetIPv4Interface.DHCP}} | "
        "ConvertTo-Json -Depth 3"
    )
    output = _run_ps(ps_cmd)
    if output:
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                nic = NICInfo()
                nic.name = item.get("InterfaceAlias", "")
                nic.description = item.get("InterfaceDescription", "")
                nic.ip_address = (item.get("IPv4") or "").split(",")[0]
                prefix = (item.get("Mask") or "").split(",")[0]
                if prefix and prefix.isdigit():
                    try:
                        net = ipaddress.IPv4Network(f"0.0.0.0/{prefix}")
                        nic.subnet_mask = str(net.netmask)
                    except Exception:
                        pass
                nic.gateway = (item.get("Gateway") or "").split(",")[0]
                dns_str = item.get("DNS") or ""
                nic.dns_servers = [d.strip() for d in dns_str.split(",") if d.strip()]
                nic.dns_suffix = item.get("DNSSuffix") or ""
                nic.dhcp_enabled = str(item.get("DHCP", "")).lower() == "enabled"
                if nic.ip_address and not nic.ip_address.startswith("169.254"):
                    ctx.nics.append(nic)
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to parse PS NIC output: %s", e)

    # Get MAC addresses
    mac_cmd = (
        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
        "Select-Object Name, MacAddress, LinkSpeed | ConvertTo-Json"
    )
    mac_output = _run_ps(mac_cmd)
    if mac_output:
        try:
            mac_data = json.loads(mac_output)
            if isinstance(mac_data, dict):
                mac_data = [mac_data]
            mac_map = {m.get("Name", ""): m for m in mac_data}
            for nic in ctx.nics:
                if nic.name in mac_map:
                    raw = mac_map[nic.name].get("MacAddress", "")
                    nic.mac_address = raw.replace("-", ":").upper()
                    speed = mac_map[nic.name].get("LinkSpeed", "")
                    if speed:
                        # Parse "1 Gbps" -> 1000
                        m = re.search(r"(\d+)\s*(Gbps|Mbps)", speed)
                        if m:
                            val = int(m.group(1))
                            if m.group(2) == "Gbps":
                                val *= 1000
                            nic.speed_mbps = val
        except (json.JSONDecodeError, KeyError):
            pass

    # Get DHCP server info
    dhcp_cmd = (
        "Get-NetIPConfiguration | Where-Object {$_.NetIPv4Interface.DHCP -eq 'Enabled'} | "
        "ForEach-Object { "
        "  $dhcp = (Get-WmiObject Win32_NetworkAdapterConfiguration | "
        "    Where-Object {$_.IPAddress -contains $_.IPv4Address.IPAddress}).DHCPServer; "
        "  [PSCustomObject]@{Iface=$_.InterfaceAlias; DHCPServer=$dhcp} "
        "} | ConvertTo-Json"
    )
    dhcp_output = _run_ps(dhcp_cmd)
    if dhcp_output:
        try:
            dhcp_data = json.loads(dhcp_output)
            if isinstance(dhcp_data, dict):
                dhcp_data = [dhcp_data]
            for item in dhcp_data:
                iface = item.get("Iface", "")
                server = item.get("DHCPServer", "")
                for nic in ctx.nics:
                    if nic.name == iface and server:
                        nic.dhcp_server = server
        except Exception:
            pass

    # Get routes
    route_cmd = (
        "Get-NetRoute -AddressFamily IPv4 | "
        "Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric | "
        "ConvertTo-Json"
    )
    route_output = _run_ps(route_cmd)
    if route_output:
        try:
            route_data = json.loads(route_output)
            if isinstance(route_data, dict):
                route_data = [route_data]
            for item in route_data:
                entry = RouteEntry()
                dest = item.get("DestinationPrefix", "")
                if "/" in dest:
                    parts = dest.split("/")
                    entry.destination = parts[0]
                    try:
                        net = ipaddress.IPv4Network(dest, strict=False)
                        entry.mask = str(net.netmask)
                    except Exception:
                        entry.mask = parts[1]
                entry.gateway = item.get("NextHop", "")
                entry.interface = item.get("InterfaceAlias", "")
                entry.metric = int(item.get("RouteMetric", 0))
                ctx.routes.append(entry)
        except (json.JSONDecodeError, KeyError):
            pass


def _collect_linux(ctx: LocalContext) -> None:
    """Collect network context on Linux."""
    # Get IP addresses
    output = _run_cmd(["ip", "-j", "addr", "show"])
    if output:
        try:
            data = json.loads(output)
            for iface in data:
                if iface.get("operstate") != "UP":
                    continue
                name = iface.get("ifname", "")
                mac = iface.get("address", "").upper()
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") != "inet":
                        continue
                    ip = addr_info.get("local", "")
                    prefix = addr_info.get("prefixlen", 24)
                    if ip.startswith("127."):
                        continue
                    nic = NICInfo()
                    nic.name = name
                    nic.ip_address = ip
                    nic.mac_address = mac
                    try:
                        net = ipaddress.IPv4Network(f"0.0.0.0/{prefix}")
                        nic.subnet_mask = str(net.netmask)
                    except Exception:
                        nic.subnet_mask = "255.255.255.0"
                    ctx.nics.append(nic)
        except (json.JSONDecodeError, KeyError) as e:
            logger.debug("Failed to parse ip addr: %s", e)

    # Fallback: ifconfig
    if not ctx.nics:
        output = _run_cmd(["ifconfig"])
        if output:
            current_nic = None
            for line in output.splitlines():
                m = re.match(r"^(\S+):", line)
                if m:
                    current_nic = NICInfo(name=m.group(1))
                    ctx.nics.append(current_nic)
                if current_nic:
                    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        current_nic.ip_address = m.group(1)
                    m = re.search(r"netmask (\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        current_nic.subnet_mask = m.group(1)
                    m = re.search(r"ether ([0-9a-fA-F:]+)", line)
                    if m:
                        current_nic.mac_address = m.group(1).upper()

    # Get default gateway from routes
    output = _run_cmd(["ip", "-j", "route", "show", "default"])
    if output:
        try:
            routes = json.loads(output)
            for r in routes:
                gw = r.get("gateway", "")
                if gw:
                    for nic in ctx.nics:
                        if nic.name == r.get("dev"):
                            nic.gateway = gw
        except Exception:
            pass

    # Get routes
    output = _run_cmd(["ip", "-j", "route", "show"])
    if output:
        try:
            routes = json.loads(output)
            for r in routes:
                entry = RouteEntry()
                entry.destination = r.get("dst", "")
                entry.gateway = r.get("gateway", "")
                entry.interface = r.get("dev", "")
                entry.metric = r.get("metric", 0)
                ctx.routes.append(entry)
        except Exception:
            pass

    # Get DNS servers from resolv.conf
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        for nic in ctx.nics:
                            if parts[1] not in nic.dns_servers:
                                nic.dns_servers.append(parts[1])
    except FileNotFoundError:
        pass
