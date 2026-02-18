"""
Windows Infrastructure collectors.
Queries Windows DHCP Server, DNS Server, and Active Directory
via PowerShell subprocess with JSON output.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _run_ps_json(command: str, credential_args: str = "",
                 timeout: int = 60) -> Optional[Any]:
    """
    Run a PowerShell command that returns JSON.
    Handles single object vs list, logs errors (no secrets).
    """
    full_cmd = command
    if credential_args:
        full_cmd = f"{credential_args}; {command}"

    ps_args = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-Command", full_cmd,
    ]

    logger.debug("Running PS: %s", command)  # Log command without creds

    try:
        result = subprocess.run(
            ps_args, capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            err = result.stderr.strip()
            # Sanitize error - remove anything that looks like credentials
            logger.debug("PS command returned error: %s", err[:500])
            return None

        output = result.stdout.strip()
        if not output:
            return None

        data = json.loads(output)
        # Ensure we always return a list for consistency
        if isinstance(data, dict):
            return [data]
        return data

    except json.JSONDecodeError as e:
        logger.debug("PS JSON parse error: %s", e)
    except subprocess.TimeoutExpired:
        logger.warning("PS command timed out after %ds", timeout)
    except FileNotFoundError:
        logger.warning("PowerShell not available on this system")
    except Exception as e:
        logger.warning("PS execution error: %s", e)
    return None


def _build_cred_arg(username: str, password: str, domain: str = "") -> str:
    """Build a PowerShell credential argument string."""
    if not username or not password:
        return ""
    user = f"{domain}\\{username}" if domain else username
    # Use SecureString for password - not logged
    return (
        f"$__pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        f"$__cred = New-Object System.Management.Automation.PSCredential('{user}', $__pw)"
    )


# --- DHCP Server ---

@dataclass
class DHCPScope:
    """Windows DHCP Scope information."""
    scope_id: str = ""
    name: str = ""
    subnet_mask: str = ""
    start_range: str = ""
    end_range: str = ""
    state: str = ""
    lease_duration: str = ""


@dataclass
class DHCPLease:
    """Windows DHCP Lease."""
    ip_address: str = ""
    scope_id: str = ""
    mac_address: str = ""
    hostname: str = ""
    lease_expiry: str = ""
    address_state: str = ""


@dataclass
class DHCPReservation:
    """Windows DHCP Reservation."""
    ip_address: str = ""
    scope_id: str = ""
    mac_address: str = ""
    name: str = ""
    description: str = ""


@dataclass
class DHCPServerData:
    """Complete data from a Windows DHCP server."""
    server_ip: str = ""
    scopes: list[DHCPScope] = field(default_factory=list)
    leases: list[DHCPLease] = field(default_factory=list)
    reservations: list[DHCPReservation] = field(default_factory=list)
    scope_options: dict[str, dict] = field(default_factory=dict)
    server_options: dict = field(default_factory=dict)
    utilization: dict[str, dict] = field(default_factory=dict)


def collect_dhcp_server(server_ip: str, username: str = "",
                        password: str = "", domain: str = "") -> Optional[DHCPServerData]:
    """Collect DHCP data from a Windows DHCP Server."""
    cred_arg = _build_cred_arg(username, password, domain)
    data = DHCPServerData(server_ip=server_ip)

    # 1. Get scopes
    cmd = (
        f"Get-DhcpServerv4Scope -ComputerName '{server_ip}' | "
        "Select-Object ScopeId, Name, SubnetMask, StartRange, EndRange, State, "
        "LeaseDuration | ConvertTo-Json -Depth 3"
    )
    scopes = _run_ps_json(cmd, cred_arg)
    if scopes:
        for s in scopes:
            scope = DHCPScope(
                scope_id=str(s.get("ScopeId", "")),
                name=s.get("Name", ""),
                subnet_mask=str(s.get("SubnetMask", "")),
                start_range=str(s.get("StartRange", "")),
                end_range=str(s.get("EndRange", "")),
                state=s.get("State", ""),
                lease_duration=str(s.get("LeaseDuration", "")),
            )
            data.scopes.append(scope)
    else:
        logger.info("No DHCP scopes found or DHCP module not available for %s",
                     server_ip)
        return None

    # 2. Get leases per scope
    for scope in data.scopes:
        cmd = (
            f"Get-DhcpServerv4Lease -ComputerName '{server_ip}' "
            f"-ScopeId '{scope.scope_id}' -AllLeases | "
            "Select-Object IPAddress, ScopeId, ClientId, HostName, "
            "LeaseExpiryTime, AddressState | ConvertTo-Json -Depth 3"
        )
        leases = _run_ps_json(cmd, cred_arg)
        if leases:
            for le in leases:
                lease = DHCPLease(
                    ip_address=str(le.get("IPAddress", "")),
                    scope_id=str(le.get("ScopeId", "")),
                    mac_address=str(le.get("ClientId", "")).replace("-", ":").upper(),
                    hostname=le.get("HostName", "") or "",
                    lease_expiry=str(le.get("LeaseExpiryTime", "")),
                    address_state=le.get("AddressState", ""),
                )
                data.leases.append(lease)

    # 3. Get reservations per scope
    for scope in data.scopes:
        cmd = (
            f"Get-DhcpServerv4Reservation -ComputerName '{server_ip}' "
            f"-ScopeId '{scope.scope_id}' | "
            "Select-Object IPAddress, ScopeId, ClientId, Name, Description | "
            "ConvertTo-Json -Depth 3"
        )
        reservations = _run_ps_json(cmd, cred_arg)
        if reservations:
            for r in reservations:
                res = DHCPReservation(
                    ip_address=str(r.get("IPAddress", "")),
                    scope_id=str(r.get("ScopeId", "")),
                    mac_address=str(r.get("ClientId", "")).replace("-", ":").upper(),
                    name=r.get("Name", "") or "",
                    description=r.get("Description", "") or "",
                )
                data.reservations.append(res)

    # 4. Get scope options (DNS, gateway, domain etc.)
    for scope in data.scopes:
        cmd = (
            f"Get-DhcpServerv4OptionValue -ComputerName '{server_ip}' "
            f"-ScopeId '{scope.scope_id}' -All | "
            "Select-Object OptionId, Name, Value | ConvertTo-Json -Depth 3"
        )
        opts = _run_ps_json(cmd, cred_arg)
        if opts:
            scope_opts = {}
            for o in opts:
                oid = o.get("OptionId", 0)
                scope_opts[str(oid)] = {
                    "name": o.get("Name", ""),
                    "value": o.get("Value", []),
                }
            data.scope_options[scope.scope_id] = scope_opts

    # 5. Get server-level options
    cmd = (
        f"Get-DhcpServerv4OptionValue -ComputerName '{server_ip}' | "
        "Select-Object OptionId, Name, Value | ConvertTo-Json -Depth 3"
    )
    server_opts = _run_ps_json(cmd, cred_arg)
    if server_opts:
        for o in server_opts:
            oid = o.get("OptionId", 0)
            data.server_options[str(oid)] = {
                "name": o.get("Name", ""),
                "value": o.get("Value", []),
            }

    # 6. Compute utilization
    for scope in data.scopes:
        scope_leases = [l for l in data.leases if l.scope_id == scope.scope_id]
        active = len([l for l in scope_leases if "Active" in l.address_state])
        reserv = len([r for r in data.reservations if r.scope_id == scope.scope_id])
        import ipaddress
        try:
            start = ipaddress.IPv4Address(scope.start_range)
            end = ipaddress.IPv4Address(scope.end_range)
            total = int(end) - int(start) + 1
        except Exception:
            total = 0
        data.utilization[scope.scope_id] = {
            "total_addresses": total,
            "active_leases": active,
            "reservations": reserv,
            "utilization_pct": round(active / total * 100, 1) if total > 0 else 0,
        }

    logger.info("DHCP: %d scopes, %d leases, %d reservations from %s",
                len(data.scopes), len(data.leases), len(data.reservations), server_ip)
    return data


# --- DNS Server ---

@dataclass
class DNSServerData:
    """Data from a Windows DNS Server."""
    server_ip: str = ""
    forwarders: list[str] = field(default_factory=list)
    listening_ips: list[str] = field(default_factory=list)
    recursion_enabled: bool = True


def collect_dns_server(server_ip: str, username: str = "",
                       password: str = "", domain: str = "") -> Optional[DNSServerData]:
    """Collect DNS server configuration from a Windows DNS Server."""
    cred_arg = _build_cred_arg(username, password, domain)
    data = DNSServerData(server_ip=server_ip)

    # Get DNS server settings
    cmd = (
        f"Get-DnsServer -ComputerName '{server_ip}' | "
        "Select-Object -ExpandProperty ServerSetting | "
        "Select-Object ListeningIPAddress, AllIPAddress | "
        "ConvertTo-Json -Depth 3"
    )
    settings = _run_ps_json(cmd, cred_arg)

    # Get forwarders
    cmd = (
        f"Get-DnsServerForwarder -ComputerName '{server_ip}' | "
        "Select-Object -ExpandProperty IPAddress | "
        "ForEach-Object {{ $_.IPAddressToString }} | ConvertTo-Json"
    )
    fwd = _run_ps_json(cmd, cred_arg)
    if fwd:
        if isinstance(fwd, list):
            data.forwarders = [str(f) for f in fwd]

    # Get recursion
    cmd = (
        f"Get-DnsServerRecursion -ComputerName '{server_ip}' | "
        "Select-Object Enable | ConvertTo-Json"
    )
    rec = _run_ps_json(cmd, cred_arg)
    if rec and isinstance(rec, list) and rec:
        data.recursion_enabled = bool(rec[0].get("Enable", True))

    logger.info("DNS server %s: forwarders=%s", server_ip, data.forwarders)
    return data


# --- Active Directory ---

@dataclass
class ADComputer:
    """AD computer account."""
    name: str = ""
    dns_hostname: str = ""
    operating_system: str = ""
    ipv4_address: str = ""
    last_logon: str = ""
    distinguished_name: str = ""
    enabled: bool = True


@dataclass
class ADDomainController:
    """AD Domain Controller info."""
    hostname: str = ""
    ip_address: str = ""
    site: str = ""
    is_global_catalog: bool = False
    os_version: str = ""
    roles: list[str] = field(default_factory=list)


@dataclass
class ADData:
    """Data from Active Directory."""
    domain_name: str = ""
    domain_controllers: list[ADDomainController] = field(default_factory=list)
    computers: list[ADComputer] = field(default_factory=list)


def collect_ad_data(username: str = "", password: str = "",
                    domain: str = "") -> Optional[ADData]:
    """Collect data from Active Directory."""
    cred_arg = _build_cred_arg(username, password, domain)
    data = ADData()

    # Check if AD module is available
    check = _run_ps_json(
        "if (Get-Module -ListAvailable ActiveDirectory) "
        "{ @{available=$true} | ConvertTo-Json } "
        "else { @{available=$false} | ConvertTo-Json }"
    )
    if not check or not check[0].get("available"):
        logger.info("Active Directory PowerShell module not available")
        return None

    # Get Domain info
    cmd = (
        "Get-ADDomain | Select-Object DNSRoot, Forest, Name | ConvertTo-Json -Depth 2"
    )
    dom = _run_ps_json(cmd, cred_arg)
    if dom:
        data.domain_name = dom[0].get("DNSRoot", "")

    # Get Domain Controllers
    cmd = (
        "Get-ADDomainController -Filter * | "
        "Select-Object HostName, IPv4Address, Site, IsGlobalCatalog, "
        "OperatingSystem, OperationMasterRoles | ConvertTo-Json -Depth 3"
    )
    dcs = _run_ps_json(cmd, cred_arg)
    if dcs:
        for dc in dcs:
            data.domain_controllers.append(ADDomainController(
                hostname=dc.get("HostName", ""),
                ip_address=dc.get("IPv4Address", ""),
                site=dc.get("Site", ""),
                is_global_catalog=dc.get("IsGlobalCatalog", False),
                os_version=dc.get("OperatingSystem", ""),
                roles=dc.get("OperationMasterRoles", []) or [],
            ))

    # Get computers
    cmd = (
        "Get-ADComputer -Filter * -Properties DNSHostName, OperatingSystem, "
        "IPv4Address, LastLogonDate, Enabled | "
        "Select-Object Name, DNSHostName, OperatingSystem, IPv4Address, "
        "LastLogonDate, DistinguishedName, Enabled | ConvertTo-Json -Depth 3"
    )
    computers = _run_ps_json(cmd, cred_arg, timeout=120)
    if computers:
        for c in computers:
            data.computers.append(ADComputer(
                name=c.get("Name", ""),
                dns_hostname=c.get("DNSHostName", "") or "",
                operating_system=c.get("OperatingSystem", "") or "",
                ipv4_address=c.get("IPv4Address", "") or "",
                last_logon=str(c.get("LastLogonDate", "") or ""),
                distinguished_name=c.get("DistinguishedName", "") or "",
                enabled=c.get("Enabled", True),
            ))

    logger.info("AD: domain=%s, %d DCs, %d computers",
                data.domain_name, len(data.domain_controllers), len(data.computers))
    return data


def discover_dhcp_servers_from_ad(username: str = "", password: str = "",
                                   domain: str = "") -> list[str]:
    """Try to discover authorized DHCP servers from AD."""
    cred_arg = _build_cred_arg(username, password, domain)
    cmd = (
        "Get-DhcpServerInDC | Select-Object IPAddress, DnsName | "
        "ConvertTo-Json -Depth 2"
    )
    result = _run_ps_json(cmd, cred_arg)
    if result:
        return [str(s.get("IPAddress", "")) for s in result if s.get("IPAddress")]
    return []
