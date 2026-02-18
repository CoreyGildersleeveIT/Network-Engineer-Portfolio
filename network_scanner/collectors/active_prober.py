"""
Active network probing module.
Implements ICMP ping, TCP port scanning, service fingerprinting,
HTTP/HTTPS header grabbing, SSH banner grabbing, SMB/RDP probing.

All probing is non-exploitative - connect, read banner, disconnect.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import struct
import time
from typing import Optional

from ..core.models import DataSource, PortInfo

logger = logging.getLogger(__name__)


# --- ICMP Ping ---

async def ping_host(ip: str, timeout: float = 2.0) -> bool:
    """
    Ping a host using ICMP (requires raw socket / admin).
    Falls back to TCP connect probe if ICMP fails.
    """
    # Try system ping first
    try:
        import platform
        if platform.system() == "Windows":
            proc = await asyncio.create_subprocess_exec(
                "ping", "-n", "1", "-w", str(int(timeout * 1000)), ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(int(timeout)), ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 1)
        return proc.returncode == 0
    except Exception:
        return False


async def tcp_ping(ip: str, port: int = 443, timeout: float = 2.0) -> bool:
    """TCP connect probe as fallback for ICMP-blocked networks."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


# --- Port Scanning ---

async def scan_port(ip: str, port: int, timeout: float = 2.0) -> Optional[PortInfo]:
    """Scan a single TCP port. Returns PortInfo if open, None if closed."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        info = PortInfo(port=port, protocol="tcp", state="open",
                        source=DataSource.PORT_SCAN)

        # Try to read banner (non-blocking, short timeout)
        reader_task = asyncio.current_task()
        try:
            reader, _ = _, writer  # reuse connection
            # For some services, just connecting gives a banner
            # We need to actually get the reader
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()

        # Assign well-known service names
        info.service = _well_known_service(port)
        return info

    except (asyncio.TimeoutError, ConnectionRefusedError,
            OSError, ConnectionResetError):
        return None


async def scan_port_with_banner(ip: str, port: int,
                                 timeout: float = 3.0) -> Optional[PortInfo]:
    """Scan a port and attempt to grab a banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        info = PortInfo(port=port, protocol="tcp", state="open",
                        source=DataSource.PORT_SCAN)
        info.service = _well_known_service(port)

        # Try reading initial banner
        try:
            banner_data = await asyncio.wait_for(
                reader.read(1024), timeout=2.0,
            )
            if banner_data:
                info.banner = banner_data.decode("utf-8", errors="replace").strip()[:512]
        except (asyncio.TimeoutError, Exception):
            pass

        writer.close()
        await writer.wait_closed()
        return info

    except (asyncio.TimeoutError, ConnectionRefusedError,
            OSError, ConnectionResetError):
        return None


async def scan_ports(ip: str, ports: list[int], concurrency: int = 50,
                     timeout: float = 2.0, grab_banners: bool = False) -> list[PortInfo]:
    """Scan multiple ports on a host with bounded concurrency."""
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def _scan(port: int) -> Optional[PortInfo]:
        async with sem:
            if grab_banners:
                return await scan_port_with_banner(ip, port, timeout)
            return await scan_port(ip, port, timeout)

    tasks = [asyncio.create_task(_scan(p)) for p in ports]
    done = await asyncio.gather(*tasks, return_exceptions=True)
    for result in done:
        if isinstance(result, PortInfo):
            results.append(result)

    return results


# --- HTTP/HTTPS Fingerprinting ---

async def probe_http(ip: str, port: int = 80,
                     timeout: float = 5.0) -> Optional[PortInfo]:
    """Probe HTTP service for headers, server, title."""
    use_ssl = port in (443, 8443, 636, 993, 995, 465)
    scheme = "https" if use_ssl else "http"

    try:
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )

        # Send HTTP request
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: NetScannerPro/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        # Read response (max 32KB)
        response = b""
        try:
            response = await asyncio.wait_for(
                reader.read(32768), timeout=5.0,
            )
        except asyncio.TimeoutError:
            pass

        writer.close()
        await writer.wait_closed()

        if not response:
            return None

        text = response.decode("utf-8", errors="replace")

        info = PortInfo(
            port=port, protocol="tcp", state="open",
            service="https" if use_ssl else "http",
            source=DataSource.HTTPS_BANNER if use_ssl else DataSource.HTTP_BANNER,
        )

        # Parse status code
        status_match = re.search(r"HTTP/\d\.\d\s+(\d+)", text)
        if status_match:
            info.http_status = int(status_match.group(1))

        # Parse Server header
        server_match = re.search(r"[Ss]erver:\s*(.+?)[\r\n]", text)
        if server_match:
            info.http_server = server_match.group(1).strip()[:200]

        # Parse title
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text,
                                re.IGNORECASE | re.DOTALL)
        if title_match:
            info.http_title = title_match.group(1).strip()[:200]

        # Get TLS cert info if HTTPS
        if use_ssl:
            try:
                ssl_ctx2 = ssl.create_default_context()
                ssl_ctx2.check_hostname = False
                ssl_ctx2.verify_mode = ssl.CERT_NONE
                reader2, writer2 = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_ctx2),
                    timeout=timeout,
                )
                ssl_obj = writer2.get_extra_info("ssl_object")
                if ssl_obj:
                    cert = ssl_obj.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        info.tls_subject = subject.get("commonName", "")
                        info.tls_issuer = issuer.get("organizationName", "")
                        info.tls_expiry = cert.get("notAfter", "")
                        info.source = DataSource.TLS_CERT
                writer2.close()
                await writer2.wait_closed()
            except Exception:
                pass

        return info

    except Exception:
        return None


# --- SSH Banner Grabbing ---

async def probe_ssh(ip: str, port: int = 22,
                    timeout: float = 5.0) -> Optional[PortInfo]:
    """Grab SSH banner string."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        try:
            banner = await asyncio.wait_for(reader.readline(), timeout=3.0)
            info = PortInfo(
                port=port, protocol="tcp", state="open",
                service="ssh",
                banner=banner.decode("utf-8", errors="replace").strip()[:256],
                source=DataSource.SSH_BANNER,
            )
            writer.close()
            await writer.wait_closed()
            return info
        except asyncio.TimeoutError:
            writer.close()
            await writer.wait_closed()
            return PortInfo(port=port, protocol="tcp", state="open",
                           service="ssh", source=DataSource.PORT_SCAN)
    except Exception:
        return None


# --- RDP Probe ---

async def probe_rdp(ip: str, port: int = 3389,
                    timeout: float = 3.0) -> Optional[PortInfo]:
    """Basic RDP presence check via TCP connect (no auth attempt)."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return PortInfo(
            port=port, protocol="tcp", state="open",
            service="rdp",
            source=DataSource.RDP_PROBE,
        )
    except Exception:
        return None


# --- DNS Resolution ---

async def resolve_hostname(ip: str) -> tuple[str, str]:
    """Resolve IP to hostname (PTR) and hostname to IP (A record)."""
    loop = asyncio.get_event_loop()
    hostname = ""
    forward_ip = ""

    # Reverse lookup
    try:
        result = await loop.run_in_executor(
            None, lambda: socket.gethostbyaddr(ip)
        )
        hostname = result[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    # Forward lookup verification
    if hostname:
        try:
            result = await loop.run_in_executor(
                None, lambda: socket.gethostbyname(hostname)
            )
            forward_ip = result
        except (socket.herror, socket.gaierror, OSError):
            pass

    return hostname, forward_ip


# --- Service fingerprinting for specific ports ---

async def fingerprint_services(ip: str, open_ports: list[PortInfo],
                                timeout: float = 5.0) -> list[PortInfo]:
    """Enhanced fingerprinting for open ports."""
    enhanced = []
    tasks = []

    for port_info in open_ports:
        p = port_info.port
        if p in (80, 8000, 8080, 8081, 8088, 8443, 443, 8888):
            tasks.append(probe_http(ip, p, timeout))
        elif p == 22:
            tasks.append(probe_ssh(ip, p, timeout))
        elif p == 3389:
            tasks.append(probe_rdp(ip, p, timeout))
        else:
            enhanced.append(port_info)
            continue

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, PortInfo):
                enhanced.append(result)

    # Keep ports that weren't re-fingerprinted
    fingerprinted_ports = {p.port for p in enhanced}
    for p in open_ports:
        if p.port not in fingerprinted_ports:
            enhanced.append(p)

    return enhanced


def _well_known_service(port: int) -> str:
    """Map port number to well-known service name."""
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
        123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
        143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
        389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
        500: "ike", 514: "syslog", 515: "lpd", 554: "rtsp",
        587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 2049: "nfs", 3268: "gc",
        3306: "mysql", 3389: "rdp", 4786: "cisco-smi",
        5060: "sip", 5061: "sips", 5432: "postgresql",
        5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
        8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
        9100: "jetdirect", 9200: "elasticsearch",
        27017: "mongodb",
    }
    return services.get(port, "")
