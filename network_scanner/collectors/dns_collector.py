"""
DNS resolution collector.
Performs forward (A) and reverse (PTR) lookups for discovered hosts.
Uses asyncio-compatible DNS resolution.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DNSResult:
    """Result of a DNS lookup."""
    query: str = ""
    record_type: str = ""  # A, PTR, AAAA
    result: str = ""
    success: bool = False
    error: str = ""


async def resolve_hostname(ip_address: str, timeout: float = 3.0) -> Optional[str]:
    """Reverse DNS lookup: IP -> hostname."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip_address),
            timeout=timeout,
        )
        hostname = result[0]
        if hostname and hostname != ip_address:
            return hostname
    except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
        pass
    return None


async def resolve_ip(hostname: str, timeout: float = 3.0) -> Optional[str]:
    """Forward DNS lookup: hostname -> IP."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, hostname),
            timeout=timeout,
        )
        return result
    except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
        pass
    return None


async def batch_reverse_dns(ip_addresses: list[str],
                            concurrency: int = 50,
                            timeout: float = 3.0) -> dict[str, str]:
    """Batch reverse DNS lookups with concurrency control."""
    results: dict[str, str] = {}
    sem = asyncio.Semaphore(concurrency)

    async def _lookup(ip: str) -> None:
        async with sem:
            hostname = await resolve_hostname(ip, timeout)
            if hostname:
                results[ip] = hostname

    tasks = [_lookup(ip) for ip in ip_addresses]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("Reverse DNS: %d/%d resolved", len(results), len(ip_addresses))
    return results


async def batch_forward_dns(hostnames: list[str],
                            concurrency: int = 50,
                            timeout: float = 3.0) -> dict[str, str]:
    """Batch forward DNS lookups with concurrency control."""
    results: dict[str, str] = {}
    sem = asyncio.Semaphore(concurrency)

    async def _lookup(name: str) -> None:
        async with sem:
            ip = await resolve_ip(name, timeout)
            if ip:
                results[name] = ip

    tasks = [_lookup(name) for name in hostnames]
    await asyncio.gather(*tasks, return_exceptions=True)

    logger.info("Forward DNS: %d/%d resolved", len(results), len(hostnames))
    return results
