"""
DHCP Offer Listener and Rogue DHCP Detection.

Sends a DHCP DISCOVER and listens for DHCPOFFER packets.
Collects: offering server IP, offered address, subnet mask, router,
DNS servers, domain name, lease time.
Flags multiple offers from different servers.

Requires admin/root privileges for raw socket access.
"""

from __future__ import annotations

import logging
import os
import platform
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DHCPOffer:
    """A DHCP OFFER response."""
    server_ip: str = ""         # Option 54 - DHCP Server Identifier
    offered_ip: str = ""        # yiaddr
    subnet_mask: str = ""       # Option 1
    router: str = ""            # Option 3
    dns_servers: list[str] = field(default_factory=list)  # Option 6
    domain_name: str = ""       # Option 15
    lease_time: int = 0         # Option 51
    ntp_servers: list[str] = field(default_factory=list)  # Option 42
    raw_options: dict = field(default_factory=dict)


def is_admin() -> bool:
    """Check if running with admin/root privileges."""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def detect_dhcp_servers(timeout: float = 10.0,
                        interface_ip: str = "0.0.0.0") -> list[DHCPOffer]:
    """
    Send DHCP DISCOVER and collect DHCPOFFER responses.
    Returns list of offers (multiple = possible rogue DHCP).
    """
    if not is_admin():
        logger.warning(
            "DHCP detection requires admin/root privileges. "
            "Run the application as Administrator to enable this feature."
        )
        return []

    offers = []
    xid = random.randint(1, 0xFFFFFFFF)
    client_mac = bytes([0x00, 0x11, 0x22, 0x33, 0x44, random.randint(0, 255)])

    try:
        discover_packet = _build_dhcp_discover(xid, client_mac)
        sock = _create_dhcp_socket(interface_ip)
        if not sock:
            return []

        try:
            # Send DHCP DISCOVER to broadcast
            sock.sendto(discover_packet, ("255.255.255.255", 67))
            logger.info("Sent DHCP DISCOVER (xid=0x%08x)", xid)

            # Listen for responses
            start = time.time()
            while time.time() - start < timeout:
                sock.settimeout(max(0.5, timeout - (time.time() - start)))
                try:
                    data, addr = sock.recvfrom(4096)
                    offer = _parse_dhcp_offer(data, xid)
                    if offer:
                        logger.info("Received DHCP OFFER from %s (offered %s)",
                                    offer.server_ip, offer.offered_ip)
                        offers.append(offer)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.debug("Error receiving DHCP packet: %s", e)
        finally:
            sock.close()

    except PermissionError:
        logger.warning("Permission denied for raw socket. Run as Administrator.")
    except Exception as e:
        logger.error("DHCP detection error: %s", e)

    if len(offers) > 1:
        servers = set(o.server_ip for o in offers)
        if len(servers) > 1:
            logger.warning(
                "MULTIPLE DHCP SERVERS DETECTED: %s - Possible rogue DHCP!",
                ", ".join(servers)
            )

    return offers


def _create_dhcp_socket(interface_ip: str) -> Optional[socket.socket]:
    """Create a UDP socket for DHCP discovery."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if platform.system() == "Windows":
            # Windows needs to bind to specific interface or 0.0.0.0
            sock.bind((interface_ip, 68))
        else:
            sock.bind(("0.0.0.0", 68))

        return sock
    except Exception as e:
        logger.error("Failed to create DHCP socket: %s", e)
        return None


def _build_dhcp_discover(xid: int, client_mac: bytes) -> bytes:
    """Build a DHCP DISCOVER packet."""
    packet = bytearray()

    # BOOTP header
    packet.append(1)           # op: BOOTREQUEST
    packet.append(1)           # htype: Ethernet
    packet.append(6)           # hlen: MAC length
    packet.append(0)           # hops
    packet.extend(struct.pack("!I", xid))  # xid
    packet.extend(struct.pack("!H", 0))    # secs
    packet.extend(struct.pack("!H", 0x8000))  # flags: broadcast
    packet.extend(b"\x00" * 4)   # ciaddr
    packet.extend(b"\x00" * 4)   # yiaddr
    packet.extend(b"\x00" * 4)   # siaddr
    packet.extend(b"\x00" * 4)   # giaddr
    packet.extend(client_mac)    # chaddr (6 bytes)
    packet.extend(b"\x00" * 10)  # chaddr padding
    packet.extend(b"\x00" * 64)  # sname
    packet.extend(b"\x00" * 128) # file

    # DHCP magic cookie
    packet.extend(b"\x63\x82\x53\x63")

    # DHCP options
    # Option 53: DHCP Message Type = DISCOVER (1)
    packet.extend(bytes([53, 1, 1]))
    # Option 55: Parameter Request List
    packet.extend(bytes([55, 7, 1, 3, 6, 15, 42, 51, 54]))
    # Option 61: Client Identifier
    packet.extend(bytes([61, 7, 1]))
    packet.extend(client_mac)
    # End
    packet.append(255)

    # Pad to minimum length
    while len(packet) < 300:
        packet.append(0)

    return bytes(packet)


def _parse_dhcp_offer(data: bytes, expected_xid: int) -> Optional[DHCPOffer]:
    """Parse a DHCP OFFER response."""
    if len(data) < 240:
        return None

    # Verify it's a BOOTREPLY
    if data[0] != 2:
        return None

    # Verify XID
    xid = struct.unpack("!I", data[4:8])[0]
    if xid != expected_xid:
        return None

    offer = DHCPOffer()

    # yiaddr (offered IP)
    offer.offered_ip = socket.inet_ntoa(data[16:20])

    # siaddr (server IP from header)
    siaddr = socket.inet_ntoa(data[20:24])

    # Parse DHCP options (starting after magic cookie at byte 240)
    i = 240
    is_offer = False
    while i < len(data):
        opt = data[i]
        if opt == 255:  # End
            break
        if opt == 0:    # Padding
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        opt_data = data[i + 2:i + 2 + length]
        i += 2 + length

        if opt == 53 and length >= 1:  # DHCP Message Type
            if opt_data[0] == 2:  # OFFER
                is_offer = True
        elif opt == 1 and length >= 4:  # Subnet Mask
            offer.subnet_mask = socket.inet_ntoa(opt_data[:4])
        elif opt == 3 and length >= 4:  # Router
            offer.router = socket.inet_ntoa(opt_data[:4])
        elif opt == 6:  # DNS Servers
            for j in range(0, length, 4):
                if j + 4 <= length:
                    offer.dns_servers.append(socket.inet_ntoa(opt_data[j:j+4]))
        elif opt == 15:  # Domain Name
            offer.domain_name = opt_data.decode("ascii", errors="ignore").rstrip("\x00")
        elif opt == 42:  # NTP Servers
            for j in range(0, length, 4):
                if j + 4 <= length:
                    offer.ntp_servers.append(socket.inet_ntoa(opt_data[j:j+4]))
        elif opt == 51 and length >= 4:  # Lease Time
            offer.lease_time = struct.unpack("!I", opt_data[:4])[0]
        elif opt == 54 and length >= 4:  # Server Identifier
            offer.server_ip = socket.inet_ntoa(opt_data[:4])

        offer.raw_options[opt] = opt_data.hex()

    if not is_offer:
        return None

    # Use siaddr if server_ip not set by option 54
    if not offer.server_ip and siaddr != "0.0.0.0":
        offer.server_ip = siaddr

    return offer
