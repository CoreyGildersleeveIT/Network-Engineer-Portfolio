"""
Topology graph builder.
Constructs a network topology graph from LLDP/CDP neighbor data,
switch FDB tables, and device records.

Exports to GraphML, JSON graph, draw.io XML, and Mermaid diagram formats.
"""

from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.models import DeviceRecord, DeviceRole

logger = logging.getLogger(__name__)


@dataclass
class TopoNode:
    """A node in the topology graph."""
    id: str = ""
    label: str = ""
    ip: str = ""
    mac: str = ""
    role: str = "unknown"
    vendor: str = ""
    layer: int = 3  # 1=core, 2=distribution, 3=access, 4=endpoint
    sys_descr: str = ""
    x: float = 0.0
    y: float = 0.0


@dataclass
class TopoEdge:
    """An edge in the topology graph."""
    source: str = ""
    target: str = ""
    source_port: str = ""
    target_port: str = ""
    edge_type: str = "connection"  # connection, lldp, cdp, fdb
    label: str = ""


@dataclass
class TopologyGraph:
    """Complete topology graph."""
    nodes: dict[str, TopoNode] = field(default_factory=dict)
    edges: list[TopoEdge] = field(default_factory=list)


class TopologyBuilder:
    """Builds topology from device records and neighbor data."""

    def __init__(self) -> None:
        self.graph = TopologyGraph()

    def build_from_devices(self, devices: dict[str, DeviceRecord],
                           gateway_ips: list[str] = None) -> TopologyGraph:
        """Build topology from correlated device records."""
        gateway_ips = gateway_ips or []

        # Add all infrastructure devices as nodes
        for ip, device in devices.items():
            role = device.device_role.value
            if isinstance(role, DeviceRole):
                role_str = role.value
            else:
                role_str = str(role)

            # Determine layer
            layer = 4  # endpoint
            if role_str in ("router", "firewall"):
                layer = 1
            elif role_str in ("switch", "domain_controller"):
                layer = 2
            elif role_str in ("access_point", "server", "dhcp_server", "dns_server"):
                layer = 3
            if ip in gateway_ips:
                layer = 1

            label = device.hostname.value or device.dns_name.value or ip
            node = TopoNode(
                id=ip,
                label=label,
                ip=ip,
                mac=device.mac_address.value or "",
                role=role_str,
                vendor=device.vendor.value or "",
                layer=layer,
                sys_descr=device.snmp_sys_descr[:100] if device.snmp_sys_descr else "",
            )
            self.graph.nodes[ip] = node

        # Build edges from LLDP neighbors
        for ip, device in devices.items():
            for neighbor in device.lldp_neighbors:
                mgmt_addr = neighbor.get("mgmt_addr", "")
                remote_name = neighbor.get("remote_sys_name", "")
                local_port = neighbor.get("local_port", "")
                remote_port = neighbor.get("remote_port", "")

                # Find target node
                target_id = ""
                if mgmt_addr and mgmt_addr in self.graph.nodes:
                    target_id = mgmt_addr
                else:
                    for nip, ndev in devices.items():
                        if (ndev.hostname.value == remote_name or
                                ndev.snmp_sys_name == remote_name):
                            target_id = nip
                            break

                if target_id and target_id != ip:
                    edge = TopoEdge(
                        source=ip,
                        target=target_id,
                        source_port=local_port,
                        target_port=remote_port,
                        edge_type="lldp",
                        label=f"{local_port} <-> {remote_port}",
                    )
                    if not self._edge_exists(edge):
                        self.graph.edges.append(edge)

            # Build edges from CDP neighbors
            for neighbor in device.cdp_neighbors:
                addr = neighbor.get("address", "")
                device_id = neighbor.get("device_id", "")
                local_port = neighbor.get("local_port", "")
                remote_port = neighbor.get("device_port", "")

                target_id = ""
                if addr and addr in self.graph.nodes:
                    target_id = addr
                else:
                    for nip, ndev in devices.items():
                        if (ndev.hostname.value == device_id or
                                ndev.snmp_sys_name == device_id):
                            target_id = nip
                            break

                if target_id and target_id != ip:
                    edge = TopoEdge(
                        source=ip,
                        target=target_id,
                        source_port=local_port,
                        target_port=remote_port,
                        edge_type="cdp",
                        label=f"{local_port} <-> {remote_port}",
                    )
                    if not self._edge_exists(edge):
                        self.graph.edges.append(edge)

        # Build edges from switch port mappings (endpoint to switch)
        for ip, device in devices.items():
            if device.switch_port:
                sp = device.switch_port
                switch_ip = sp.switch_ip
                if switch_ip and switch_ip in self.graph.nodes:
                    edge = TopoEdge(
                        source=switch_ip,
                        target=ip,
                        source_port=sp.port_name,
                        target_port="",
                        edge_type="fdb",
                        label=sp.port_name,
                    )
                    if not self._edge_exists(edge):
                        self.graph.edges.append(edge)

        # Connect endpoints to their gateway if no other connection
        for ip, node in self.graph.nodes.items():
            if node.layer == 4 and not any(
                e.source == ip or e.target == ip for e in self.graph.edges
            ):
                for gw in gateway_ips:
                    if gw in self.graph.nodes:
                        self.graph.edges.append(TopoEdge(
                            source=gw, target=ip, edge_type="gateway",
                            label="gateway",
                        ))
                        break

        self._compute_layout()
        logger.info("Topology: %d nodes, %d edges",
                     len(self.graph.nodes), len(self.graph.edges))
        return self.graph

    def _edge_exists(self, new_edge: TopoEdge) -> bool:
        """Check if equivalent edge already exists."""
        for e in self.graph.edges:
            if ((e.source == new_edge.source and e.target == new_edge.target) or
                    (e.source == new_edge.target and e.target == new_edge.source)):
                return True
        return False

    def _compute_layout(self) -> None:
        """Simple hierarchical layout."""
        by_layer: dict[int, list[str]] = {1: [], 2: [], 3: [], 4: []}
        for nid, node in self.graph.nodes.items():
            by_layer.setdefault(node.layer, []).append(nid)

        y_positions = {1: 50, 2: 200, 3: 350, 4: 500}
        for layer, node_ids in by_layer.items():
            y = y_positions.get(layer, 600)
            spacing = max(150, 900 / (len(node_ids) + 1))
            for i, nid in enumerate(node_ids):
                self.graph.nodes[nid].x = 50 + (i + 1) * spacing
                self.graph.nodes[nid].y = y

    # --- Export formats ---

    def export_graphml(self) -> str:
        """Export to GraphML format."""
        ns = "http://graphml.graphstruct.org/xmlns"
        ET.register_namespace("", ns)
        root = ET.Element("graphml", xmlns=ns)

        # Define keys
        for attr in ("label", "ip", "role", "vendor", "layer"):
            ET.SubElement(root, "key", id=attr, **{"for": "node"},
                          attr_name=attr, attr_type="string")
        for attr in ("source_port", "target_port", "edge_type"):
            ET.SubElement(root, "key", id=attr, **{"for": "edge"},
                          attr_name=attr, attr_type="string")

        graph = ET.SubElement(root, "graph", edgedefault="undirected")

        for nid, node in self.graph.nodes.items():
            n = ET.SubElement(graph, "node", id=nid)
            for attr in ("label", "ip", "role", "vendor"):
                d = ET.SubElement(n, "data", key=attr)
                d.text = str(getattr(node, attr, ""))
            d = ET.SubElement(n, "data", key="layer")
            d.text = str(node.layer)

        for i, edge in enumerate(self.graph.edges):
            e = ET.SubElement(graph, "edge", id=f"e{i}",
                              source=edge.source, target=edge.target)
            for attr in ("source_port", "target_port", "edge_type"):
                d = ET.SubElement(e, "data", key=attr)
                d.text = str(getattr(edge, attr, ""))

        return ET.tostring(root, encoding="unicode", xml_declaration=True)

    def export_json_graph(self) -> str:
        """Export to JSON graph format."""
        data = {
            "nodes": [
                {
                    "id": n.id, "label": n.label, "ip": n.ip,
                    "mac": n.mac, "role": n.role, "vendor": n.vendor,
                    "layer": n.layer, "x": n.x, "y": n.y,
                }
                for n in self.graph.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source, "target": e.target,
                    "source_port": e.source_port, "target_port": e.target_port,
                    "type": e.edge_type, "label": e.label,
                }
                for e in self.graph.edges
            ],
        }
        return json.dumps(data, indent=2)

    def export_mermaid(self) -> str:
        """Export to Mermaid diagram syntax."""
        lines = ["graph TD"]
        for nid, node in self.graph.nodes.items():
            safe_id = nid.replace(".", "_")
            shape = {
                "router": f"{safe_id}{{{{{node.label}}}}}",
                "firewall": f"{safe_id}[/{node.label}\\]",
                "switch": f"{safe_id}[{node.label}]",
                "access_point": f"{safe_id}(({node.label}))",
                "server": f"{safe_id}[({node.label})]",
            }.get(node.role, f"{safe_id}[{node.label}]")
            lines.append(f"    {shape}")

        for edge in self.graph.edges:
            src = edge.source.replace(".", "_")
            tgt = edge.target.replace(".", "_")
            if edge.label:
                lines.append(f"    {src} ---|{edge.label}| {tgt}")
            else:
                lines.append(f"    {src} --- {tgt}")

        return "\n".join(lines)

    def export_drawio(self) -> str:
        """Export to draw.io XML format."""
        root = ET.Element("mxfile")
        diagram = ET.SubElement(root, "diagram", name="Network Topology")
        model = ET.SubElement(diagram, "mxGraphModel")
        root_cell = ET.SubElement(model, "root")

        ET.SubElement(root_cell, "mxCell", id="0")
        ET.SubElement(root_cell, "mxCell", id="1", parent="0")

        # Style maps
        style_map = {
            "router": "shape=mxgraph.cisco19.router;",
            "firewall": "shape=mxgraph.cisco19.firewall;",
            "switch": "shape=mxgraph.cisco19.switch;",
            "access_point": "shape=mxgraph.cisco19.access_point;",
            "server": "shape=mxgraph.cisco19.server;",
            "printer": "shape=mxgraph.cisco19.printer;",
            "endpoint": "shape=mxgraph.cisco19.pc;",
        }
        default_style = "rounded=1;whiteSpace=wrap;html=1;"

        cell_id = 2
        id_map = {}

        for nid, node in self.graph.nodes.items():
            style = style_map.get(node.role, default_style)
            style += f"fillColor=#{'FF6B6B' if node.layer == 1 else '4ECDC4' if node.layer == 2 else '45B7D1' if node.layer == 3 else 'DDA0DD'};"

            cell = ET.SubElement(root_cell, "mxCell",
                                 id=str(cell_id), value=node.label,
                                 style=style, vertex="1", parent="1")
            ET.SubElement(cell, "mxGeometry",
                          x=str(int(node.x)), y=str(int(node.y)),
                          width="80", height="80",
                          **{"as": "geometry"})
            id_map[nid] = str(cell_id)
            cell_id += 1

        for edge in self.graph.edges:
            src_id = id_map.get(edge.source)
            tgt_id = id_map.get(edge.target)
            if src_id and tgt_id:
                cell = ET.SubElement(root_cell, "mxCell",
                                     id=str(cell_id),
                                     value=edge.label or "",
                                     style="edgeStyle=orthogonalEdgeStyle;",
                                     edge="1", parent="1",
                                     source=src_id, target=tgt_id)
                ET.SubElement(cell, "mxGeometry",
                              relative="1", **{"as": "geometry"})
                cell_id += 1

        return ET.tostring(root, encoding="unicode", xml_declaration=True)
