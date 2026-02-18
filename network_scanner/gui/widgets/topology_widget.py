"""
Interactive topology visualization widget.
Renders network topology as an interactive node-link diagram
using Qt's QGraphicsView framework.
"""

from __future__ import annotations

import math
from typing import Optional

from PySide6.QtCore import Qt, QPointF, QRectF
from PySide6.QtGui import (
    QBrush, QColor, QFont, QPainter, QPainterPath, QPen,
)
from PySide6.QtWidgets import (
    QComboBox, QGraphicsEllipseItem, QGraphicsItem,
    QGraphicsLineItem, QGraphicsScene, QGraphicsTextItem,
    QGraphicsView, QHBoxLayout, QLabel, QPushButton,
    QVBoxLayout, QWidget,
)


ROLE_COLORS = {
    "router": "#e74c3c",
    "firewall": "#c0392b",
    "switch": "#2980b9",
    "access_point": "#27ae60",
    "server": "#8e44ad",
    "domain_controller": "#d35400",
    "printer": "#7f8c8d",
    "camera": "#16a085",
    "endpoint": "#34495e",
    "unknown": "#555555",
}

ROLE_SHAPES = {
    "router": "diamond",
    "firewall": "hexagon",
    "switch": "rect",
    "access_point": "triangle",
    "server": "rect",
    "domain_controller": "rect",
    "printer": "circle",
    "camera": "circle",
    "endpoint": "circle",
    "unknown": "circle",
}


class DeviceNode(QGraphicsEllipseItem):
    """Interactive device node in the topology view."""

    def __init__(self, node_data: dict, parent=None):
        self.node_data = node_data
        size = self._size_for_layer(node_data.get("layer", 4))
        super().__init__(-size/2, -size/2, size, size, parent)

        role = node_data.get("role", "unknown")
        color = QColor(ROLE_COLORS.get(role, "#555555"))

        self.setBrush(QBrush(color))
        self.setPen(QPen(color.lighter(150), 2))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        # Label
        label = node_data.get("label", node_data.get("ip", ""))
        self.label_item = QGraphicsTextItem(label, self)
        self.label_item.setDefaultTextColor(QColor("#e0e0e0"))
        font = QFont("Segoe UI", 8)
        self.label_item.setFont(font)
        br = self.label_item.boundingRect()
        self.label_item.setPos(-br.width()/2, size/2 + 2)

        # Role label below
        role_label = role.replace("_", " ").title()
        self.role_item = QGraphicsTextItem(role_label, self)
        self.role_item.setDefaultTextColor(color.lighter(130))
        role_font = QFont("Segoe UI", 7)
        self.role_item.setFont(role_font)
        rbr = self.role_item.boundingRect()
        self.role_item.setPos(-rbr.width()/2, size/2 + 14)

        # Tooltip
        tooltip = (
            f"IP: {node_data.get('ip', '')}\n"
            f"Name: {label}\n"
            f"Role: {role_label}\n"
            f"Vendor: {node_data.get('vendor', '')}\n"
            f"Layer: {node_data.get('layer', '?')}"
        )
        self.setToolTip(tooltip)

        self._edges: list[EdgeLine] = []

    def _size_for_layer(self, layer: int) -> float:
        return {1: 50, 2: 40, 3: 30, 4: 20}.get(layer, 20)

    def add_edge(self, edge: EdgeLine):
        self._edges.append(edge)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.update_position()
        return super().itemChange(change, value)


class EdgeLine(QGraphicsLineItem):
    """Edge connecting two device nodes."""

    def __init__(self, source: DeviceNode, target: DeviceNode,
                 edge_data: dict, parent=None):
        super().__init__(parent)
        self.source_node = source
        self.target_node = target
        self.edge_data = edge_data

        edge_type = edge_data.get("type", "connection")
        colors = {
            "lldp": "#3498db",
            "cdp": "#2ecc71",
            "fdb": "#f39c12",
            "gateway": "#e74c3c",
        }
        color = QColor(colors.get(edge_type, "#555555"))
        pen = QPen(color, 2)
        if edge_type == "fdb":
            pen.setStyle(Qt.PenStyle.DashLine)
        self.setPen(pen)

        # Label
        label_text = edge_data.get("label", "")
        if label_text:
            self.label = QGraphicsTextItem(label_text, self)
            self.label.setDefaultTextColor(QColor("#8888aa"))
            self.label.setFont(QFont("Segoe UI", 7))
        else:
            self.label = None

        self.setToolTip(
            f"Type: {edge_type}\n"
            f"Src Port: {edge_data.get('source_port', '')}\n"
            f"Dst Port: {edge_data.get('target_port', '')}"
        )

        source.add_edge(self)
        target.add_edge(self)
        self.update_position()

    def update_position(self):
        p1 = self.source_node.scenePos()
        p2 = self.target_node.scenePos()
        self.setLine(p1.x(), p1.y(), p2.x(), p2.y())
        if self.label:
            mid = QPointF((p1.x() + p2.x()) / 2, (p1.y() + p2.y()) / 2)
            self.label.setPos(mid)


class TopologyWidget(QWidget):
    """Interactive network topology visualization."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._nodes: dict[str, DeviceNode] = {}

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Topology View"))
        toolbar.addStretch()

        self.layer_filter = QComboBox()
        self.layer_filter.addItem("All Layers", 0)
        self.layer_filter.addItem("Core (L1)", 1)
        self.layer_filter.addItem("Distribution (L2)", 2)
        self.layer_filter.addItem("Access (L3)", 3)
        self.layer_filter.addItem("Endpoints (L4)", 4)
        self.layer_filter.currentIndexChanged.connect(self._filter_layer)
        toolbar.addWidget(QLabel("Filter:"))
        toolbar.addWidget(self.layer_filter)

        self.btn_zoom_in = QPushButton("+")
        self.btn_zoom_in.setMaximumWidth(30)
        self.btn_zoom_in.clicked.connect(lambda: self.view.scale(1.2, 1.2))
        self.btn_zoom_out = QPushButton("-")
        self.btn_zoom_out.setMaximumWidth(30)
        self.btn_zoom_out.clicked.connect(lambda: self.view.scale(0.8, 0.8))
        self.btn_fit = QPushButton("Fit")
        self.btn_fit.setMaximumWidth(50)
        self.btn_fit.clicked.connect(self._fit_view)

        toolbar.addWidget(self.btn_zoom_in)
        toolbar.addWidget(self.btn_zoom_out)
        toolbar.addWidget(self.btn_fit)

        layout.addLayout(toolbar)

        # Graphics scene and view
        self.scene = QGraphicsScene()
        self.scene.setBackgroundBrush(QBrush(QColor("#0f0f23")))

        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        layout.addWidget(self.view)

        # Info bar
        self.info_label = QLabel("No topology data. Run a scan with SNMP enabled.")
        self.info_label.setStyleSheet("color: #8888aa;")
        layout.addWidget(self.info_label)

    def load_topology(self, topo_json: str):
        """Load topology from JSON graph format."""
        import json
        try:
            data = json.loads(topo_json)
        except (json.JSONDecodeError, TypeError):
            return

        self.scene.clear()
        self._nodes.clear()

        nodes = data.get("nodes", [])
        edges = data.get("edges", [])

        # Create nodes
        for n in nodes:
            node = DeviceNode(n)
            node.setPos(n.get("x", 0), n.get("y", 0))
            self.scene.addItem(node)
            self._nodes[n.get("id", "")] = node

        # Create edges
        for e in edges:
            src = self._nodes.get(e.get("source", ""))
            tgt = self._nodes.get(e.get("target", ""))
            if src and tgt:
                edge = EdgeLine(src, tgt, e)
                self.scene.addItem(edge)

        self.info_label.setText(
            f"Topology: {len(nodes)} nodes, {len(edges)} edges"
        )
        self._fit_view()

    def _fit_view(self):
        self.view.fitInView(self.scene.itemsBoundingRect(),
                            Qt.AspectRatioMode.KeepAspectRatio)

    def _filter_layer(self, index):
        layer = self.layer_filter.currentData()
        for nid, node in self._nodes.items():
            if layer == 0:
                node.setVisible(True)
            else:
                node.setVisible(node.node_data.get("layer", 4) == layer)
