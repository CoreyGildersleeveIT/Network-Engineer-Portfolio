"""
Report exporter module.
Generates CSV, JSON, HTML, PDF, and GraphML exports from scan results.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..core.config import get_exports_dir

logger = logging.getLogger(__name__)


class ReportExporter:
    """Export scan results in multiple formats."""

    def __init__(self, session_id: str, devices: list[dict],
                 infra_summary: dict, topology_graphml: str = "",
                 topology_json: str = "",
                 flat_devices: Optional[list[dict]] = None) -> None:
        self.session_id = session_id
        self.devices = devices
        self.flat_devices = flat_devices or []
        self.infra_summary = infra_summary
        self.topology_graphml = topology_graphml
        self.topology_json = topology_json
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def export_all(self, output_dir: Optional[Path] = None) -> dict[str, str]:
        """Export all formats, return dict of format -> file path."""
        out = output_dir or get_exports_dir() / f"scan_{self.timestamp}"
        out.mkdir(parents=True, exist_ok=True)

        results = {}
        results["csv"] = self.export_csv(out / "assets.csv")
        results["json"] = self.export_json(out / "assets.json")
        results["infra_json"] = self.export_infra_json(out / "infra_summary.json")
        results["html"] = self.export_html(out / "report.html")

        if self.topology_graphml:
            results["graphml"] = self.export_graphml(out / "topology.graphml")
        if self.topology_json:
            results["topology_json"] = str(out / "topology.json")
            (out / "topology.json").write_text(self.topology_json)

        try:
            results["pdf"] = self.export_pdf(out / "report.pdf")
        except Exception as e:
            logger.warning("PDF export failed: %s", e)
            results["pdf"] = ""

        logger.info("Exports saved to %s", out)
        return results

    def export_csv(self, path: Path) -> str:
        """Export flat device inventory to CSV."""
        if not self.flat_devices:
            return ""
        fieldnames = list(self.flat_devices[0].keys()) if self.flat_devices else []
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.flat_devices)
        return str(path)

    def export_json(self, path: Path) -> str:
        """Export structured device inventory to JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.devices, f, indent=2, default=str)
        return str(path)

    def export_infra_json(self, path: Path) -> str:
        """Export infrastructure summary to JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.infra_summary, f, indent=2, default=str)
        return str(path)

    def export_graphml(self, path: Path) -> str:
        """Export topology to GraphML."""
        path.write_text(self.topology_graphml, encoding="utf-8")
        return str(path)

    def export_html(self, path: Path) -> str:
        """Export interactive HTML report."""
        html = self._build_html()
        path.write_text(html, encoding="utf-8")
        return str(path)

    def export_pdf(self, path: Path) -> str:
        """Export PDF report (requires reportlab)."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter, landscape
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
                PageBreak,
            )
        except ImportError:
            logger.info("reportlab not installed - PDF export unavailable")
            return ""

        doc = SimpleDocTemplate(str(path), pagesize=landscape(letter),
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                      fontSize=18, spaceAfter=20)
        h2_style = ParagraphStyle('CustomH2', parent=styles['Heading2'],
                                    fontSize=14, spaceAfter=10)
        body_style = styles['BodyText']
        elements = []

        # Title page
        elements.append(Paragraph("Network Scan Report", title_style))
        elements.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))

        scan_info = self.infra_summary.get("scan_info", {})
        elements.append(Paragraph(
            f"Scanner: {scan_info.get('scanner_hostname', 'N/A')} "
            f"({scan_info.get('scanner_ip', 'N/A')})", body_style))
        elements.append(Spacer(1, 20))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", h2_style))
        totals = self.infra_summary.get("totals", {})
        elements.append(Paragraph(
            f"Total Devices: {totals.get('total_devices', 0)} | "
            f"Alive: {totals.get('total_alive', 0)} | "
            f"SNMP: {totals.get('total_with_snmp', 0)} | "
            f"Switches: {totals.get('total_switches', 0)} | "
            f"APs: {totals.get('total_aps', 0)}", body_style))

        # DHCP / DNS / Gateway info
        dhcp_servers = self.infra_summary.get("dhcp_servers", [])
        if dhcp_servers:
            elements.append(Paragraph(
                f"DHCP Servers: {', '.join(s.get('ip', '') for s in dhcp_servers)}",
                body_style))

        dns_servers = self.infra_summary.get("dns_servers", [])
        if dns_servers:
            elements.append(Paragraph(
                f"DNS Servers: {', '.join(s.get('ip', '') for s in dns_servers)}",
                body_style))

        rogue = self.infra_summary.get("rogue_dhcp", {})
        if rogue.get("detected"):
            elements.append(Paragraph(
                "WARNING: Multiple DHCP servers detected!", body_style))

        elements.append(Spacer(1, 10))
        elements.append(PageBreak())

        # Device Inventory Table
        elements.append(Paragraph("Device Inventory", h2_style))
        if self.flat_devices:
            cols = ["ip_address", "hostname", "mac_address", "vendor",
                    "device_role", "os_hint", "open_ports", "overall_confidence"]
            header = [c.replace("_", " ").title() for c in cols]
            table_data = [header]
            for dev in self.flat_devices[:200]:  # Limit for PDF
                row = []
                for c in cols:
                    val = str(dev.get(c, ""))[:60]
                    row.append(val)
                table_data.append(row)

            col_widths = [90, 90, 100, 80, 70, 80, 140, 50]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTSIZE', (0, 0), (-1, -1), 7),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.white, colors.HexColor('#ECF0F1')]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(t)

        elements.append(PageBreak())

        # Data Sources & Trust
        elements.append(Paragraph("Data Sources & Trust", h2_style))
        quality = self.infra_summary.get("data_quality", {})
        sources = quality.get("sources_used", [])
        if sources:
            elements.append(Paragraph(f"Sources used: {', '.join(sources)}", body_style))
        success = quality.get("source_success", {})
        for src, ok in success.items():
            status = "OK" if ok else "FAILED"
            elements.append(Paragraph(f"  {src}: {status}", body_style))
        limits = quality.get("limitations", [])
        if limits:
            elements.append(Paragraph("Limitations:", body_style))
            for lim in limits:
                elements.append(Paragraph(f"  - {lim}", body_style))

        doc.build(elements)
        return str(path)

    def _build_html(self) -> str:
        """Build interactive HTML report."""
        scan_info = self.infra_summary.get("scan_info", {})
        totals = self.infra_summary.get("totals", {})
        quality = self.infra_summary.get("data_quality", {})

        # Build device rows
        rows_html = ""
        for dev in self.flat_devices:
            role = dev.get("device_role", "unknown")
            role_class = role.replace("_", "-")
            confidence = dev.get("overall_confidence", 0)
            conf_class = "high" if confidence >= 0.7 else "med" if confidence >= 0.4 else "low"
            rows_html += f"""<tr class="role-{role_class}">
  <td>{dev.get('ip_address', '')}</td>
  <td>{dev.get('hostname', '')}</td>
  <td>{dev.get('mac_address', '')}</td>
  <td>{dev.get('vendor', '')}</td>
  <td><span class="badge badge-{role_class}">{role}</span></td>
  <td>{dev.get('os_hint', '')}</td>
  <td>{dev.get('ip_assignment', '')}</td>
  <td class="ports">{dev.get('open_ports', '')}</td>
  <td>{dev.get('switch_port', '')}</td>
  <td><span class="conf conf-{conf_class}">{confidence}</span></td>
</tr>
"""

        # Infrastructure details
        dhcp_html = ""
        for s in self.infra_summary.get("dhcp_servers", []):
            dhcp_html += f"<li>{s.get('ip', '')} - DNS: {s.get('dns_servers', [])}, GW: {s.get('router', '')}</li>"

        dns_html = ""
        for s in self.infra_summary.get("dns_servers", []):
            dns_html += f"<li>{s.get('ip', '')} (source: {s.get('source', '')})</li>"

        dc_html = ""
        for dc in self.infra_summary.get("domain_controllers", []):
            dc_html += f"<li>{dc.get('hostname', '')} ({dc.get('ip', '')})</li>"

        sources_html = ""
        for src, ok in quality.get("source_success", {}).items():
            icon = "check" if ok else "x"
            sources_html += f"<li class='{'ok' if ok else 'fail'}'>{src}: {'OK' if ok else 'FAILED'}</li>"

        rogue_warning = ""
        rogue = self.infra_summary.get("rogue_dhcp", {})
        if rogue.get("detected"):
            rogue_warning = '<div class="alert alert-danger">Multiple DHCP servers detected - possible rogue DHCP!</div>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Scan Report - {scan_info.get('scanner_hostname', '')}</title>
<style>
:root {{ --bg: #1a1a2e; --card: #16213e; --text: #e0e0e0; --accent: #0f3460;
         --green: #2ecc71; --red: #e74c3c; --blue: #3498db; --orange: #f39c12; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
        color: var(--text); padding: 20px; }}
.container {{ max-width: 1600px; margin: 0 auto; }}
h1 {{ color: var(--blue); margin-bottom: 5px; font-size: 24px; }}
h2 {{ color: var(--blue); margin: 20px 0 10px; font-size: 18px; border-bottom: 1px solid var(--accent); padding-bottom: 5px; }}
.subtitle {{ color: #888; margin-bottom: 20px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }}
.card {{ background: var(--card); border-radius: 8px; padding: 15px; }}
.card h3 {{ color: var(--blue); font-size: 14px; margin-bottom: 5px; }}
.card .value {{ font-size: 28px; font-weight: bold; }}
.alert {{ padding: 12px; border-radius: 6px; margin: 10px 0; font-weight: bold; }}
.alert-danger {{ background: rgba(231,76,60,0.2); border: 1px solid var(--red); color: var(--red); }}
table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; }}
th {{ background: var(--accent); color: white; padding: 10px 8px; text-align: left; font-size: 12px;
      position: sticky; top: 0; cursor: pointer; user-select: none; }}
th:hover {{ background: #1a4a7a; }}
td {{ padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 11px; }}
tr:hover {{ background: rgba(52,152,219,0.1); }}
.badge {{ padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: bold; text-transform: uppercase; }}
.badge-switch {{ background: #2980b9; color: white; }}
.badge-router {{ background: #e74c3c; color: white; }}
.badge-firewall {{ background: #c0392b; color: white; }}
.badge-server {{ background: #8e44ad; color: white; }}
.badge-access-point {{ background: #27ae60; color: white; }}
.badge-domain-controller {{ background: #d35400; color: white; }}
.badge-printer {{ background: #7f8c8d; color: white; }}
.badge-camera {{ background: #16a085; color: white; }}
.badge-endpoint {{ background: #2c3e50; color: white; }}
.badge-unknown {{ background: #34495e; color: #95a5a6; }}
.ports {{ max-width: 200px; word-break: break-all; font-family: monospace; font-size: 10px; }}
.conf {{ padding: 2px 6px; border-radius: 4px; font-size: 10px; }}
.conf-high {{ background: rgba(46,204,113,0.2); color: var(--green); }}
.conf-med {{ background: rgba(243,156,18,0.2); color: var(--orange); }}
.conf-low {{ background: rgba(231,76,60,0.2); color: var(--red); }}
ul {{ list-style: none; padding-left: 10px; }}
ul li {{ padding: 3px 0; font-size: 13px; }}
ul li.ok::before {{ content: "✓ "; color: var(--green); }}
ul li.fail::before {{ content: "✗ "; color: var(--red); }}
.filter-bar {{ display: flex; gap: 10px; margin: 10px 0; flex-wrap: wrap; }}
.filter-bar input, .filter-bar select {{ padding: 8px; border: 1px solid var(--accent);
    border-radius: 4px; background: var(--card); color: var(--text); font-size: 13px; }}
.filter-bar input {{ flex: 1; min-width: 200px; }}
</style>
</head>
<body>
<div class="container">
<h1>Network Scan Report</h1>
<p class="subtitle">Scanner: {scan_info.get('scanner_hostname', '')} ({scan_info.get('scanner_ip', '')}) |
   Scan: {scan_info.get('scan_start', '')[:19]} to {scan_info.get('scan_end', '')[:19]}</p>

{rogue_warning}

<div class="grid">
  <div class="card"><h3>Total Devices</h3><div class="value">{totals.get('total_devices', 0)}</div></div>
  <div class="card"><h3>Alive</h3><div class="value">{totals.get('total_alive', 0)}</div></div>
  <div class="card"><h3>SNMP Devices</h3><div class="value">{totals.get('total_with_snmp', 0)}</div></div>
  <div class="card"><h3>Switches</h3><div class="value">{totals.get('total_switches', 0)}</div></div>
  <div class="card"><h3>Access Points</h3><div class="value">{totals.get('total_aps', 0)}</div></div>
</div>

<h2>Infrastructure</h2>
<div class="grid">
  <div class="card"><h3>DHCP Servers</h3><ul>{dhcp_html or '<li>None detected</li>'}</ul></div>
  <div class="card"><h3>DNS Servers</h3><ul>{dns_html or '<li>None detected</li>'}</ul></div>
  <div class="card"><h3>Domain Controllers</h3><ul>{dc_html or '<li>None detected</li>'}</ul></div>
</div>

<h2>Device Inventory</h2>
<div class="filter-bar">
  <input type="text" id="searchBox" placeholder="Filter by IP, hostname, vendor, MAC..." onkeyup="filterTable()">
  <select id="roleFilter" onchange="filterTable()">
    <option value="">All Roles</option>
    <option value="switch">Switch</option><option value="router">Router</option>
    <option value="firewall">Firewall</option><option value="server">Server</option>
    <option value="access_point">Access Point</option><option value="domain_controller">DC</option>
    <option value="printer">Printer</option><option value="camera">Camera</option>
    <option value="endpoint">Endpoint</option><option value="unknown">Unknown</option>
  </select>
</div>
<div style="overflow-x:auto; max-height: 70vh; overflow-y: auto;">
<table id="deviceTable">
<thead><tr>
  <th onclick="sortTable(0)">IP Address</th>
  <th onclick="sortTable(1)">Hostname</th>
  <th onclick="sortTable(2)">MAC Address</th>
  <th onclick="sortTable(3)">Vendor</th>
  <th onclick="sortTable(4)">Role</th>
  <th onclick="sortTable(5)">OS Hint</th>
  <th onclick="sortTable(6)">Assignment</th>
  <th onclick="sortTable(7)">Open Ports</th>
  <th onclick="sortTable(8)">Switch Port</th>
  <th onclick="sortTable(9)">Confidence</th>
</tr></thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>

<h2>Data Sources & Trust</h2>
<div class="card">
  <h3>Sources Used</h3>
  <p>{', '.join(quality.get('sources_used', []))}</p>
  <h3>Source Results</h3>
  <ul>{sources_html}</ul>
</div>

</div>
<script>
function filterTable() {{
  const search = document.getElementById('searchBox').value.toLowerCase();
  const role = document.getElementById('roleFilter').value;
  const rows = document.querySelectorAll('#deviceTable tbody tr');
  rows.forEach(row => {{
    const text = row.textContent.toLowerCase();
    const rowRole = row.className.replace('role-', '').replace('-', '_');
    const matchSearch = !search || text.includes(search);
    const matchRole = !role || rowRole.includes(role);
    row.style.display = (matchSearch && matchRole) ? '' : 'none';
  }});
}}
function sortTable(n) {{
  const table = document.getElementById('deviceTable');
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  const asc = table.dataset.sortCol == n && table.dataset.sortDir !== 'asc';
  table.dataset.sortCol = n;
  table.dataset.sortDir = asc ? 'asc' : 'desc';
  rows.sort((a, b) => {{
    const va = a.cells[n].textContent.trim();
    const vb = b.cells[n].textContent.trim();
    if (n === 0) {{ // IP sort
      const pa = va.split('.').map(x => x.padStart(3, '0')).join('');
      const pb = vb.split('.').map(x => x.padStart(3, '0')).join('');
      return asc ? pa.localeCompare(pb) : pb.localeCompare(pa);
    }}
    return asc ? va.localeCompare(vb) : vb.localeCompare(va);
  }});
  const tbody = table.querySelector('tbody');
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""
