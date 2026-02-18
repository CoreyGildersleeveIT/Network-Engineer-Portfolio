# NetScanner Pro - Network Technician Scanner & Mapper

A portable, GUI-based network inventory and topology mapping tool for authorized network technicians.

## Features

- **Multi-source Discovery**: ARP, DHCP, DNS, SNMP, and active probing to build a high-fidelity device inventory
- **SNMP Collection**: Walks sysDescr, sysName, interface tables, LLDP/CDP neighbor tables, and MAC address (FDB) tables
- **Windows Infrastructure Detection**: Identifies domain controllers, DHCP servers, and DNS servers via LDAP/DNS SRV records
- **Correlation Engine**: Merges data from multiple sources with confidence scoring per field
- **Role Classification**: Automatically classifies devices as routers, switches, APs, servers, printers, etc.
- **Topology Mapping**: Builds network graph from LLDP/CDP/FDB data with hierarchical layer assignment
- **Interactive GUI**: PySide6 (Qt) dark-themed interface with scan profiles, real-time progress, results browser, and interactive topology view
- **Multi-format Export**: CSV, JSON, HTML report, PDF report, and GraphML topology
- **Credential Vault**: Encrypted storage for SNMP communities and Windows credentials
- **Authorization Gate**: Requires user acknowledgment before scanning

## Requirements

- Python 3.10+
- Administrator/root privileges (for raw socket scanning)
- Network access to target subnets

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Run the GUI application
python -m network_scanner

# Build standalone executable
python -m network_scanner.packaging.build
```

## Project Structure

```
network_scanner/
├── __init__.py              # Package metadata
├── __main__.py              # Application entry point
├── core/
│   ├── config.py            # Application settings and paths
│   ├── credentials.py       # Encrypted credential vault
│   ├── database.py          # SQLite database layer
│   ├── models.py            # Data models (DeviceRecord, ScanProfile)
│   ├── oui.py               # MAC vendor lookup
│   ├── correlation.py       # Multi-source data correlation engine
│   ├── role_classifier.py   # Device role classification
│   └── scan_engine.py       # Orchestrates scan phases
├── collectors/
│   ├── active_prober.py     # Ping sweep & port scanning
│   ├── arp_collector.py     # ARP table collection
│   ├── dhcp_listener.py     # DHCP lease discovery
│   ├── dns_collector.py     # DNS resolution & SRV queries
│   ├── local_context.py     # Local host/gateway detection
│   ├── snmp_collector.py    # SNMP walks (sysDescr, LLDP, CDP, FDB)
│   └── windows_infra.py     # AD/DHCP/DNS server discovery
├── topology/
│   └── graph_builder.py     # Network graph from LLDP/CDP/FDB data
├── reporting/
│   └── exporter.py          # CSV, JSON, HTML, PDF, GraphML export
├── gui/
│   ├── auth_dialog.py       # Authorization gate dialog
│   ├── main_window.py       # Main application window
│   ├── styles.py            # Dark theme stylesheet
│   └── widgets/
│       ├── credentials_widget.py   # Credential management UI
│       ├── profile_widget.py       # Scan profile configuration
│       ├── results_widget.py       # Results browser / device table
│       ├── scan_runner_widget.py   # Real-time scan progress
│       └── topology_widget.py      # Interactive topology visualization
├── packaging/
│   ├── build.py             # Build script
│   └── netscanner.spec      # PyInstaller spec
└── requirements.txt
```

## Authorization

This tool includes an authorization gate that requires the operator to acknowledge authorized use before scanning. All scan sessions are logged with the authorizing user's name.

## License

For authorized use in network documentation and inventory projects.
