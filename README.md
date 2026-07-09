# 🛡️ Network Intrusion Detection System (NIDS)

A Python-based network intrusion detection system that monitors live network traffic and detects three common network-layer attacks in real time — **ARP Spoofing**, **Port Scanning**, and **SYN Flooding**. Built as a practical application of CCNA-level networking knowledge combined with Python packet analysis.

Detection is handled in two layers: rule-based logic for known attack patterns, and an ML-based anomaly detection layer (Isolation Forest) trained on the CICIDS2017 dataset to catch variations that rules alone miss.

---

## 🎯 Attack Scope

| Attack | What It Does | Why It's Dangerous |
|---|---|---|
| **ARP Spoofing** | Links attacker's MAC to a legitimate IP to intercept traffic | Enables man-in-the-middle attacks and credential theft |
| **Port Scanning** | Systematically probes ports to map open services | Reconnaissance — the first step in most network attacks |
| **SYN Flooding** | Floods a host with TCP SYN packets without completing handshakes | Exhausts server resources, causing denial of service |

These three attack types represent the **reconnaissance and disruption phases** of a typical network attack chain — a natural starting point for network-layer intrusion detection.

---

## 🏗️ Architecture

```
NIDS/
├── config/
│   └── config.yaml          # Detection thresholds, time windows, interface settings
│
├── docs/                    # Project documentation and writeups
├── logs/                    # Structured alert and event logs
│
├── nids/
│   ├── rules/               # Rule-based attack detection logic
│   │   ├── __init__.py
│   │   ├── arp_spoof.py     # ARP spoofing detector
│   │   ├── port_scan.py     # Port scan detector
│   │   └── syn_flood.py     # SYN flood detector
│   │
│   ├── ml/                  # ML anomaly detection layer (Phase 2)
│   │   ├── __init__.py
│   │   ├── anomaly.py       # Isolation Forest model
│   │   └── features.py      # Feature extraction from packet data
│   │
│   ├── dashboard/           # Real-time visualization (Phase 3)
│   │   ├── app.py           # Flask web server
│   │   └── templates/       # Dashboard UI
│   │
│   ├── __init__.py
│   ├── capture.py           # Live packet capture using Scapy
│   ├── engine.py            # Central orchestration — runs all detectors
│   ├── alerts.py            # Alert generation, formatting, and output
│   ├── storage.py           # Event persistence and log management
│   └── cli.py               # Command line interface
│
└── tests/
    ├── __init__.py
    ├── test_arp_spoof.py
    ├── test_port_scan.py
    └── test_syn_flood.py
```

---

## 🔍 Detection Logic

### ARP Spoofing
Monitors ARP reply packets and maintains an IP-to-MAC mapping table. Flags any ARP reply where a known IP is being associated with a new, unexpected MAC address — a strong indicator of spoofing activity.

**Detection signal**: Conflicting MAC address for a known IP in ARP reply traffic.

### Port Scanning
Tracks connection attempts per source IP within a configurable time window. Triggers an alert when a single source attempts connections to an unusually high number of distinct destination ports within that window.

**Detection signal**: Source IP exceeds `port_scan_threshold` unique destination ports within `time_window` seconds (configurable in `config.yaml`).

### SYN Flooding
Monitors the ratio of SYN packets to completed TCP handshakes per source IP. A high SYN count with few corresponding SYN-ACK completions within a time window signals flood behavior.

**Detection signal**: SYN packet count exceeds `syn_flood_threshold` with completion ratio below `min_completion_ratio` (configurable in `config.yaml`).

---

## 🤖 ML Anomaly Detection *(Phase 2)* - Not part of CS50 Python

In addition to rule-based detection, an Isolation Forest model trained on the [CICIDS2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html) detects anomalous traffic patterns that explicit rules may miss.

**Features used**:
- Packet rate per source IP
- SYN/ACK ratio per source IP
- Unique destination ports per source IP per time window
- ARP reply frequency

**Purpose**: Catch variations of known attacks and novel patterns outside explicit rule boundaries. Results are compared against rule-based detection to evaluate relative performance.

---

## ⚙️ Configuration

All detection thresholds are externalised in `config/config.yaml`:

```yaml
detection:
  port_scan_threshold: 15        # Unique ports within time window to trigger alert
  syn_flood_threshold: 100       # SYN packets within time window to trigger alert
  min_completion_ratio: 0.2      # Minimum SYN/ACK ratio before flagging
  time_window: 10                # Seconds for rolling detection window

capture:
  interface: "eth0"              # Network interface to monitor
  promiscuous: true

alerts:
  log_file: "logs/alerts.log"
  console_output: true
```

---

## ⚠️ Alert System

When an attack pattern is detected the system:
- Logs the event with timestamp, source IP, attack type, and severity level
- Outputs a real-time warning to the console via CLI
- Writes a structured entry to `logs/alerts.log` for post-analysis
- *(Phase 3)* Displays a live alert on the Flask dashboard

---

## 🖥️ Dashboard *(Phase 3)* - Not part of CS50 Python

A lightweight Flask dashboard will visualize:
- Live network traffic by protocol
- Real-time alerts and detected anomalies
- Per-source IP traffic patterns
- Attack frequency over time

---

## 🧪 Testing and Validation

Unit tests for each detector are in `tests/`. The system is validated against the **CICIDS2017 dataset** — a publicly available labeled network traffic dataset containing real attack scenarios including port scanning, DoS, and brute force traffic.

Validation metrics documented in `docs/`:
- Detection rate per attack type
- False positive rate
- ML vs rule-based comparison

Attack simulation scripts for local isolated testing are included in `tests/`.

> ⚠️ **Legal notice**: This tool is intended for use only on networks you own or have explicit written permission to monitor. Unauthorized network monitoring is illegal in most jurisdictions.

---

## 🛠️ Tech Stack

**Phase 1 — Rules-based detection**
- Python 3.11+
- Scapy — packet capture and dissection
- PyYAML — configuration management

**Phase 2 — ML anomaly detection**
- scikit-learn — Isolation Forest model
- Pandas / NumPy — feature extraction and data processing

**Phase 3 — Dashboard**
- Flask — web server
- Chart.js — real-time traffic visualization

---

## 🚀 Project Status

- [x] Repository initialized
- [x] Project architecture designed
- [x] Configuration structure (`config.yaml`)
- [x] Detection rule files scaffolded
- [x] Test files scaffolded
- [x] Packet capture module (`capture.py`)
- [x] ARP spoofing detector
- [x] Port scan detector
- [x] SYN flood detector
- [ ] Alert manager
- [ ] Storage and logging
- [ ] CLI interface
- [ ] Unit tests passing
- [ ] CICIDS2017 dataset validation
- [ ] ML anomaly detection layer
- [ ] Flask dashboard

---

## 📚 Background

This project came from a specific gap — completing CCNA1 and CCNA2 gave me solid theoretical networking knowledge that I hadn't applied in a security context. Building a system that watches live network traffic, understands what normal looks like, and flags deviations felt like the right way to close that gap practically.

The three attack types chosen represent the reconnaissance and disruption phases of a typical network attack chain, making them a natural starting point for network-layer detection. The ML layer adds a research dimension — comparing rule-based and anomaly-based detection rates against labeled data gives quantifiable results rather than just a working tool.

---
