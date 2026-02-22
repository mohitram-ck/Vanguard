# 🛡️ Vanguard — AI-Powered Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Vanguard is a production-grade, modular **Network Intrusion Detection System (NIDS)**
built in Python. It uses machine learning to detect anomalous network traffic in
real time and automatically triggers firewall-level responses.

---

## 🧠 Architecture
```
PacketCaptureEngine  →  FeatureExtractor  →  AnomalyDetector  →  MitigationEngine
   (scapy)               (pandas/numpy)     (Isolation Forest)   (iptables/netsh)
```

Each module runs in its own background thread and communicates
through thread-safe queues — fully decoupled and scalable.

---

## 🔧 Modules

| Module | File | Description |
|---|---|---|
| Data Ingestion | `vanguard/ingestion/packet_capture.py` | Async packet capture via Scapy |
| Feature Extraction | `vanguard/features/feature_extractor.py` | Rolling-window statistical features |
| AI Engine | `vanguard/ai_engine/detector.py` | Isolation Forest anomaly detection |
| Mitigation | `vanguard/mitigation/responder.py` | Firewall blocking + audit logging |

---

## ⚡ Quickstart

### 1. Clone & install dependencies
```bash
git clone https://github.com/YOUR_USERNAME/vanguard.git
cd vanguard
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run in Demo Mode (no network/admin required)
```bash
python main.py --mode demo
```

### 3. Train on real network traffic (requires Npcap on Windows)
```bash
python main.py --mode train --train-duration 60
```

### 4. Run live detection
```bash
python main.py --mode run
```

---

## 🚨 Detection Capabilities

| Attack Type | Detection Signal |
|---|---|
| SYN Flood | High `syn_ratio` |
| Port Scan | High `unique_dst_ports` / `max_ports_per_src` |
| DDoS | Spike in `packet_rate` + `total_packets` |
| Distributed Attack | Low `src_ip_entropy` |
| Payload Anomaly | Deviation in `payload_mean` / `payload_std` |

---

## 🔒 Security Features

- **Tamper-evident audit logs** — SHA-256 hash-chained JSONL entries
- **Cross-platform firewall** — `iptables` (Linux), `netsh` (Windows), `pfctl` (macOS)
- **IP whitelist** — Prevents accidental self-blocking
- **Dry-run mode** — Safe testing without executing firewall commands

---

## 📁 Project Structure
```
vanguard/
├── vanguard/
│   ├── ingestion/
│   │   └── packet_capture.py
│   ├── features/
│   │   └── feature_extractor.py
│   ├── ai_engine/
│   │   └── detector.py
│   └── mitigation/
│       └── responder.py
├── logs/
├── tests/
├── main.py
├── requirements.txt
└── README.md
```

---

## 🖥️ Requirements

- Python 3.10+
- [Npcap](https://npcap.com) (Windows only, for live capture)
- Admin/root privileges (for live capture + firewall rules)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.