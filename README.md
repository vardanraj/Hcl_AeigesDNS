# AegisDNS — DNS Tunneling & Exfiltration Detection Engine

A hybrid rule-fused, machine-learning-driven security analytics platform engineered to detect unauthorized DNS tunneling, periodic Command & Control (C2) heartbeat beaconing, and volumetric data exfiltration over standard UDP/TCP Port 53 network egress.

---

## 🌟 Key Features

- **Dual Ingestion Engine**:
  - Live promiscuous packet sniffing via Npcap / Scapy (`/api/capture`).
  - Offline `.pcap` and `.pcapng` batch file uploads up to 50MB (`/api/upload`).
  - Built-in synthetic traffic generator for benign baseline and 5 attack families (`/api/synthetic`).
- **RFC 6762 mDNS Noise Filter**:
  - Early-exit filter for multicast DNS and zero-configuration discovery queries (`.local`, `_tcp`, `_udp`).
- **13 Lexical & Entropy Feature Extraction**:
  - Shannon entropy, subdomain/qname length, digit ratio, hex ratio, uppercase ratio, and query record types (TXT, CNAME, NULL, A).
- **Multi-Detector Analytics Tier**:
  - **Rule-Based Detector**: Subdomain entropy, character ratios, and high-risk query records.
  - **C2 Beacon Detector**: Stateful inter-arrival time deltas with low jitter variance ($\text{CV} < 0.20$).
  - **Volumetric Exfiltration Detector**: Subdomain cardinality ($\ge 15$) and cumulative payload volume ($\ge 3,000$ B).
  - **Supervised Random Forest ML Classifier**: 13-feature anomaly probability inference.
- **Incident Score Fusion**:
  - Weighted composite risk scoring: $\text{Risk} = (0.30 \times \text{Rule} + 0.25 \times \text{Beacon} + 0.25 \times \text{Exfil} + 0.20 \times \text{ML}) \times 100$.
  - Severity classification: Critical ($\ge 80$), High ($\ge 60$), Medium ($\ge 35$), Low ($< 35$).
- **SOC Operations Interface**:
  - Real-time React SPA with WebSocket streaming (`/ws/live`).
  - Interactive forensic drawer with sub-scores, timeline evidence, and recommended remediation.

---

## 📊 Empirical Benchmarks (5-Seed Cross-Validation)

Evaluated across 5 attack families (`iodine_base32`, `dnscat2_hex`, `cobalt_strike_txt`, `low_and_slow_exfil`, `dict_words_c2`):

| Detector | Precision (Mean) | Recall (Mean) | F1-Score (Mean) | ROC-AUC (Mean) | FP / 1k Benign |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Fused Ensemble** | **0.8368 ± 0.0392** | **0.9983 ± 0.0015** | **0.9017 ± 0.0278** | **0.9844 ± 0.0105** | **108.19 ± 32.55** |
| ML Calibrated | 0.7090 ± 0.0849 | 0.8436 ± 0.0498 | 0.7177 ± 0.0716 | 0.9450 ± 0.0261 | 179.76 ± 27.65 |
| Rules Only | 0.6147 ± 0.0096 | 0.9977 ± 0.0017 | 0.7512 ± 0.0105 | 0.7860 ± 0.0080 | 316.92 ± 3.91 |
| ML Default | 0.5677 ± 0.0317 | 0.7597 ± 0.0144 | 0.6369 ± 0.0235 | 0.9450 ± 0.0261 | 158.34 ± 29.31 |

---

## 🛠️ Architecture Overview

```
                      +------------------------------------+
                      |    Raw DNS Ingestion (Port 53)     |
                      | (Npcap Live Sniffer / PCAP Upload) |
                      +-----------------+------------------+
                                        |
                                        v
                      +-----------------+------------------+
                      |   RFC 6762 mDNS Allowlist Filter   |
                      +-----------------+------------------+
                                        | (Non-allowlisted)
                                        v
                      +-----------------+------------------+
                      | 13-Feature Extraction (Entropy/Len)|
                      +-----------------+------------------+
                                        |
               +------------------------+------------------------+
               |                        |                        |
               v                        v                        v
       +---------------+        +---------------+        +---------------+
       |  Rule Engine  |        | C2 Beacon (CV)|        |  Exfiltration |
       | (Weight: 30%) |        | (Weight: 25%) |        | (Weight: 25%) |
       +-------+-------+        +-------+-------+        +-------+-------+
               |                        |                        |
               +------------------------+------------------------+
                                        |
                                        +-----> Random Forest ML (Weight: 20%)
                                        |
                                        v
                      +-----------------+------------------+
                      |     Incident Fusion Engine         |
                      |   (0-100 Unified Risk Scoring)     |
                      +-----------------+------------------+
                                        |
                                        v
                      +-----------------+------------------+
                      |  FastAPI / WebSocket (/ws/live)    |
                      |   React SOC Dashboard Interface    |
                      +------------------------------------+
```

---

## 🚀 Quickstart Guide

### 1. Backend Setup

```bash
# Clone the repository
git clone <repository-url>
cd AntiGravity_Workflow

# Install dependencies
pip install -r requirements.txt

# Start backend server
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` to view the dashboard.

---

## 🧪 Testing & Evaluation

```bash
# Run unit tests
python -m pytest

# Run full 5-seed evaluation benchmark
$env:PYTHONPATH="."; python scripts/evaluate.py
```

---

## 👥 Project Credits

- **Student:** Vardan Raj (Roll No: 2400320101233)
- **Institution:** ABES Engineering College, Ghaziabad
- **Department:** Department of Computer Science & Engineering
- **Project Guide:** Mr. Priyan S
