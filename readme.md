# PiSentry - ML-Powered Network Intrusion Detection System

> Real-time network intrusion detection on a Raspberry Pi 5, combining a Random Forest classifier with AbuseIPDB threat intelligence to detect and classify attacks across 13 attack vectors.
<img width="2438" height="1463" alt="Network_top" src="https://github.com/user-attachments/assets/41c2d6ab-a4c2-4791-9e12-94fdccd76186" />

---

## Table of Contents

- [Features](#features)
- [Network Setup](#network-setup)
- [Installation](#installation)
- [Running](#running)
- [Dashboard](#dashboard)
- [Model Metrics](#model-metrics)
- [Detection Threshold](#detection-threshold)
- [Project Structure](#project-structure)
- [Technologies](#technologies)

---

## Features

- **Passive out-of-band deployment** via port mirroring - zero impact on live traffic
- **Two-layer detection** - AbuseIPDB threat intelligence checked before ML classification
- **13 attack class classification** using Random Forest trained on CIC-IDS-2017
- **70 statistical flow features** extracted from TCP/UDP sessions in real time
- **SHAP explainability** - top 10 feature contributors printed to terminal on every alert
- **AWS SNS SMS alerts** sent to subscribed users on detection
- **5 minute alert cooldown** per source IP and attack type to prevent spam
- **Flask dashboard** with live traffic chart, alert history and SMS subscriber management
- **SQLite persistence** across system restarts

---

## Network Setup

 <img width="2438" height="1463" alt="Network_top" src="https://github.com/user-attachments/assets/93fab2d0-987f-4f74-b973-438ed68da032" />

---

The TP-Link TL-SG105E managed switch mirrors all traffic from ports 2 and 3 to port 1 where the NIDS listens passively. The NIDS is never in the traffic path.

---

## Installation

### Requirements

- Raspberry Pi 5 (8GB recommended) running Ubuntu Server
- TP-Link TL-SG105E managed switch or equivalent with port mirroring support
- Python 3.12+
- AWS account with SNS configured
- AbuseIPDB API key (free tier - 1,000 checks/day)

### 1. Clone the repository

```bash
git clone https://github.com/LiamDoocey/PiSentry.git
cd PiGuard
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up environment variables

Create a `.env` file in the project root:

```env
ABUSEIPDB_API_KEY= {your_abuseipdb_key}
AWS_ACCESS_KEY_ID= {your_aws_access_key}
AWS_SECRET_KEY= {your_aws_secret_key}
SNS_TOPIC_ARN= {your_aws_sns_topic_arn}
```

### 5. Configure port mirroring on your switch

On the TL-SG105E:
- Log into the switch admin panel at `192.168.100.1`
- Go to **Monitoring > Port Mirror**
- Set port 1 as the mirror destination (NIDS)
- Set ports 2 and 3 as the mirrored source ports

### 6. Place the trained model

Ensure the following files are in the `models/` directory:

```
models/
├── nids.pkl
└── label_encoder.pkl
```

To retrain from scratch, run the notebooks in `notebooks/` in order.

---

## Running

### Standard mode (SMS alerts enabled)

```bash
sudo venv/bin/python src/monitor.py --iface eth0
```

### Test mode (no SMS sent — for development)

```bash
sudo venv/bin/python src/monitor.py --iface eth0 --test
```

The dashboard will be available at:

```
http://192.168.xxx.xxx:5000 (NIDS Address)
```

Accessible from any device on the same network.

---

## Dashboard

### Main Dashboard
Displays lifetime stat cards, real-time traffic volume chart and alert history. The chart supports day, week and month intervals.

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/d6eb39dc-c4f9-4bcd-ac69-550b832fa131" />

### Alert Modal
Click any alert to view full flow details including source/destination IP, port, protocol, attack classification and model confidence.

<img width="911" height="491" alt="image" src="https://github.com/user-attachments/assets/6b6b5c17-a88f-4545-a27d-744f9e42820b" />

### SMS Subscriber Management
Add and remove SMS subscribers directly from the dashboard without accessing the AWS console.

<img width="767" height="313" alt="image" src="https://github.com/user-attachments/assets/dc5bd766-7253-4298-8fae-79edd7c88762" />

### Terminal Output
Every alert prints the SHAP explanation alongside the prediction time directly to the terminal.

<img width="810" height="400" alt="image" src="https://github.com/user-attachments/assets/042eea00-4c39-4e14-9dec-a89c71f9e3ec" />

---

## Model Metrics

Trained on CIC-IDS-2017 with an 80/20 stratified split (743,216 train / 185,805 test).

### Model Comparison

| Model | Macro F1 | Train Time | Predict Time |
|-------|----------|------------|--------------|
| **Random Forest** | **0.94** | **39.42s** | **0.45s** |
| XGBoost | 0.94 | 47.10s | 0.74s |
| Decision Tree | 0.93 | 19.99s | 0.05s |

Random Forest was selected for its balance of accuracy and prediction speed on the Raspberry Pi 5.

### Per-Class F1 Scores

| Class | Precision | Recall | F1 |
|-------|-----------|--------|----|
| BENIGN | 1.00 | 1.00 | 1.00 |
| DDoS | 1.00 | 1.00 | 1.00 |
| DoS GoldenEye | 1.00 | 1.00 | 1.00 |
| DoS Hulk | 1.00 | 1.00 | 1.00 |
| DoS Slowhttptest | 1.00 | 1.00 | 1.00 |
| DoS slowloris | 1.00 | 0.99 | 1.00 |
| FTP-Patator | 1.00 | 1.00 | 1.00 |
| PortScan | 1.00 | 1.00 | 1.00 |
| SSH-Patator | 1.00 | 1.00 | 1.00 |
| Other Attack | 1.00 | 0.99 | 0.99 |
| Bot | 0.89 | 0.91 | 0.90 |
| Web Attack - Brute Force | 0.76 | 0.73 | 0.75 |
| Web Attack - XSS | 0.61 | 0.60 | 0.61 |
| **Macro Avg** | **0.94** | **0.94** | **0.94** |

### Live Testing Results

Tested on a physical private network with real attack tools:

| Attack | Tool | Confidence | Detected |
|--------|------|------------|----------|
| FTP-Patator | Hydra | 50-70% | ✅ |
| SSH-Patator | Hydra | 55-70% | ✅ |
| PortScan | Nmap | 60-70% | ✅ |
| DDoS | hping3 | 50-65% | ✅ |
| DoS Hulk | Apache Bench | 50-60% | ✅ |
| DoS Slowhttptest | slowhttptest | 50-60% | ✅ |
| DoS Slowloris | slowhttptest | 50-60% | ✅ |
| DoS GoldenEye | Apache Bench | 50-65% | ✅ |
| Web Attack - Brute Force | Hydra | N/A | ❌ |
| Web Attack - XSS | OWASP ZAP | N/A | ❌ |
| Other Attack | Metasploit | N/A | ❌ |
| Bot | Metasploit | N/A | ❌ |

**Prediction time on Raspberry Pi 5: ~30ms per flow**

---

## Detection Threshold

The model was trained on CIC-IDS-2017 which was generated on professional 10Gbps network infrastructure. Live consumer hardware produces different traffic characteristics, resulting in lower confidence scores (50-70% vs near-perfect on the test set). A custom threshold is applied to compensate:

- BENIGN confidence ≥ 50% → classify as **BENIGN**
- BENIGN confidence < 50% and top attack class > 50% → classify as **attack**
- Neither exceeds 50% → default to **BENIGN**

---

## Project Structure

```
PiGuard/
├── src/
│   ├── monitor.py          # Entry point — packet capture and pipeline
│   ├── flow.py             # TCP/UDP flow aggregation
│   ├── features.py         # 70 CIC-IDS-2017 feature extraction
│   ├── predict.py          # Random Forest classification + SHAP
│   ├── alerts.py           # AWS SNS alert management
│   ├── threat_intel.py     # AbuseIPDB threat intelligence
│   ├── dashboard.py        # Flask dashboard and REST API
│   └── db.py               # SQLite database layer
├── models/
│   ├── nids.pkl            # Trained Random Forest model
│   └── label_encoder.pkl   # Label encoder
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── templates/
│   └── index.html
├── notebooks/
│   ├── data_explore.ipynb  # Dataset preprocessing
│   └── training_model.ipynb
├── .env                    # Environment variables (not committed)
└── requirements.txt
```

---

## Technologies

| Category | Technology |
|----------|------------|
| Language | Python 3.12 |
| Packet Capture | Scapy |
| ML Framework | Scikit-learn |
| Model | Random Forest (200 estimators) |
| Explainability | SHAP |
| Class Balancing | imbalanced-learn (SMOTE) |
| Web Framework | Flask |
| Alerting | AWS SNS |
| Threat Intelligence | AbuseIPDB |
| Database | SQLite |
| Hardware | Raspberry Pi 5 (8GB) |
| Dataset | CIC-IDS-2017 |

---
**Liam Doocey** — BSc Computer Science, SETU (2026)
