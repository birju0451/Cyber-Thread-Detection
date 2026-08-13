# 🛡️ ABTD v2.0 — Adaptive Behavioral Threat Detection

**Risk-Adaptive Zero Trust Windows Security System**

A comprehensive endpoint protection platform combining **Zero Trust Architecture** with **Machine Learning** and **Behavioral Analysis** for real-time Windows security monitoring.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    ABTD v2.0 System Architecture             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Windows Agent (6 Monitors)                  │ │
│  │  File │ Process │ Registry │ Network │ USB │ Startup    │ │
│  └───────────────────────┬─────────────────────────────────┘ │
│                          │                                    │
│                   ┌──────▼──────┐                             │
│                   │   Event     │                             │
│                   │ Classifier  │ (filter non-security noise) │
│                   └──────┬──────┘                             │
│                          │                                    │
│  ┌───────────────────────▼─────────────────────────────────┐ │
│  │           ABTD Hybrid Detection Engine (7 Layers)       │ │
│  │  1. Feature Extraction     5. Reputation Analysis       │ │
│  │  2. Random Forest (ML)     6. Behavior Engine           │ │
│  │  3. Isolation Forest (ML)  7. Correlation Engine        │ │
│  │  4. Rule-Based Heuristics  → Adaptive Threat Scoring    │ │
│  └───────────────────────┬─────────────────────────────────┘ │
│                          │                                    │
│  ┌───────────────────────▼─────────────────────────────────┐ │
│  │          Zero Trust Access Control Pipeline             │ │
│  │  Identity → Device → App → Process → Resource           │ │
│  │  → Risk Fusion → Policy Engine → Access Decision        │ │
│  │  (ALLOW / MONITOR / RESTRICT / CHALLENGE / BLOCK)       │ │
│  └───────────────────────┬─────────────────────────────────┘ │
│                          │                                    │
│  ┌───────────────────────▼─────────────────────────────────┐ │
│  │              Response Engine (Simulation Mode)          │ │
│  │  Desktop Alerts │ DB Logging │ Process Action           │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Flask API +    │  │ Chrome       │  │ MongoDB Atlas  │  │
│  │  Dashboard      │  │ Extension    │  │ (Persistence)  │  │
│  └─────────────────┘  └──────────────┘  └────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train ML Models
```bash
python train_all.py
```

### 3. Start System
```bash
python run.py
```

### 4. Access Dashboard
- **Dashboard**: http://127.0.0.1:5000/dashboard
- **Zero Trust**: http://127.0.0.1:5000/zero-trust
- **Scanner**: http://127.0.0.1:5000/scanner

### 5. Chrome Extension (Optional)
1. Open `chrome://extensions/`
2. Enable Developer Mode
3. Click "Load unpacked" → select `extension/` folder

---

## 📁 Project Structure

```
Cyber-Thread-Detection/
├── run.py                     # Main entry point
├── config.py                  # Central configuration
├── train_all.py               # ML model training orchestrator
│
├── agent/                     # Windows Background Agent
│   ├── agent.py               # Agent orchestrator (6 threads)
│   ├── event_classifier.py    # Intelligent event triage
│   ├── zt_pipeline.py         # Zero Trust pipeline bridge
│   ├── file_monitor.py        # Watchdog file system monitor
│   ├── process_monitor.py     # Process creation/termination
│   ├── network_monitor.py     # TCP connection monitor
│   ├── registry_monitor.py    # Registry persistence detector
│   ├── usb_monitor.py         # USB insertion/removal
│   ├── startup_monitor.py     # Startup folder + scheduled tasks
│   └── notifier.py            # Desktop notification
│
├── engine/                    # ABTD Detection Engine
│   ├── predictor.py           # Main orchestrator (7-layer)
│   ├── url_analyzer.py        # URL/phishing ML analysis
│   ├── file_analyzer.py       # File/malware analysis
│   ├── memory_analyzer.py     # Memory anomaly analysis
│   ├── rule_engine.py         # Heuristic rules
│   ├── reputation.py          # IP/domain reputation
│   └── threat_scorer.py       # Adaptive weighted fusion
│
├── zero_trust/                # Zero Trust Architecture
│   ├── access_control/        # Main ZT pipeline
│   │   └── access_controller.py
│   ├── identity/              # User identity management
│   │   └── identity_manager.py
│   ├── device_trust/          # Device posture assessment
│   │   └── device_assessor.py
│   ├── application_trust/     # Application trust scoring
│   │   └── app_assessor.py
│   ├── process_trust/         # Process risk assessment
│   │   └── process_assessor.py
│   ├── resource_protection/   # Resource sensitivity registry
│   │   └── resource_registry.py
│   ├── risk_engine/           # Multi-signal risk calculator
│   │   └── risk_calculator.py
│   ├── policy_engine/         # Policy evaluation + enforcement
│   │   ├── policy_engine.py
│   │   └── policies.json
│   └── trust_manager/        # Trust state management
│       └── trust_manager.py
│
├── abtd/                      # ABTD Intelligence Layer
│   ├── behavior_engine/       # Temporal behavioral profiling
│   │   └── behavior_engine.py
│   ├── correlation_engine/    # Multi-event incident correlation
│   │   └── correlation_engine.py
│   └── response_engine/       # Automated response actions
│       └── response_engine.py
│
├── ml/                        # ML Training Pipeline
│   ├── feature_engineering.py # URL + file feature extraction
│   ├── train_url_classifier.py
│   ├── train_malware_classifier.py
│   ├── train_memory_anomaly.py
│   └── train_behavior_anomaly.py
│
├── backend/                   # Flask Backend
│   ├── app.py                 # Flask application factory
│   ├── database.py            # MongoDB Atlas integration
│   ├── logger.py              # Logging configuration
│   └── routes/                # API endpoints (15+)
│       ├── predict_routes.py
│       ├── zero_trust_routes.py
│       ├── alert_routes.py
│       └── ...
│
├── frontend/                  # Dashboard UI
│   ├── templates/             # 20 HTML templates
│   │   ├── dashboard.html
│   │   ├── zero_trust.html
│   │   └── ...
│   └── static/                # CSS + JS
│
├── extension/                 # Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js          # Service worker (ZT + ABTD)
│   ├── content.js             # Page overlay injection
│   └── popup/                 # Extension popup UI
│
├── datasets/                  # Training datasets (6 CSV files)
├── models/                    # Trained model artifacts (.pkl)
├── evaluation/                # Research evaluation + benchmarks
│   ├── research_evaluation.py
│   └── performance_benchmark.py
│
└── tests/                     # Test suites
    ├── test_agent.py
    ├── test_zero_trust.py
    ├── test_integration.py
    └── test_engine.py
```

---

## 🔐 Zero Trust Architecture

ABTD v2.0 implements a **complete Zero Trust access control pipeline**:

| Step | Module | Function |
|------|--------|----------|
| 1 | Identity Manager | Verify user identity + privilege level |
| 2 | Device Assessor | Assess device security posture |
| 3 | App Assessor | Evaluate application trust (signed, known, etc.) |
| 4 | Process Assessor | Assess process risk (blocklist, parent chain) |
| 5 | Resource Registry | Check resource sensitivity level |
| 6 | Risk Calculator | Fuse all signals into overall risk score |
| 7 | Policy Engine | Match against 10+ policies → access decision |
| 8 | Response Engine | Execute decision (alert, monitor, block) |

**Access Decisions**: `ALLOW` → `MONITOR` → `RESTRICT` → `CHALLENGE` → `QUARANTINE` → `BLOCK`

---

## 🤖 ML Models

| Model | Algorithm | Dataset | Purpose |
|-------|-----------|---------|---------|
| URL Classifier | Random Forest (300 trees) | Phishing_Legitimate_full.csv + balanced_urls.csv | Phishing/malicious URL detection |
| Malware Classifier | Random Forest (200 trees) | Malware dataset.csv | Malware vs benign classification |
| Memory Anomaly | Isolation Forest | Obfuscated-MalMem2022.csv | Obfuscated malware detection |
| Behavior Anomaly | Isolation Forest | Midterm_53_group.csv | Network behavior anomaly detection |

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run Zero Trust tests only
python -m pytest tests/test_zero_trust.py -v

# Run integration tests
python -m pytest tests/test_integration.py -v

# Research evaluation (5-approach comparison)
python evaluation/research_evaluation.py

# Performance benchmarks
python evaluation/performance_benchmark.py
```

---

## 🛠️ Technology Stack

- **Python 3.11** — Core runtime
- **Flask 3.x** — Web framework + REST API
- **scikit-learn** — Random Forest + Isolation Forest
- **pandas / numpy** — Data processing
- **MongoDB Atlas** — Cloud threat log database
- **psutil** — Process + network monitoring
- **watchdog** — File system monitoring
- **winreg** — Windows Registry monitoring
- **Chart.js** — Dashboard visualizations
- **Chrome Manifest V3** — Browser extension

---

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/predict` | ABTD threat analysis |
| POST | `/api/zero-trust/evaluate` | Zero Trust evaluation |
| GET | `/api/zero-trust/overview` | ZT dashboard overview |
| GET | `/api/zero-trust/trust-scores` | Entity trust scores |
| GET | `/api/zero-trust/access-decisions` | Access decision log |
| GET | `/api/zero-trust/incidents` | Correlated incidents |
| GET | `/api/zero-trust/policies` | Policy list |
| GET | `/api/zero-trust/device-trust` | Device posture |
| GET | `/api/zero-trust/identity` | Identity context |
| GET | `/api/zero-trust/process-trust` | Process risk scores |
| GET | `/api/zero-trust/app-trust` | Application trust |
| GET | `/api/zero-trust/behavior` | Behavioral profiles |
| GET | `/api/stats` | System statistics |
| POST | `/api/scan` | File scan endpoint |

---

*ABTD v2.0 — Risk-Adaptive Zero Trust Windows Security System*
*Adaptive Behavioral Threat Detection | Python 3.11 | Flask | MongoDB Atlas*
