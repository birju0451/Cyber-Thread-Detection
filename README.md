# ABTD — Adaptive Behavioral Threat Detection
### AI-Powered Windows Endpoint Protection Platform

> Final Year Engineering Project | Python 3.11 | Flask | MongoDB Atlas | scikit-learn | Gemini AI

---

## 🏗️ System Architecture

```
User Browser / Windows System
        │
        ├─ Chrome Extension (Manifest V3)
        │      ├─ background.js  → scans every URL visited
        │      ├─ content.js     → injects threat banners + link tooltips
        │      └─ popup.html     → live scan dashboard in extension popup
        │
        └─ Flask API (port 5000)
               │
               ├─ /predict          → Extension scan endpoint
               ├─ /api/scan         → Manual scan (URL / File)
               ├─ /api/stats        → Dashboard KPIs
               ├─ /api/history      → MongoDB scan log
               ├─ /api/*-alerts     → Agent threat alerts
               └─ /dashboard        → Web dashboard (HTML)
                      │
                      └─ ABTD Engine (5-layer detection)
                             │
                             ├─ Layer 1: Feature Extraction
                             ├─ Layer 2: Random Forest Classifier
                             ├─ Layer 3: Isolation Forest Anomaly
                             ├─ Layer 4: Heuristic Rule Engine (10 rules)
                             └─ Layer 5: WHOIS + DNSBL Reputation
```

## 📦 Datasets Used

| Dataset | Size | Used For |
|---|---|---|
| `Phishing_Legitimate_full.csv` | 10K rows, 48 features | URL classifier (pre-extracted features) |
| `balanced_urls.csv` | 632K raw URLs | URL classifier (feature extraction) |
| `Malware dataset.csv` | 100K rows | Malware process classifier |
| `Obfuscated-MalMem2022.csv` | 58K rows (Volatility) | Memory anomaly detection |
| `Midterm_53_group.csv` | 394K packets (Wireshark) | Network behavior anomaly |

## 🤖 ML Models

| Model | Algorithm | Input | Output |
|---|---|---|---|
| `url_classifier.pkl` | Random Forest (300 trees) | 17 URL structural features | Benign / Phishing |
| `malware_classifier.pkl` | Random Forest (200 trees) | Process memory features | Benign / Malware |
| `memory_anomaly.pkl` | Isolation Forest | Volatility memory dump features | Normal / Anomaly |
| `behavior_anomaly.pkl` | Isolation Forest | Per-IP network packet stats | Normal / Anomaly |

## 🚀 Quick Start

### 1. Install Dependencies
```powershell
cd d:\Cyber-Thread-Detection
python -m pip install -r requirements.txt
```

### 2. Generate Extension Icons
```powershell
python generate_icons.py
```

### 3. Train ML Models
```powershell
# Train all 4 models (takes 10–30 min)
python train_all.py

# Or train individually (faster for testing)
python train_all.py --url-only
python train_all.py --skip-url      # Skip URL model (slowest)
```

### 4. Start the System
```powershell
# Full system (Flask + Windows Agent)
python run.py

# Flask only (no background monitoring)
python run.py --no-agent

# View on: http://127.0.0.1:5000/dashboard
```

### 5. Load Chrome Extension
1. Open Chrome → `chrome://extensions`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked**
4. Select `d:\Cyber-Thread-Detection\extension\`

**To pack for distribution:**
1. Chrome → `chrome://extensions`
2. Click **Pack Extension**
3. Browse → select the `extension/` folder
4. Chrome creates `extension.crx` (installer) + `extension.pem` (key)

### 6. Run Tests
```powershell
python -m pytest tests/ -v
```

## 📁 Project Structure

```
Cyber-Thread-Detection/
├── config.py               ← Central config (paths, thresholds, env)
├── run.py                  ← Main entry point
├── train_all.py            ← ML training orchestrator
├── setup.py                ← Environment validator
├── generate_icons.py       ← Chrome extension icons
├── requirements.txt
│
├── datasets/               ← Training CSV files
├── models/                 ← Trained .pkl model files
├── logs/                   ← Rotating log files
├── awareness/              ← Cybersecurity education JSON
│
├── ml/                     ← Training scripts
│   ├── feature_engineering.py
│   ├── train_url_classifier.py
│   ├── train_malware_classifier.py
│   ├── train_memory_anomaly.py
│   └── train_behavior_anomaly.py
│
├── engine/                 ← ABTD detection engine (5 layers)
│   ├── predictor.py        ← Main orchestrator (entry point)
│   ├── url_analyzer.py     ← URL ML integration
│   ├── file_analyzer.py    ← File entropy + PE + ML
│   ├── memory_analyzer.py  ← Process memory anomaly
│   ├── rule_engine.py      ← 10 heuristic security rules
│   ├── reputation.py       ← WHOIS + DNSBL checks
│   └── threat_scorer.py    ← Score fusion & classification
│
├── backend/                ← Flask web server
│   ├── app.py              ← App factory (registers blueprints)
│   ├── database.py         ← MongoDB Atlas DAL
│   ├── logger.py           ← Structured colorized logging
│   ├── utils.py            ← Gemini AI integration
│   └── routes/             ← 8 Blueprint route modules
│
├── frontend/               ← Web dashboard
│   ├── templates/          ← Jinja2 HTML templates (8 pages)
│   └── static/             ← CSS + JS (dark theme design system)
│
├── agent/                  ← Windows background monitoring agent
│   ├── agent.py            ← Orchestrator (main daemon)
│   ├── file_monitor.py     ← watchdog: Downloads/Desktop/Temp
│   ├── process_monitor.py  ← psutil: all running processes
│   ├── registry_monitor.py ← winreg: startup persistence keys
│   ├── network_monitor.py  ← psutil: TCP connections
│   └── notifier.py         ← Windows desktop notifications
│
├── extension/              ← Chrome Extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js       ← Service worker (URL scanning)
│   ├── content.js          ← Threat banners + link tooltips
│   └── popup/              ← Extension popup UI
│
└── tests/                  ← Pytest test suite (77 tests)
    ├── test_engine.py      ← 25 engine + rule + feature tests
    ├── test_routes.py      ← 35 Flask API integration tests
    └── test_agent.py       ← 17 agent + file analyzer tests
```

## 🔑 Environment Variables (.env)

| Variable | Default | Description |
|---|---|---|
| `MONGO_URI` | Atlas URI | MongoDB Atlas connection string |
| `GEMINI_API_KEY` | — | Google Gemini AI API key |
| `GEMINI_ENABLED` | `true` | Enable AI threat explanations |
| `FLASK_PORT` | `5000` | Flask server port |
| `AGENT_ENABLED` | `true` | Run background monitoring agent |
| `AGENT_SCAN_INTERVAL` | `30` | Process scan interval (seconds) |

## 🎯 Threat Classification

| Level | Score | Color | Action |
|---|---|---|---|
| ✅ **SAFE** | 0–24 | Green | Allow |
| ⚠️ **SUSPICIOUS** | 25–49 | Amber | Warn user |
| 🚫 **MALICIOUS** | 50–74 | Red | Block + Notify |
| 🔴 **CRITICAL** | 75–100 | Purple | Block + Alert + Log |

## 📊 Score Fusion Weights

| Layer | Weight | Source |
|---|---|---|
| Random Forest (ML) | **40%** | Trained classifier |
| Isolation Forest (Anomaly) | **20%** | Unsupervised model |
| Rule Engine (Heuristics) | **25%** | 10 security rules |
| Reputation (WHOIS+DNSBL) | **15%** | External lookup |

## 🌐 API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/predict` | POST | Chrome Extension URL scan |
| `/api/scan` | POST | Dashboard manual scan |
| `/api/stats` | GET | KPI dashboard stats |
| `/api/history` | GET | Paginated scan log |
| `/api/status` | GET | System health check |
| `/api/system-info` | GET | CPU/RAM/disk telemetry |
| `/api/file-alerts` | GET | File monitoring alerts |
| `/api/process-alerts` | GET | Process monitoring alerts |
| `/api/network-alerts` | GET | Network monitoring alerts |
| `/api/registry-alerts` | GET | Registry persistence alerts |
| `/api/quarantine` | GET | Quarantined file list |
| `/api/settings` | GET/POST | System settings |
| `/api/awareness` | GET | Awareness topic list |
| `/api/awareness/<slug>` | GET | Topic content + quiz |

## 👨‍💻 Technology Stack

- **Python 3.11** — Core runtime
- **Flask 3.x** — Web framework
- **scikit-learn** — Random Forest + Isolation Forest
- **pandas / numpy** — Data processing
- **MongoDB Atlas** — Cloud threat log database
- **Google Gemini AI** — Natural language threat explanations
- **watchdog** — File system monitoring
- **psutil** — Process + network monitoring
- **winreg** — Windows Registry monitoring
- **Chart.js** — Dashboard visualizations
- **Chrome Manifest V3** — Browser extension

---

*ABTD v1.0 — Adaptive Behavioral Threat Detection System*  
*Final Year Engineering Project — Python 3.11 | Flask | MongoDB Atlas*
