# ABTD — Adaptive Behavioral Threat Detection
## Project Walkthrough & Live Progress Tracker
> Last Updated: 2026-08-11 | Status: ALL COMMANDS EXECUTED ✅

---

## 📌 LEGEND
```
[x] = DONE ✅
[~] = IN PROGRESS 🔄
[ ] = PENDING ⏳
```

---

## ✅ PHASE 1 — Project Scaffolding
- [x] Create directory structure (`agent/`, `backend/`, `engine/`, `ml/`, `extension/`, `frontend/`, `tests/`, `datasets/`, `models/`, `logs/`, `quarantine/`, `awareness/`)
- [x] `config.py` — Central config (paths, thresholds, MongoDB URI, Gemini key, Flask settings)
- [x] `requirements.txt` — All pip dependencies listed
- [x] `setup.py` — Environment validator + auto-install
- [x] All `__init__.py` files created in every package

---

## ✅ PHASE 2 — ML Training Pipelines
- [x] `ml/feature_engineering.py` — URL feature extractor (30 structural features)
- [x] `ml/train_url_classifier.py` — Random Forest, Phishing_Legitimate_full.csv + balanced_urls.csv
- [x] `ml/train_malware_classifier.py` — Random Forest, Malware dataset.csv
- [x] `ml/train_memory_anomaly.py` — Isolation Forest, Obfuscated-MalMem2022.csv
- [x] `ml/train_behavior_anomaly.py` — Isolation Forest, Midterm_53_group.csv (Wireshark PCAP)
- [x] `train_all.py` — Master training orchestrator (flags: --url-only, --skip-url, etc.)

---

## ✅ PHASE 3 — ABTD Detection Engine (5-Layer)
- [x] `engine/url_analyzer.py` — URL ML integration layer
- [x] `engine/file_analyzer.py` — SHA-256 + Shannon entropy + PE header + malware ML
- [x] `engine/memory_analyzer.py` — Process memory anomaly detection (psutil)
- [x] `engine/rule_engine.py` — 10 heuristic security rules (IP-in-URL, brand impersonation, etc.)
- [x] `engine/reputation.py` — WHOIS + DNSBL reputation checks
- [x] `engine/threat_scorer.py` — Score fusion: RF(40%) + Anomaly(20%) + Rules(25%) + Reputation(15%)
- [x] `engine/predictor.py` — Main orchestrator, used by all routes and agent

---

## ✅ PHASE 4 — Flask Backend + REST API
- [x] `backend/logger.py` — Structured colorized rotating log
- [x] `backend/database.py` — MongoDB Atlas DAL (singleton pattern)
- [x] `backend/utils.py` — Gemini AI integration + helper functions
- [x] `backend/routes/predict_routes.py` — `/predict` (Chrome Extension endpoint)
- [x] `backend/routes/scan_routes.py` — `/api/scan` (dashboard manual scan)
- [x] `backend/routes/stats_routes.py` — `/api/stats` + `/api/history` (KPI data)
- [x] `backend/routes/alert_routes.py` — `/api/file-alerts`, `/api/process-alerts`, `/api/network-alerts`, `/api/registry-alerts`, `/api/quarantine`
- [x] `backend/routes/system_routes.py` — `/api/status` + `/api/system-info` (CPU/RAM/disk)
- [x] `backend/routes/settings_routes.py` — `/api/settings` (GET + POST)
- [x] `backend/routes/awareness_routes.py` — `/api/awareness` + `/api/awareness/<slug>`
- [x] `backend/app.py` — Flask factory, CORS, registers all Blueprints

---

## ✅ PHASE 5 — Web Dashboard (Dark Glassmorphism UI)
- [x] `frontend/static/css/main.css` — Design tokens, layout, dark theme
- [x] `frontend/static/css/components.css` — Cards, badges, tables, charts
- [x] `frontend/static/js/main.js` — Global JS utilities
- [x] `frontend/static/js/dashboard.js` — Dashboard charts (Chart.js), live stats
- [x] `frontend/static/js/scanner.js` — Scanner form, results rendering
- [x] `frontend/templates/base.html` — Sidebar nav, header, layout
- [x] `frontend/templates/dashboard.html` — KPI cards, threat chart, recent scans
- [x] `frontend/templates/scanner.html` — URL + File + Process scanner
- [x] `frontend/templates/history.html` — Paginated scan history table
- [x] `frontend/templates/threats.html` — Live threat alerts (file/process/network/registry)
- [x] `frontend/templates/awareness.html` — Cybersecurity education hub
- [x] `frontend/templates/awareness_topic.html` — Topic detail + interactive quiz
- [x] `frontend/templates/settings.html` — System settings + threshold config
- [x] `frontend/templates/about.html` — Project info, architecture, team

---

## ✅ PHASE 6 — Windows Background Agent (Daemon Threads)
- [x] `agent/notifier.py` — Windows desktop notifications (plyer / win10toast)
- [x] `agent/file_monitor.py` — watchdog: Downloads, Desktop, Temp directory monitoring
- [x] `agent/process_monitor.py` — psutil: all running processes every 30s
- [x] `agent/registry_monitor.py` — winreg: startup persistence key diff (HKCU + HKLM)
- [x] `agent/network_monitor.py` — psutil: TCP connections, suspicious port detection
- [x] `agent/agent.py` — Main daemon orchestrator, SIGINT/SIGTERM graceful shutdown

---

## ✅ PHASE 7 — Chrome Extension (Manifest V3)
- [x] `extension/manifest.json` — MV3: webNavigation, tabs, storage, notifications perms
- [x] `extension/background.js` — Service worker: URL interception, badge updates, notifications
- [x] `extension/content.js` — Threat banner injection + 800ms hover link tooltips
- [x] `extension/popup/popup.html` — Popup UI: current page scan, quick scanner, session stats
- [x] `extension/popup/popup.css` — Dark theme matching dashboard, animated status pill
- [x] `extension/popup/popup.js` — Live API check, tab analysis, session stats storage
- [x] `extension/icons/icon16.png` — Generated ✅
- [x] `extension/icons/icon48.png` — Generated ✅
- [x] `extension/icons/icon128.png` — Generated ✅

---

## ✅ PHASE 8 — Security Awareness Content (6 Topics)
- [x] `awareness/phishing.json` — Phishing: types, indicators, quiz (2 questions)
- [x] `awareness/malware.json` — Malware: types, ABTD detection, quiz
- [x] `awareness/ransomware.json` — Ransomware: WannaCry, NotPetya, 3-2-1 backup rule
- [x] `awareness/password_security.json` — Password managers, passphrases, 2FA
- [x] `awareness/social_engineering.json` — Pretexting, vishing, baiting
- [x] `awareness/safe_browsing.json` — Browser hardening, HTTPS, VPN, ABTD extension tips

---

## ✅ PHASE 9 — Entry Points + Tests
- [x] `run.py` — Full system launcher: Flask + Agent (flags: --no-agent, --agent-only, --host)
- [x] `generate_icons.py` — Auto-generates Pillow PNG icons for extension
- [x] `tests/test_engine.py` — 25 tests: URL analysis, rule engine, threat scorer, feature engineering
- [x] `tests/test_routes.py` — 35 tests: all Flask API endpoints via test client
- [x] `tests/test_agent.py` — 17 tests: agent monitors + file analyzer (entropy, PE, SHA-256)
- [x] `README.md` — Complete documentation: architecture, datasets, API ref, quick start

---

## ✅ ML MODEL TRAINING — All 4 Models Trained
| Model File | Size | Training Dataset | Status |
|---|---|---|---|
| `models/url_classifier.pkl` | **22.3 MB** | Phishing_Legitimate_full.csv + balanced_urls.csv | ✅ TRAINED |
| `models/malware_classifier.pkl` | **3.3 MB** | Malware dataset.csv (100K rows) | ✅ TRAINED |
| `models/memory_anomaly.pkl` | **2.1 MB** | Obfuscated-MalMem2022.csv (58K Volatility rows) | ✅ TRAINED |
| `models/behavior_anomaly.pkl` | **2.6 MB** | Midterm_53_group.csv (394K Wireshark packets) | ✅ TRAINED |

---

## 📊 Dataset → Label Column → Model Mapping

| Dataset | Rows | Label Column | Label Values | Output Model |
|---|---|---|---|---|
| `Phishing_Legitimate_full.csv` | 10,000 | `CLASS_LABEL` | 0=legit, 1=phishing | url_classifier.pkl |
| `balanced_urls.csv` | 632,509 | `result` | 0=benign, 1=phishing | url_classifier.pkl |
| `Malware dataset.csv` | 100,001 | `classification` | benign / malware | malware_classifier.pkl |
| `Obfuscated-MalMem2022.csv` | 58,597 | `Class` | Benign / Malware | memory_anomaly.pkl |
| `Midterm_53_group.csv` | 394,137 | PCAP → per-IP stats | Unsupervised | behavior_anomaly.pkl |

---

## 🎯 Threat Score Fusion Weights

| Layer | Weight | Algorithm |
|---|---|---|
| Random Forest (ML Classifier) | **40%** | Supervised learning on labeled data |
| Isolation Forest (Anomaly) | **20%** | One-class unsupervised anomaly |
| Rule Engine (Heuristics) | **25%** | 10 hand-crafted security rules |
| Reputation (WHOIS + DNSBL) | **15%** | Domain age + blacklist lookup |

---

## 🌐 API Endpoints Reference

| Endpoint | Method | Description |
|---|---|---|
| `/predict` | POST | Chrome Extension URL scan (fast) |
| `/api/scan` | POST | Manual scan: URL / File / Process |
| `/api/stats` | GET | Dashboard KPI stats |
| `/api/history` | GET | Paginated MongoDB scan log |
| `/api/status` | GET | System health check |
| `/api/system-info` | GET | CPU / RAM / Disk telemetry |
| `/api/file-alerts` | GET | File monitoring alerts |
| `/api/process-alerts` | GET | Process monitoring alerts |
| `/api/network-alerts` | GET | TCP connection alerts |
| `/api/registry-alerts` | GET | Registry persistence alerts |
| `/api/quarantine` | GET | Quarantined files list |
| `/api/settings` | GET/POST | System settings |
| `/api/awareness` | GET | List all awareness topics |
| `/api/awareness/<slug>` | GET | Topic content + quiz |
| `/dashboard` | GET | Main dashboard page |
| `/scanner` | GET | Scanner page |
| `/history` | GET | History page |
| `/threats` | GET | Threats page |

---

## 🔑 Environment Variables (.env)

| Variable | Value |
|---|---|
| `MONGO_URI` | `mongodb+srv://kkaryacse_db_user:***@cyberthreat.dnvgxor.mongodb.net/` |
| `MONGO_DB` | `abtd` |
| `GEMINI_API_KEY` | Configured ✅ |
| `GEMINI_ENABLED` | `true` |
| `FLASK_HOST` | `127.0.0.1` |
| `FLASK_PORT` | `5000` |
| `AGENT_ENABLED` | `true` |
| `AGENT_SCAN_INTERVAL` | `30` (seconds) |

---

## 🚀 STARTUP COMMANDS

```powershell
# Navigate to project
cd d:\Cyber-Thread-Detection

# 1. (Optional) Retrain all models
python train_all.py

# 2. Run tests
python -m pytest tests/ -v

# 3. Start full system (Flask + Windows Agent)
python run.py

# 4. Flask only (no background monitoring)
python run.py --no-agent

# 5. Agent only (no Flask)
python run.py --agent-only
```

**Dashboard:** http://127.0.0.1:5000/dashboard
**Scanner:** http://127.0.0.1:5000/scanner

---

## 🔌 CHROME EXTENSION SETUP

### Load as Developer (Unpacked)
```
1. Open Chrome → chrome://extensions
2. Toggle Developer Mode → ON
3. Click "Load unpacked"
4. Browse → d:\Cyber-Thread-Detection\extension\
5. Click Select Folder
```

### Pack for Distribution (.crx)
```
1. Chrome → chrome://extensions
2. Click "Pack Extension"
3. Extension root directory → d:\Cyber-Thread-Detection\extension\
4. Leave private key blank (first time)
5. Click "Pack Extension"
→ Creates: extension.crx  (installer — share this)
→ Creates: extension.pem  (private key — keep safe, never share!)
```

---

## 📦 Complete File Tree

```
d:\Cyber-Thread-Detection\
├── config.py                    ← Central config
├── run.py                       ← MAIN ENTRY POINT
├── train_all.py                 ← Train all ML models
├── setup.py                     ← Environment setup
├── generate_icons.py            ← Chrome extension icons
├── requirements.txt
├── README.md
├── WALKTHROUGH.md               ← THIS FILE
│
├── datasets/                    ← Training CSVs (6 files)
│   ├── Phishing_Legitimate_full.csv
│   ├── balanced_urls.csv
│   ├── Malware dataset.csv
│   ├── Obfuscated-MalMem2022.csv
│   ├── Midterm_53_group.csv
│   └── social_media_behavior_dataset.csv
│
├── models/                      ← Trained .pkl files (ALL 4 ✅)
│   ├── url_classifier.pkl       (22.3 MB)
│   ├── malware_classifier.pkl   (3.3 MB)
│   ├── memory_anomaly.pkl       (2.1 MB)
│   └── behavior_anomaly.pkl     (2.6 MB)
│
├── ml/                          ← Training scripts
│   ├── feature_engineering.py
│   ├── train_url_classifier.py
│   ├── train_malware_classifier.py
│   ├── train_memory_anomaly.py
│   └── train_behavior_anomaly.py
│
├── engine/                      ← 5-layer detection engine
│   ├── predictor.py             ← MAIN ORCHESTRATOR
│   ├── url_analyzer.py
│   ├── file_analyzer.py         ← SHA-256 + entropy + PE
│   ├── memory_analyzer.py
│   ├── rule_engine.py           ← 10 security rules
│   ├── reputation.py
│   └── threat_scorer.py
│
├── backend/                     ← Flask web server
│   ├── app.py
│   ├── database.py              ← MongoDB Atlas
│   ├── logger.py
│   ├── utils.py                 ← Gemini AI
│   └── routes/                  ← 8 Blueprint modules
│
├── frontend/                    ← Dashboard UI
│   ├── templates/               ← 9 HTML pages
│   └── static/                  ← CSS + JS
│
├── agent/                       ← Windows monitoring daemon
│   ├── agent.py
│   ├── file_monitor.py          ← watchdog
│   ├── process_monitor.py       ← psutil
│   ├── registry_monitor.py      ← winreg
│   ├── network_monitor.py       ← TCP monitoring
│   └── notifier.py              ← Toast notifications
│
├── extension/                   ← Chrome Extension MV3
│   ├── manifest.json
│   ├── background.js            ← Service worker
│   ├── content.js               ← Banners + tooltips
│   ├── icons/                   ← icon16/48/128.png ✅
│   └── popup/                   ← popup.html/css/js
│
├── awareness/                   ← 6 security topic JSONs
├── tests/                       ← 77 pytest tests
└── logs/                        ← Runtime log files
```

---

## ✅ FINAL STATUS: PROJECT COMPLETE

| Phase | Status |
|---|---|
| Phase 1: Scaffolding | ✅ DONE |
| Phase 2: ML Pipelines | ✅ DONE |
| Phase 3: Detection Engine | ✅ DONE |
| Phase 4: Flask Backend | ✅ DONE |
| Phase 5: Web Dashboard | ✅ DONE |
| Phase 6: Windows Agent | ✅ DONE |
| Phase 7: Chrome Extension | ✅ DONE |
| Phase 8: Awareness Content | ✅ DONE |
| Phase 9: Tests + Docs | ✅ DONE |
| Model Training (4/4) | ✅ DONE |
| Icons Generated | ✅ DONE |
| README Written | ✅ DONE |

> 🎉 **ABTD v1.0 — Fully Operational**
> Run `python run.py` and open http://127.0.0.1:5000/dashboard
