"""
ABTD — Adaptive Behavioral Threat Detection
============================================
config.py  —  Central project configuration
All paths, thresholds, toggles, and environment variables live here.
Import this module anywhere: ``import config``
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Root of the project (this file lives here)
BASE_DIR: Path = Path(__file__).resolve().parent

DATASETS_DIR   = BASE_DIR / "datasets"
MODELS_DIR     = BASE_DIR / "models"
LOGS_DIR       = BASE_DIR / "logs"
QUARANTINE_DIR = BASE_DIR / "quarantine"
AWARENESS_DIR  = BASE_DIR / "awareness"
TEMPLATES_DIR  = BASE_DIR / "frontend" / "templates"
STATIC_DIR     = BASE_DIR / "frontend" / "static"

# Ensure runtime directories exist
for _d in (MODELS_DIR, LOGS_DIR, QUARANTINE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Environment  (optional .env file)
# ---------------------------------------------------------------------------

load_dotenv(BASE_DIR / ".env")

# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

MONGO_ENABLED: bool = os.getenv("MONGO_ENABLED", "false").lower() == "true"
MONGO_URI  : str = os.getenv("MONGO_URI", "mongodb+srv://kkaryacse_db_user:DFaJpYGda60JeBHk@cyberthreat.dnvgxor.mongodb.net/?appName=CyberThreat")
MONGO_DB   : str = os.getenv("MONGO_DB",  "abtd")

COLLECTIONS = {
    # v1.0 collections
    "scans"           : "scans",
    "alerts"          : "alerts",
    "settings"        : "settings",
    "users"           : "users",
    "quarantine"      : "quarantine",
    # v2.0 Zero Trust collections
    "trust_scores"    : "trust_scores",
    "access_decisions": "access_decisions",
    "incidents"       : "incidents",
    "device_posture"  : "device_posture",
    "behavior_profiles": "behavior_profiles",
    "policies"        : "zt_policies",
    "audit_log"       : "audit_log",
    "assessments"     : "assessments",
}

# ---------------------------------------------------------------------------
# Flask
# ---------------------------------------------------------------------------

FLASK_HOST        : str  = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT        : int  = int(os.getenv("FLASK_PORT", "5000"))
FLASK_DEBUG       : bool = os.getenv("FLASK_DEBUG", "false").lower() == "true"
FLASK_SECRET_KEY  : str  = os.getenv("FLASK_SECRET_KEY", "abtd-secret-change-in-production")

# ---------------------------------------------------------------------------
# ML Model Paths
# ---------------------------------------------------------------------------

URL_MODEL_PATH      = MODELS_DIR / "url_classifier.pkl"
MALWARE_MODEL_PATH  = MODELS_DIR / "malware_classifier.pkl"
MEMORY_MODEL_PATH   = MODELS_DIR / "memory_anomaly.pkl"
BEHAVIOR_MODEL_PATH = MODELS_DIR / "behavior_anomaly.pkl"

# ---------------------------------------------------------------------------
# ABTD Threat Scoring Weights
# (must sum to 1.0)
# ---------------------------------------------------------------------------

SCORE_WEIGHTS = {
    "random_forest" : 0.40,   # Supervised ML score
    "isolation_forest": 0.20, # Anomaly score
    "rules"         : 0.25,   # Heuristic rule score
    "reputation"    : 0.15,   # Domain/IP reputation score
}

# ---------------------------------------------------------------------------
# Threat Classification Thresholds (0–100 scale)
# ---------------------------------------------------------------------------

THRESHOLDS = {
    "safe"       : 25,   # score  < 25  → SAFE
    "suspicious" : 50,   # score  < 50  → SUSPICIOUS
    "malicious"  : 75,   # score  < 75  → MALICIOUS
    # score >= 75         → CRITICAL
}

THREAT_LEVELS = ["SAFE", "SUSPICIOUS", "MALICIOUS", "CRITICAL"]

# ---------------------------------------------------------------------------
# Rule Engine — Heuristic Penalties (each adds to rule_score 0–100)
# ---------------------------------------------------------------------------

RULE_PENALTIES = {
    "ip_in_url"           : 20,
    "url_length_excessive": 10,
    "hex_encoded_chars"   : 15,
    "suspicious_keywords" : 15,
    "multiple_subdomains" : 10,
    "https_missing"       : 10,
    "url_shortener"       : 15,
    "brand_impersonation" : 20,
    "double_extension"    : 15,
    "at_symbol_in_url"    : 20,
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "banking", "paypal", "amazon", "google", "microsoft",
    "apple", "ebay", "password", "credential", "wallet", "crypto",
]

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "clck.ru",
}

# ---------------------------------------------------------------------------
# Windows Agent Settings
# ---------------------------------------------------------------------------

AGENT_ENABLED          : bool = os.getenv("AGENT_ENABLED", "true").lower() == "true"
AGENT_SCAN_INTERVAL_S  : int  = int(os.getenv("AGENT_SCAN_INTERVAL", "30"))   # seconds
AGENT_LOG_FILE         : Path = LOGS_DIR / "agent.log"

# Directories the agent watches for newly written files
WATCHED_DIRS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    os.path.join(os.environ.get("TEMP", "C:/Windows/Temp")),
]

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".hta", ".scr", ".pif", ".com", ".dll", ".sys",
}

# Processes that should never run (blocklist)
BLOCKED_PROCESSES = {
    "mimikatz.exe", "procdump.exe", "pwdump.exe",
    "wce.exe", "fgdump.exe", "meterpreter.exe",
}

# Registry keys monitored for persistence
PERSISTENCE_REGISTRY_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
]

# ---------------------------------------------------------------------------
# Gemini API (Optional — for threat explanation)
# ---------------------------------------------------------------------------

GEMINI_ENABLED  : bool = os.getenv("GEMINI_ENABLED", "false").lower() == "true"
GEMINI_API_KEY  : str  = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL    : str  = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LEVEL      : str  = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE       : Path = LOGS_DIR / "abtd.log"
LOG_MAX_BYTES  : int  = 10 * 1024 * 1024   # 10 MB
LOG_BACKUP_COUNT: int = 5

# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

PAGE_SIZE: int = 25

# ---------------------------------------------------------------------------
# Zero Trust Architecture Settings (v2.0)
# ---------------------------------------------------------------------------

# Simulation mode: when True, destructive response actions are logged only
# Set ZT_SIMULATION_MODE=false in .env to enable real actions
ZT_SIMULATION_MODE: bool = os.getenv("ZT_SIMULATION_MODE", "true").lower() != "false"

# Trust score thresholds (trust = 100 - risk)
ZT_TRUST_THRESHOLDS = {
    "TRUSTED"       : 90,   # score >= 90 → Trusted
    "LOW_RISK"      : 70,   # score >= 70 → Low Risk
    "MODERATE_RISK" : 50,   # score >= 50 → Moderate Risk
    "HIGH_RISK"     : 30,   # score >= 30 → High Risk
    "UNTRUSTED"     : 0,    # score <  30 → Untrusted
}

# Multi-signal risk weights for Zero Trust risk calculator
# Must sum to 1.0
ZT_RISK_WEIGHTS = {
    "identity" : 0.15,
    "device"   : 0.20,
    "app"      : 0.15,
    "process"  : 0.15,
    "url"      : 0.10,
    "file"     : 0.10,
    "behavior" : 0.10,
    "network"  : 0.05,
}

# Minimum trust scores required per resource sensitivity level
ZT_MIN_TRUST_FOR_SENSITIVITY = {
    "PUBLIC"   : 0,
    "INTERNAL" : 40,
    "SENSITIVE": 65,
    "CRITICAL" : 85,
}

# Zero Trust access decision types
ZT_DECISIONS = ["ALLOW", "MONITOR", "RESTRICT", "CHALLENGE", "QUARANTINE", "BLOCK"]

# Default entity trust starting scores
ZT_DEFAULT_TRUST = {
    "user"      : 75,
    "device"    : 70,
    "process"   : 60,
    "app"       : 65,
    "connection": 50,
}

# Correlation engine: time window for grouping events into incidents (seconds)
ZT_CORRELATION_WINDOW: int = int(os.getenv("ZT_CORRELATION_WINDOW", "300"))

# Security Assessment
ASSESSMENT_DIR: Path = BASE_DIR / "reports"
ASSESSMENT_DIR.mkdir(parents=True, exist_ok=True)
