"""
ABTD — setup.py
================
One-click setup: installs dependencies, checks MongoDB, and verifies the environment.
Run: python setup.py
"""

import subprocess
import sys
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def banner(text: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")


def step(msg: str) -> None:
    print(f"  ► {msg}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def err(msg: str) -> None:
    print(f"  ✗ {msg}")


def check_python_version() -> None:
    banner("Checking Python Version")
    major, minor = sys.version_info[:2]
    step(f"Detected Python {major}.{minor}")
    if (major, minor) < (3, 10):
        err("Python 3.10+ is required. Please upgrade.")
        sys.exit(1)
    ok("Python version OK")


def install_requirements() -> None:
    banner("Installing Dependencies")
    req_file = BASE_DIR / "requirements.txt"
    step(f"Installing from {req_file}")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(req_file), "--quiet"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        err("pip install failed:")
        print(result.stderr)
        sys.exit(1)
    ok("All dependencies installed")


def create_env_file() -> None:
    banner("Environment Configuration")
    env_file = BASE_DIR / ".env"
    if env_file.exists():
        ok(".env already exists — skipping")
        return

    step("Creating default .env file")
    env_content = """\
# ABTD Environment Configuration
# ================================
# MongoDB
MONGO_URI=mongodb://localhost:27017
MONGO_DB=abtd

# Flask
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=false
FLASK_SECRET_KEY=abtd-change-this-secret-key

# Gemini AI (optional)
GEMINI_ENABLED=false
GEMINI_API_KEY=

# Windows Agent
AGENT_ENABLED=true
AGENT_SCAN_INTERVAL=30

# Logging
LOG_LEVEL=INFO
"""
    env_file.write_text(env_content)
    ok(".env created — review and update values before running")


def check_mongodb() -> None:
    banner("Checking MongoDB Connection")
    try:
        import pymongo
        from pymongo import MongoClient
        from pymongo.errors import ConnectionFailure
        client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        ok("MongoDB is running at localhost:27017")
        client.close()
    except Exception as e:
        err(f"MongoDB not reachable: {e}")
        print("  → Install MongoDB Community: https://www.mongodb.com/try/download/community")
        print("  → Or set MONGO_URI in .env to your Atlas connection string")


def create_gitignore() -> None:
    banner("Creating .gitignore")
    gitignore = BASE_DIR / ".gitignore"
    if gitignore.exists():
        ok(".gitignore already exists")
        return
    content = """\
# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
.Python
.venv/
venv/
env/
*.egg-info/
dist/
build/

# Models (large binary files)
models/*.pkl
models/*.joblib

# Environment
.env

# Logs
logs/*.log

# Quarantine
quarantine/*
!quarantine/.gitkeep

# IDE
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db
"""
    gitignore.write_text(content)
    ok(".gitignore created")


def main() -> None:
    banner("ABTD Project Setup")
    print(f"  Project root: {BASE_DIR}")

    check_python_version()
    create_env_file()
    install_requirements()
    check_mongodb()
    create_gitignore()

    banner("Setup Complete")
    print("""
  Next steps:
  ─────────────────────────────────────────────────────
  1. Train ML models:
       python train_all.py

  2. Start the system:
       python run.py

  3. Open the dashboard:
       http://127.0.0.1:5000

  4. Load the Chrome extension:
       chrome://extensions → Load unpacked → select extension/
  ─────────────────────────────────────────────────────
""")


if __name__ == "__main__":
    main()
