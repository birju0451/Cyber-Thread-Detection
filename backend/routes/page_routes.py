"""
backend/routes/page_routes.py
================================
Blueprint: HTML page routes for the web dashboard.
Serves all Jinja2 templates — both v1.0 and v2.0 Zero Trust pages.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, render_template, redirect, url_for

page_bp = Blueprint("pages", __name__)


@page_bp.route("/")
def index():
    return redirect(url_for("pages.dashboard"))


# ── v1.0 Pages ────────────────────────────────────────────────────────────────

@page_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@page_bp.route("/scanner")
def scanner():
    return render_template("scanner.html")


@page_bp.route("/history")
def history():
    return render_template("history.html")


@page_bp.route("/threats")
def threats():
    return render_template("threats.html")


@page_bp.route("/awareness")
def awareness():
    return render_template("awareness.html")


@page_bp.route("/awareness/<slug>")
def awareness_topic(slug: str):
    return render_template("awareness_topic.html", slug=slug)


@page_bp.route("/settings")
def settings():
    return render_template("settings.html")


@page_bp.route("/about")
def about():
    return render_template("about.html")


# ── Zero Trust Pages (v2.0) ───────────────────────────────────────────────────

@page_bp.route("/zero-trust")
def zero_trust():
    return render_template("zero_trust.html")


@page_bp.route("/access-decisions")
def access_decisions():
    return render_template("access_decisions.html")


@page_bp.route("/device-trust")
def device_trust():
    return render_template("device_trust.html")


@page_bp.route("/user-trust")
def user_trust():
    return render_template("user_trust.html")


@page_bp.route("/application-trust")
def application_trust():
    return render_template("application_trust.html")


@page_bp.route("/process-trust")
def process_trust():
    return render_template("process_trust.html")


@page_bp.route("/incidents")
def incidents():
    return render_template("incidents.html")


@page_bp.route("/network-activity")
def network_activity():
    return render_template("network_activity.html")


@page_bp.route("/file-activity")
def file_activity():
    return render_template("file_activity.html")


@page_bp.route("/registry-activity")
def registry_activity():
    return render_template("registry_activity.html")


@page_bp.route("/assessment")
def assessment():
    return render_template("assessment.html")
