"""
backend/routes/page_routes.py
================================
Blueprint: HTML page routes for the web dashboard.
Serves all Jinja2 templates.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Blueprint, render_template, redirect, url_for

page_bp = Blueprint("pages", __name__)


@page_bp.route("/")
def index():
    return redirect(url_for("pages.dashboard"))


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
