"""
tests/test_agent.py
====================
Unit tests for the Windows background monitoring agent.
Tests each monitor independently without requiring admin rights.

Run: python -m pytest tests/test_agent.py -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest


# ── Notifier ──────────────────────────────────────────────────
class TestNotifier:

    def test_notify_does_not_crash(self):
        """notify() should never raise — always fails gracefully."""
        from agent.notifier import notify
        try:
            notify("Test Alert", "Unit test notification", severity="INFO")
        except Exception as e:
            pytest.fail(f"notify() raised an exception: {e}")

    def test_notify_long_message(self):
        from agent.notifier import notify
        long_msg = "x" * 1000
        notify("Long Message", long_msg, severity="WARNING")

    def test_notify_critical_severity(self):
        from agent.notifier import notify
        notify("Critical Test", "Testing critical notification", severity="CRITICAL")


# ── Process Monitor ───────────────────────────────────────────
class TestProcessMonitor:

    def test_process_monitor_creates(self):
        from agent.process_monitor import ProcessMonitor
        pm = ProcessMonitor()
        assert pm is not None

    def test_scan_once_returns_list(self):
        from agent.process_monitor import ProcessMonitor
        pm     = ProcessMonitor()
        result = pm.scan_once()
        assert isinstance(result, list)

    def test_scan_once_no_crash(self):
        from agent.process_monitor import ProcessMonitor
        pm = ProcessMonitor()
        try:
            pm.scan_once()
        except Exception as e:
            pytest.fail(f"scan_once() raised: {e}")


# ── Network Monitor ───────────────────────────────────────────
class TestNetworkMonitor:

    def test_network_monitor_creates(self):
        from agent.network_monitor import NetworkMonitor
        nm = NetworkMonitor()
        assert nm is not None

    def test_scan_once_returns_list(self):
        from agent.network_monitor import NetworkMonitor
        nm     = NetworkMonitor()
        result = nm.scan_once()
        assert isinstance(result, list)


# ── Registry Monitor ──────────────────────────────────────────
class TestRegistryMonitor:

    def test_registry_monitor_creates(self):
        from agent.registry_monitor import RegistryMonitor
        rm = RegistryMonitor()
        assert rm is not None

    def test_snapshot_returns_dict(self):
        from agent.registry_monitor import RegistryMonitor
        rm      = RegistryMonitor()
        snap    = rm._snapshot()
        assert isinstance(snap, dict)

    def test_scan_once_returns_list(self):
        from agent.registry_monitor import RegistryMonitor
        rm = RegistryMonitor()
        rm._baseline = rm._snapshot()  # Establish baseline first
        result = rm.scan_once()
        assert isinstance(result, list)


# ── File Monitor ──────────────────────────────────────────────
class TestFileMonitor:

    def test_file_monitor_creates(self):
        from agent.file_monitor import FileMonitor
        fm = FileMonitor()
        assert fm is not None

    def test_file_monitor_start_stop(self):
        """FileMonitor start/stop should not crash."""
        from agent.file_monitor import FileMonitor
        fm = FileMonitor()
        try:
            fm.start()
            fm.stop()
        except Exception as e:
            pytest.fail(f"FileMonitor start/stop raised: {e}")


# ── File Analyzer ─────────────────────────────────────────────
class TestFileAnalyzer:

    def test_nonexistent_file_graceful(self):
        from engine.file_analyzer import analyze_file
        result = analyze_file("C:/does/not/exist.exe")
        assert "reasons" in result
        assert "file_not_found" in result["reasons"][0].lower() or len(result["reasons"]) > 0

    def test_analyze_python_file(self):
        """Analyze a known safe Python file."""
        from engine.file_analyzer import analyze_file
        this_file = str(Path(__file__))
        result    = analyze_file(this_file)
        assert "sha256"    in result
        assert "entropy"   in result
        assert "file_name" in result
        assert result["file_size_bytes"] > 0
        assert result["sha256"]           != ""

    def test_entropy_calculation(self):
        import tempfile, os
        from engine.file_analyzer import _file_entropy

        # Write a known file and check entropy is reasonable
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 1024)
            fname = f.name

        entropy = _file_entropy(fname)
        os.unlink(fname)
        assert entropy == 0.0  # All zeros → 0 entropy

    def test_high_entropy_random_bytes(self):
        import os, tempfile
        from engine.file_analyzer import _file_entropy

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(os.urandom(4096))
            fname = f.name

        entropy = _file_entropy(fname)
        os.unlink(fname)
        assert entropy > 7.0  # Random bytes → high entropy


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
