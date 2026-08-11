"""
ml/feature_engineering.py
==========================
Shared feature extraction functions used by ALL training scripts and the live engine.

Provides:
  - extract_url_features(url)  → dict of 25 URL features
  - extract_file_features(path) → dict of file-based features
  - URL_FEATURE_COLS           → ordered column list for URL model
  - MALWARE_FEATURE_COLS       → ordered column list for malware model
"""

import re
import os
import math
import hashlib
from pathlib import Path
from urllib.parse import urlparse

try:
    import tldextract
    _TLDEXTRACT_OK = True
except ImportError:
    _TLDEXTRACT_OK = False

# ---------------------------------------------------------------------------
# URL Features
# ---------------------------------------------------------------------------

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "clck.ru",
    "rb.gy", "cutt.ly", "shorturl.at",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "banking", "paypal", "amazon", "google", "microsoft",
    "apple", "ebay", "password", "credential", "wallet", "crypto",
    "free", "winner", "prize", "click", "urgent", "suspend",
]

BRAND_NAMES = {
    "paypal", "amazon", "google", "microsoft", "apple", "ebay",
    "netflix", "facebook", "instagram", "twitter", "linkedin",
    "dropbox", "chase", "wellsfargo", "bankofamerica", "citibank",
}


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in freq if p > 0)


def _has_ip(url: str) -> int:
    """Return 1 if URL contains an IPv4 address as hostname."""
    pattern = r"(https?://)?\d{1,3}(\.\d{1,3}){3}"
    return int(bool(re.search(pattern, url)))


def extract_url_features(url: str) -> dict:
    """
    Extract 30 numerical features from a raw URL string.

    Returns a dict with all feature names and values.
    All values are numeric (int or float).
    """
    url = str(url).strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    if _TLDEXTRACT_OK:
        ext = tldextract.extract(url)
        domain     = ext.domain or ""
        subdomain  = ext.subdomain or ""
        suffix     = ext.suffix or ""
    else:
        parts  = hostname.split(".")
        domain = parts[-2] if len(parts) >= 2 else hostname
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        suffix = parts[-1] if parts else ""

    full_url_len    = len(url)
    hostname_len    = len(hostname)
    path_len        = len(path)
    query_len       = len(query)
    dot_count       = url.count(".")
    hyphen_count    = hostname.count("-")
    underscore_count= url.count("_")
    slash_count     = url.count("/")
    at_count        = url.count("@")
    digit_count     = sum(c.isdigit() for c in url)
    special_char_count = sum(not c.isalnum() and c not in "/:.-_?=&" for c in url)

    # Subdomain depth
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0

    # Domain entropy (high entropy → random, DGA-like)
    domain_entropy  = _entropy(domain)

    # Suspicious signals
    has_ip_flag         = _has_ip(url)
    has_https           = int(parsed.scheme == "https")
    is_url_shortener    = int(hostname in URL_SHORTENER_DOMAINS or
                              any(s in hostname for s in URL_SHORTENER_DOMAINS))
    has_at_symbol       = int("@" in url)
    has_hex_chars       = int(bool(re.search(r"%[0-9a-fA-F]{2}", url)))
    has_double_slash    = int("//" in path)
    is_long_url         = int(full_url_len > 75)
    has_suspicious_word = int(any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS))
    has_brand_name      = int(any(b in domain.lower() for b in BRAND_NAMES))
    has_double_ext      = int(bool(re.search(r"\.(exe|php|js|bat)\.", path.lower())))
    has_port            = int(bool(parsed.port))
    redirect_count      = url.lower().count("http", 1)   # extra http= in URL

    # Ratio features
    digit_ratio = digit_count / max(full_url_len, 1)

    return {
        "url_length"         : full_url_len,
        "hostname_length"    : hostname_len,
        "path_length"        : path_len,
        "query_length"       : query_len,
        "dot_count"          : dot_count,
        "hyphen_count"       : hyphen_count,
        "underscore_count"   : underscore_count,
        "slash_count"        : slash_count,
        "at_count"           : at_count,
        "digit_count"        : digit_count,
        "special_char_count" : special_char_count,
        "subdomain_depth"    : subdomain_depth,
        "domain_entropy"     : domain_entropy,
        "has_ip"             : has_ip_flag,
        "has_https"          : has_https,
        "is_url_shortener"   : is_url_shortener,
        "has_at_symbol"      : has_at_symbol,
        "has_hex_chars"      : has_hex_chars,
        "has_double_slash"   : has_double_slash,
        "is_long_url"        : is_long_url,
        "has_suspicious_word": has_suspicious_word,
        "has_brand_name"     : has_brand_name,
        "has_double_ext"     : has_double_ext,
        "has_port"           : has_port,
        "redirect_count"     : redirect_count,
        "digit_ratio"        : digit_ratio,
    }


# Canonical feature column order for URL model input
URL_FEATURE_COLS = list(extract_url_features("http://example.com").keys())


# ---------------------------------------------------------------------------
# File / Malware Features
# ---------------------------------------------------------------------------

def extract_file_features(file_path: str) -> dict:
    """
    Extract numeric features from a file for malware classification.

    Returns a dict of features. Falls back gracefully on permission errors.
    """
    path = Path(file_path)
    features = {
        "file_size"       : 0,
        "extension_risk"  : 0,
        "entropy"         : 0.0,
        "is_executable"   : 0,
        "is_script"       : 0,
        "is_archive"      : 0,
        "has_pe_header"   : 0,
        "name_length"     : len(path.name),
        "name_entropy"    : _entropy(path.stem),
        "name_digit_ratio": sum(c.isdigit() for c in path.stem) / max(len(path.stem), 1),
        "in_temp_dir"     : 0,
        "in_startup_dir"  : 0,
        "double_extension": 0,
    }

    HIGH_RISK_EXT = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                     ".jar", ".msi", ".hta", ".scr", ".pif", ".com"}
    SCRIPT_EXT    = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}
    ARCHIVE_EXT   = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".iso"}

    suffix = path.suffix.lower()
    features["is_executable"] = int(suffix in HIGH_RISK_EXT)
    features["is_script"]     = int(suffix in SCRIPT_EXT)
    features["is_archive"]    = int(suffix in ARCHIVE_EXT)
    features["extension_risk"]= int(suffix in HIGH_RISK_EXT)

    # Double extension check (e.g. "document.pdf.exe")
    name = path.name.lower()
    if name.count(".") >= 2:
        features["double_extension"] = 1

    # Path-based signals
    str_path = str(file_path).lower()
    temp_indicators = ["\\temp\\", "\\tmp\\", "appdata\\local\\temp"]
    startup_indicators = ["\\startup\\", "\\start menu\\programs\\startup"]
    features["in_temp_dir"]    = int(any(t in str_path for t in temp_indicators))
    features["in_startup_dir"] = int(any(s in str_path for s in startup_indicators))

    try:
        features["file_size"] = path.stat().st_size

        # Read first 4 bytes for PE header ("MZ")
        with open(path, "rb") as f:
            header = f.read(4)
            features["has_pe_header"] = int(header[:2] == b"MZ")

            # Read entire file for entropy (cap at 1MB for speed)
            f.seek(0)
            data = f.read(1_048_576)
            if data:
                byte_counts = [0] * 256
                for b in data:
                    byte_counts[b] += 1
                total = len(data)
                features["entropy"] = -sum(
                    (c / total) * math.log2(c / total)
                    for c in byte_counts if c > 0
                )
    except (PermissionError, OSError, FileNotFoundError):
        pass

    return features


# Canonical feature column order for malware model
MALWARE_FEATURE_COLS = list(extract_file_features(
    os.path.join(os.environ.get("SYSTEMROOT", "C:/Windows"), "notepad.exe")
    if os.path.exists(os.path.join(os.environ.get("SYSTEMROOT", "C:/Windows"), "notepad.exe"))
    else __file__
).keys())
