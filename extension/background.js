/**
 * ABTD Chrome Extension — background.js (Service Worker)
 * =========================================================
 * Intercepts navigation events, sends URLs to the ABTD Flask
 * backend for analysis, and shows warning overlays on threats.
 *
 * Manifest V3 Service Worker (no persistent background page).
 */

const ABTD_API = "http://127.0.0.1:5000";

// ── Whitelist of trusted domains (skip analysis for speed) ──
const TRUSTED_DOMAINS = new Set([
  "google.com", "www.google.com", "accounts.google.com",
  "github.com", "stackoverflow.com", "microsoft.com",
  "localhost", "127.0.0.1",
]);

// ── In-memory cache (url → result, expires in 5 min) ────────
const _cache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

function getCached(url) {
  const entry = _cache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.time > CACHE_TTL_MS) { _cache.delete(url); return null; }
  return entry.result;
}

function setCache(url, result) {
  _cache.set(url, { result, time: Date.now() });
  if (_cache.size > 200) {
    // Evict oldest entry
    _cache.delete(_cache.keys().next().value);
  }
}

// ── Extract domain from URL ───────────────────────────────────
function getDomain(url) {
  try { return new URL(url).hostname; }
  catch { return ""; }
}

// ── Analyze URL via ABTD API ─────────────────────────────────
async function analyzeUrl(url) {
  const cached = getCached(url);
  if (cached) return cached;

  try {
    const response = await fetch(`${ABTD_API}/predict`, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({ url }),
    });

    if (!response.ok) return null;
    const result = await response.json();
    setCache(url, result);
    return result;
  } catch (e) {
    // ABTD server not running — silent fail
    return null;
  }
}

// ── Show Chrome notification ──────────────────────────────────
function showNotification(title, message, id) {
  chrome.notifications.create(id || "abtd-alert", {
    type    : "basic",
    iconUrl : "icons/icon48.png",
    title   : `🛡️ ABTD — ${title}`,
    message : message,
    priority: 2,
  });
}

// ── Update extension icon based on threat level ───────────────
function updateIcon(tabId, classification) {
  // All icons use same file — badge color indicates status
  const BADGE_COLORS = {
    SAFE       : "#22c55e",
    SUSPICIOUS : "#f59e0b",
    MALICIOUS  : "#ef4444",
    CRITICAL   : "#7c3aed",
  };

  const BADGE_TEXT = {
    SAFE      : "✓",
    SUSPICIOUS: "!",
    MALICIOUS : "✗",
    CRITICAL  : "✗✗",
  };

  const color = BADGE_COLORS[classification] || "#3b82f6";
  const text  = BADGE_TEXT[classification]   || "?";

  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

// ── Inject warning overlay into tab ──────────────────────────
async function injectWarning(tabId, result) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func  : (result) => {
        // Remove existing overlay
        const existing = document.getElementById("abtd-overlay");
        if (existing) existing.remove();

        const cls   = (result.classification || "").toLowerCase();
        const score = result.threat_score || 0;
        const colors = {
          suspicious: "#f59e0b",
          malicious : "#ef4444",
          critical  : "#7c3aed",
        };
        const color = colors[cls] || "#f59e0b";

        const overlay = document.createElement("div");
        overlay.id    = "abtd-overlay";
        overlay.style.cssText = `
          position: fixed;
          top: 0; left: 0; right: 0;
          background: ${color}1a;
          border-bottom: 3px solid ${color};
          z-index: 2147483647;
          padding: 12px 20px;
          font-family: -apple-system, sans-serif;
          display: flex;
          align-items: center;
          justify-content: space-between;
          backdrop-filter: blur(8px);
          animation: abtdSlideIn 0.3s ease;
        `;

        const style = document.createElement("style");
        style.textContent = `@keyframes abtdSlideIn { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }`;
        document.head.appendChild(style);

        overlay.innerHTML = `
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:20px">${cls === "critical" ? "🔴" : cls === "malicious" ? "🚫" : "⚠️"}</span>
            <div>
              <div style="font-size:14px;font-weight:700;color:${color}">ABTD — ${result.classification} THREAT (Score: ${score}/100)</div>
              <div style="font-size:12px;color:#ccc;margin-top:2px">${result.recommended_action || ""}</div>
            </div>
          </div>
          <button id="abtd-dismiss" style="background:none;border:1px solid ${color}44;color:${color};padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">Dismiss</button>
        `;

        document.body.insertAdjacentElement("afterbegin", overlay);
        document.getElementById("abtd-dismiss")?.addEventListener("click", () => overlay.remove());
        setTimeout(() => overlay?.remove(), 15000);
      },
      args: [result],
    });
  } catch (e) {
    // Tab not accessible (e.g., chrome:// pages)
  }
}

// ── Main: Listen to navigation ────────────────────────────────
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;  // Main frame only
  const url    = details.url;
  const tabId  = details.tabId;

  // Skip non-HTTP, chrome://, data: etc.
  if (!url.startsWith("http://") && !url.startsWith("https://")) return;

  // Skip trusted domains
  const domain = getDomain(url);
  if (TRUSTED_DOMAINS.has(domain)) {
    updateIcon(tabId, "SAFE");
    return;
  }

  // Analyze
  const result = await analyzeUrl(url);
  if (!result) {
    chrome.action.setBadgeText({ text: "?", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#475569", tabId });
    return;
  }

  const cls = result.classification || "UNKNOWN";
  updateIcon(tabId, cls);

  // Save to extension storage for popup
  chrome.storage.session.set({ [`tab_${tabId}`]: result });

  // Show warning for threats
  if (["SUSPICIOUS", "MALICIOUS", "CRITICAL"].includes(cls)) {
    if (cls === "MALICIOUS" || cls === "CRITICAL") {
      showNotification(
        `${cls} URL Detected`,
        `${domain} — Score: ${result.threat_score}/100\n${result.recommended_action || ""}`,
        `abtd-${tabId}`,
      );
    }
    injectWarning(tabId, result);
  }
});

// Reset badge on new navigation start
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0) {
    chrome.action.setBadgeText({ text: "…", tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#3b82f6", tabId: details.tabId });
  }
});
