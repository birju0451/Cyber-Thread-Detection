/**
 * ABTD Chrome Extension — background.js (Service Worker)
 * =========================================================
 * Intercepts navigation events, sends URLs to the ABTD Flask
 * backend for ABTD analysis AND Zero Trust evaluation.
 *
 * Flow:
 *   URL Visit → ABTD /predict → ZT /api/zero-trust/evaluate
 *   → Combined result → Badge + Warning Overlay
 *
 * Manifest V3 Service Worker (no persistent background page).
 */

const ABTD_API = "http://127.0.0.1:5000";

// ── Connection state ──────────────────────────────────────────
let _apiConnected = false;
let _protectionActive = false;

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
    _cache.delete(_cache.keys().next().value);
  }
}

// ── Session stats ─────────────────────────────────────────────
let _stats = { scanned: 0, threats: 0, safe: 0, blocked: 0 };

// ── Extract domain from URL ───────────────────────────────────
function getDomain(url) {
  try { return new URL(url).hostname; }
  catch { return ""; }
}

// ── Health check: ping ABTD API ───────────────────────────────
async function checkConnection() {
  try {
    const response = await fetch(`${ABTD_API}/api/system/info`, {
      signal: AbortSignal.timeout(3000),
    });
    _apiConnected = response.ok;
    _protectionActive = response.ok;
  } catch {
    _apiConnected = false;
    _protectionActive = false;
  }
  return _apiConnected;
}

// Periodic health check
setInterval(checkConnection, 30000);
checkConnection();

// ── Analyze URL via ABTD API + ZT Evaluate ───────────────────
async function analyzeUrl(url) {
  const cached = getCached(url);
  if (cached) return cached;

  try {
    // Step 1: ABTD threat analysis
    const abtdResp = await fetch(`${ABTD_API}/predict`, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({ url }),
      signal : AbortSignal.timeout(8000),
    });

    if (!abtdResp.ok) return null;
    const abtdResult = await abtdResp.json();

    _apiConnected = true;
    _protectionActive = true;

    // Step 2: Zero Trust evaluation
    let ztResult = null;
    try {
      const ztResp = await fetch(`${ABTD_API}/api/zero-trust/evaluate`, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify({
          event_type    : "url",
          resource      : url,
          action        : "read",
          process_name  : "chrome.exe",
          abtd_result   : abtdResult,
        }),
        signal : AbortSignal.timeout(5000),
      });

      if (ztResp.ok) {
        const ztJson = await ztResp.json();
        ztResult = ztJson.data || ztJson;
      }
    } catch {
      // ZT evaluation failed — continue with ABTD result only
    }

    // Combine results
    const combined = {
      ...abtdResult,
      zt_decision       : ztResult?.decision || "UNKNOWN",
      zt_trust_score     : ztResult?.trust_score || 0,
      zt_trust_level     : ztResult?.trust_level || "UNKNOWN",
      zt_overall_risk    : ztResult?.overall_risk || 0,
      zt_decision_reason : ztResult?.decision_reason || "",
      zt_decision_color  : ztResult?.decision_color || "#6b7280",
      zt_decision_icon   : ztResult?.decision_icon || "❓",
      zt_policy_name     : ztResult?.policy_name || "",
      has_zt             : !!ztResult,
    };

    // Update stats
    _stats.scanned++;
    if (["SUSPICIOUS", "MALICIOUS", "CRITICAL"].includes(abtdResult.classification)) {
      _stats.threats++;
    } else {
      _stats.safe++;
    }
    if (combined.zt_decision === "BLOCK") {
      _stats.blocked++;
    }

    setCache(url, combined);
    return combined;
  } catch (e) {
    _apiConnected = false;
    _protectionActive = false;
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
function updateIcon(tabId, classification, ztDecision) {
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

  // Use ZT decision color if BLOCK
  let color, text;
  if (ztDecision === "BLOCK") {
    color = "#ef4444";
    text  = "🚫";
  } else if (ztDecision === "RESTRICT") {
    color = "#f97316";
    text  = "⚠";
  } else {
    color = BADGE_COLORS[classification] || "#3b82f6";
    text  = BADGE_TEXT[classification]   || "?";
  }

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

        const cls    = (result.classification || "").toLowerCase();
        const score  = result.threat_score || 0;
        const ztDec  = result.zt_decision || "UNKNOWN";
        const ztRisk = result.zt_overall_risk || 0;
        const colors = {
          suspicious: "#f59e0b",
          malicious : "#ef4444",
          critical  : "#7c3aed",
        };
        const color = colors[cls] || "#f59e0b";

        // If ZT says BLOCK, show full-page block overlay
        if (ztDec === "BLOCK") {
          const blocker = document.createElement("div");
          blocker.id = "abtd-overlay";
          blocker.style.cssText = `
            position:fixed; top:0; left:0; right:0; bottom:0;
            background:rgba(8,12,20,0.97);
            z-index:2147483647;
            display:flex; flex-direction:column;
            align-items:center; justify-content:center;
            font-family: -apple-system, sans-serif;
            color: #f1f5f9;
          `;
          blocker.innerHTML = `
            <div style="font-size:64px;margin-bottom:20px">🚫</div>
            <div style="font-size:24px;font-weight:900;color:#ef4444;margin-bottom:12px">
              ABTD Zero Trust — ACCESS BLOCKED
            </div>
            <div style="font-size:14px;color:#94a3b8;max-width:500px;text-align:center;margin-bottom:8px">
              This page has been blocked by the Zero Trust security policy.
            </div>
            <div style="font-size:13px;color:#64748b;margin-bottom:24px">
              Threat Score: ${score}/100 | ZT Risk: ${ztRisk}/100 | Policy: ${result.zt_policy_name || "Security"}
            </div>
            <div style="font-size:12px;color:#475569;max-width:400px;text-align:center">
              ${result.zt_decision_reason || result.recommended_action || "High-risk content detected"}
            </div>
            <button onclick="this.parentElement.remove()" style="
              margin-top:30px; padding:8px 24px;
              background:transparent; border:1px solid #475569;
              color:#94a3b8; border-radius:6px; cursor:pointer;
              font-size:12px;
            ">Dismiss Warning (Not Recommended)</button>
          `;
          document.documentElement.insertBefore(blocker, document.documentElement.firstChild);
          return;
        }

        // Standard warning banner for SUSPICIOUS/MALICIOUS
        const overlay = document.createElement("div");
        overlay.id    = "abtd-overlay";
        overlay.style.cssText = `
          position: fixed; top: 0; left: 0; right: 0;
          background: ${color}1a;
          border-bottom: 3px solid ${color};
          z-index: 2147483647;
          padding: 12px 20px;
          font-family: -apple-system, sans-serif;
          display: flex; align-items: center;
          justify-content: space-between;
          backdrop-filter: blur(8px);
          animation: abtdSlideIn 0.3s ease;
        `;

        const style = document.createElement("style");
        style.textContent = `@keyframes abtdSlideIn { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }`;
        document.head.appendChild(style);

        const ztLabel = result.has_zt
          ? `<span style="font-size:11px;padding:2px 6px;border-radius:3px;background:${result.zt_decision_color}22;color:${result.zt_decision_color};margin-left:8px">${result.zt_decision_icon} ZT: ${ztDec}</span>`
          : "";

        overlay.innerHTML = `
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:20px">${cls === "critical" ? "🔴" : cls === "malicious" ? "🚫" : "⚠️"}</span>
            <div>
              <div style="font-size:14px;font-weight:700;color:${color}">
                ABTD — ${result.classification} (Score: ${score}/100) ${ztLabel}
              </div>
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
    updateIcon(tabId, "SAFE", "ALLOW");
    return;
  }

  // Analyze
  const result = await analyzeUrl(url);
  if (!result) {
    chrome.action.setBadgeText({ text: "?", tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#475569", tabId });
    return;
  }

  const cls     = result.classification || "UNKNOWN";
  const ztDec   = result.zt_decision || "UNKNOWN";
  updateIcon(tabId, cls, ztDec);

  // Save to extension storage for popup
  chrome.storage.session.set({
    [`tab_${tabId}`]: result,
    connection: _apiConnected,
    protection: _protectionActive,
    stats: _stats,
  });

  // Show warning for threats
  if (["SUSPICIOUS", "MALICIOUS", "CRITICAL"].includes(cls) || ztDec === "BLOCK") {
    if (cls === "MALICIOUS" || cls === "CRITICAL" || ztDec === "BLOCK") {
      showNotification(
        ztDec === "BLOCK" ? "URL BLOCKED" : `${cls} URL Detected`,
        `${domain} — Score: ${result.threat_score}/100 | ZT: ${ztDec}\n${result.recommended_action || ""}`,
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

// ── Message handler for popup queries ─────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "get_status") {
    sendResponse({
      connected : _apiConnected,
      protection: _protectionActive,
      stats     : _stats,
    });
    return true;
  }
  if (msg.action === "check_health") {
    checkConnection().then(ok => sendResponse({ connected: ok }));
    return true;
  }
});
