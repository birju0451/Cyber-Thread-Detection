/**
 * ABTD Chrome Extension — content.js
 * =====================================
 * Content script injected into every web page.
 *
 * Responsibilities:
 *  1. Intercepts clicks on external links before navigation
 *  2. Scans hovered links and shows a mini threat badge
 *  3. Receives warning injection messages from background.js
 *  4. Shows / dismisses the threat overlay banner
 */

(function () {
  "use strict";

  const ABTD_API   = "http://127.0.0.1:5000";
  const STYLE_ID   = "abtd-content-style";
  const BANNER_ID  = "abtd-threat-banner";
  const TOOLTIP_ID = "abtd-link-tooltip";

  // ── Inject base styles once ─────────────────────────────────
  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      #${BANNER_ID} {
        position: fixed;
        top: 0; left: 0; right: 0;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 13px;
        padding: 10px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        backdrop-filter: blur(10px);
        border-bottom: 3px solid var(--abtd-color, #ef4444);
        background: color-mix(in srgb, var(--abtd-color, #ef4444) 10%, rgba(8,12,20,0.95));
        animation: abtd-slide-down 0.3s ease;
        box-shadow: 0 2px 20px rgba(0,0,0,0.6);
      }
      @keyframes abtd-slide-down {
        from { transform: translateY(-100%); opacity: 0; }
        to   { transform: translateY(0);     opacity: 1; }
      }
      #${BANNER_ID} .abtd-content {
        display: flex; align-items: center; gap: 10px; flex: 1;
      }
      #${BANNER_ID} .abtd-icon { font-size: 20px; }
      #${BANNER_ID} .abtd-text { color: #f1f5f9; }
      #${BANNER_ID} .abtd-title { font-weight: 700; color: var(--abtd-color, #ef4444); }
      #${BANNER_ID} .abtd-sub { font-size: 11px; color: #94a3b8; margin-top: 2px; }
      #${BANNER_ID} .abtd-score {
        font-size: 22px; font-weight: 900;
        color: var(--abtd-color, #ef4444);
        min-width: 50px; text-align: right;
      }
      #${BANNER_ID} .abtd-close {
        background: none;
        border: 1px solid rgba(255,255,255,0.2);
        color: #94a3b8;
        padding: 4px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 12px;
        white-space: nowrap;
        transition: all 0.15s;
      }
      #${BANNER_ID} .abtd-close:hover { background: rgba(255,255,255,0.1); color: #f1f5f9; }
      #${TOOLTIP_ID} {
        position: fixed;
        z-index: 2147483646;
        font-family: -apple-system, sans-serif;
        font-size: 11px;
        padding: 6px 10px;
        background: #080c14;
        border: 1px solid rgba(99,179,237,0.2);
        border-radius: 6px;
        color: #94a3b8;
        pointer-events: none;
        box-shadow: 0 4px 16px rgba(0,0,0,0.6);
        white-space: nowrap;
        max-width: 280px;
        overflow: hidden;
        text-overflow: ellipsis;
        display: none;
      }
    `;
    document.documentElement.appendChild(style);
  }

  // ── Show threat banner ───────────────────────────────────────
  function showBanner(result) {
    removeBanner();
    const cls    = (result.classification || "UNKNOWN").toLowerCase();
    const score  = result.threat_score || 0;
    const colors = {
      suspicious: "#f59e0b",
      malicious : "#ef4444",
      critical  : "#7c3aed",
    };
    const icons  = {
      suspicious: "⚠️", malicious: "🚫", critical: "🔴",
    };
    const color  = colors[cls] || "#f59e0b";
    const icon   = icons[cls]  || "⚠️";

    const banner = document.createElement("div");
    banner.id    = BANNER_ID;
    banner.style.setProperty("--abtd-color", color);

    banner.innerHTML = `
      <div class="abtd-content">
        <span class="abtd-icon">${icon}</span>
        <div class="abtd-text">
          <div class="abtd-title">ABTD: ${result.classification} DETECTED</div>
          <div class="abtd-sub">${(result.reasons || [])[0] || result.recommended_action || ""}</div>
        </div>
      </div>
      <span class="abtd-score">${score}</span>
      <button class="abtd-close" id="abtd-dismiss-btn">Dismiss ✕</button>
    `;

    document.documentElement.insertBefore(banner, document.documentElement.firstChild);

    document.getElementById("abtd-dismiss-btn")?.addEventListener("click", removeBanner);
    setTimeout(removeBanner, 20000);
  }

  function removeBanner() {
    document.getElementById(BANNER_ID)?.remove();
  }

  // ── Link hover scanner ───────────────────────────────────────
  let _hoverCache   = {};
  let _tooltipEl    = null;
  let _hoverTimer   = null;

  function getTooltip() {
    if (!_tooltipEl) {
      _tooltipEl    = document.createElement("div");
      _tooltipEl.id = TOOLTIP_ID;
      document.documentElement.appendChild(_tooltipEl);
    }
    return _tooltipEl;
  }

  function showTooltip(text, x, y, color) {
    const el   = getTooltip();
    el.textContent  = text;
    el.style.color  = color || "#94a3b8";
    el.style.left   = (x + 12) + "px";
    el.style.top    = (y + 12) + "px";
    el.style.display = "block";
  }

  function hideTooltip() {
    if (_tooltipEl) _tooltipEl.style.display = "none";
  }

  async function scanLinkHover(url, x, y) {
    if (_hoverCache[url] !== undefined) {
      const cached = _hoverCache[url];
      if (cached === null) return;
      showTooltip(
        `🛡️ ABTD: ${cached.classification} (${cached.threat_score}/100)`,
        x, y,
        ["MALICIOUS","CRITICAL"].includes(cached.classification) ? "#ef4444" :
        cached.classification === "SUSPICIOUS" ? "#f59e0b" : "#22c55e"
      );
      return;
    }

    // Mark as in-flight
    _hoverCache[url] = null;
    showTooltip("🔍 Checking…", x, y);

    try {
      const res  = await fetch(`${ABTD_API}/predict`, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify({ url }),
        signal : AbortSignal.timeout(5000),
      });
      const data = await res.json();
      _hoverCache[url] = data;

      const color = data.classification === "MALICIOUS" || data.classification === "CRITICAL"
        ? "#ef4444"
        : data.classification === "SUSPICIOUS" ? "#f59e0b" : "#22c55e";
      showTooltip(`🛡️ ${data.classification} — ${data.threat_score}/100`, x, y, color);
    } catch {
      hideTooltip();
      delete _hoverCache[url];
    }
  }

  // Attach link hover listeners
  function attachHoverListeners() {
    document.addEventListener("mouseover", (e) => {
      const a = e.target.closest("a[href]");
      if (!a) return;

      const href = a.href;
      if (!href.startsWith("http")) return;
      if (href.includes("127.0.0.1") || href.includes("localhost")) return;

      clearTimeout(_hoverTimer);
      _hoverTimer = setTimeout(() => {
        scanLinkHover(href, e.clientX, e.clientY);
      }, 800);  // 800ms dwell before scan
    });

    document.addEventListener("mouseout", (e) => {
      if (e.target.closest("a[href]")) {
        clearTimeout(_hoverTimer);
        hideTooltip();
      }
    });
  }

  // ── Message listener (from background.js) ───────────────────
  chrome.runtime.onMessage.addListener((msg, sender, respond) => {
    if (msg.action === "show_warning" && msg.result) {
      showBanner(msg.result);
    }
    if (msg.action === "hide_warning") {
      removeBanner();
    }
    respond({ ok: true });
  });

  // ── Init ─────────────────────────────────────────────────────
  function init() {
    injectStyles();
    attachHoverListeners();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
