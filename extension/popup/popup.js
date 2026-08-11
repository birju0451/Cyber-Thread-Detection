/**
 * ABTD Extension — popup.js
 * ==========================
 * Loads current tab analysis, handles quick scan, updates stats.
 */

const API = "http://127.0.0.1:5000";

// Session counters stored in chrome.storage.session
let sessionStats = { scans: 0, threats: 0, safe: 0 };

async function init() {
  await loadSessionStats();
  await checkConnection();
  await loadCurrentTab();
  setupScanBtn();
}

// ── Connection Check ─────────────────────────────────────────
async function checkConnection() {
  const pill = document.getElementById("conn-status");
  const text = document.getElementById("conn-text");
  const api  = document.getElementById("api-status");
  try {
    const res = await fetch(`${API}/api/status`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      pill.classList.remove("offline");
      text.textContent = "Protected";
      api.textContent  = "API: Online";
      api.style.color  = "#22c55e";
    } else { throw new Error(); }
  } catch {
    pill.classList.add("offline");
    text.textContent = "Offline";
    api.textContent  = "API: Offline";
    api.style.color  = "#ef4444";
  }
}

// ── Current Tab Analysis ──────────────────────────────────────
async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const el    = document.getElementById("current-result");

  if (!tab?.url?.startsWith("http")) {
    el.className = "result-box";
    el.innerHTML = `<span class="result-icon">🔒</span><div class="result-info"><div class="result-cls" style="color:#475569">System Page</div><div class="result-url">Not analyzed</div></div>`;
    return;
  }

  // Try session cache first
  const stored = await chrome.storage.session.get(`tab_${tab.id}`);
  const result = stored[`tab_${tab.id}`];

  if (result) {
    renderCurrentResult(result, tab.url);
  } else {
    // Fetch live
    try {
      const res  = await fetch(`${API}/predict`, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify({ url: tab.url }),
        signal : AbortSignal.timeout(8000),
      });
      const data = await res.json();
      renderCurrentResult(data, tab.url);
      await chrome.storage.session.set({ [`tab_${tab.id}`]: data });
    } catch {
      el.className = "result-box";
      el.innerHTML = `<span class="result-icon">❓</span><div class="result-info"><div class="result-cls" style="color:#475569">Cannot connect to ABTD</div><div class="result-url">Make sure the server is running</div></div>`;
    }
  }
}

function renderCurrentResult(result, url) {
  const el  = document.getElementById("current-result");
  const cls = (result.classification || "unknown").toLowerCase();
  const COLORS = { safe:"#22c55e", suspicious:"#f59e0b", malicious:"#ef4444", critical:"#7c3aed" };
  const color  = COLORS[cls] || "#94a3b8";
  const score  = result.threat_score || 0;

  el.className = `result-box ${cls}`;
  el.innerHTML = `
    <span class="result-icon">${result.icon || "❓"}</span>
    <div class="result-info">
      <div class="result-cls" style="color:${color}">${result.classification}</div>
      <div class="result-url">${truncate(url, 40)}</div>
      <div class="score-bar"><div class="score-fill" style="width:${score}%;background:${color}"></div></div>
    </div>
    <div class="result-score" style="color:${color}">${score}</div>`;
}

// ── Quick Scan ────────────────────────────────────────────────
function setupScanBtn() {
  const btn   = document.getElementById("scan-btn");
  const input = document.getElementById("scan-input");
  const res   = document.getElementById("scan-result");

  btn.addEventListener("click", async () => {
    const url = input.value.trim();
    if (!url) return;

    btn.disabled    = true;
    btn.textContent = "…";
    res.innerHTML   = "";

    try {
      const response = await fetch(`${API}/predict`, {
        method : "POST",
        headers: { "Content-Type": "application/json" },
        body   : JSON.stringify({ url }),
        signal : AbortSignal.timeout(10000),
      });
      const data = await response.json();
      renderScanResult(data, res);
      await updateStats(data);
    } catch (e) {
      res.innerHTML = `<div style="color:#ef4444;font-size:11px;margin-top:6px">Scan failed — check connection</div>`;
    } finally {
      btn.disabled    = false;
      btn.textContent = "Scan";
    }
  });

  input.addEventListener("keydown", (e) => { if (e.key === "Enter") btn.click(); });
}

function renderScanResult(r, container) {
  const cls   = (r.classification || "unknown").toLowerCase();
  const COLORS = { safe:"#22c55e", suspicious:"#f59e0b", malicious:"#ef4444", critical:"#7c3aed" };
  const color  = COLORS[cls] || "#94a3b8";
  const score  = r.threat_score || 0;

  container.innerHTML = `
    <div style="margin-top:8px;padding:8px 10px;background:#13192a;border-radius:6px;border:1px solid ${color}44">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <span style="font-weight:700;color:${color}">${r.icon || ""} ${r.classification}</span>
        <span style="font-weight:800;color:${color}">${score}/100</span>
      </div>
      <div style="font-size:10px;color:#475569;margin-top:4px">${(r.reasons || [])[0] || ""}</div>
    </div>`;
}

// ── Session Stats ─────────────────────────────────────────────
async function loadSessionStats() {
  const stored = await chrome.storage.session.get("abtd_stats");
  if (stored.abtd_stats) sessionStats = stored.abtd_stats;
  updateStatsUI();
}

async function updateStats(result) {
  sessionStats.scans++;
  if (["SUSPICIOUS","MALICIOUS","CRITICAL"].includes(result.classification)) {
    sessionStats.threats++;
  } else {
    sessionStats.safe++;
  }
  await chrome.storage.session.set({ abtd_stats: sessionStats });
  updateStatsUI();
}

function updateStatsUI() {
  document.getElementById("stat-scans").textContent   = sessionStats.scans;
  document.getElementById("stat-threats").textContent = sessionStats.threats;
  document.getElementById("stat-safe").textContent    = sessionStats.safe;
}

// ── Helpers ───────────────────────────────────────────────────
function truncate(str, n) { return str?.length > n ? str.slice(0, n) + "…" : (str || ""); }

// ── Boot ──────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", init);
